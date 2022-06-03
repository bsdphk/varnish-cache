/*-
 * Copyright (c) 2012-2020 Varnish Software AS
 *
 * Author: Lasse Karstensen <lasse.karstensen@gmail.com>
 * Author: Lasse Karstensen <lkarsten@varnish-software.com>
 * Author: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Cookie VMOD that simplifies handling of the Cookie request header.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include <cache/cache.h>

#include <vsb.h>

#include "vcc_cookie_if.h"

enum filter_action {
	blacklist,
	whitelist
};

struct cookie {
	unsigned		magic;
#define VMOD_COOKIE_ENTRY_MAGIC	0x3BB41543
	const char		*name;
	const char		*value;
	VTAILQ_ENTRY(cookie)	list;
};

/* A structure to represent both whitelists and blacklists */
struct matchlist {
	char			*name;
	VTAILQ_ENTRY(matchlist)	list;
};

struct vmod_cookie {
	unsigned		magic;
#define VMOD_COOKIE_MAGIC	0x4EE5FB2E
	VTAILQ_HEAD(, cookie)	cookielist;
};

static void
cobj_free(VRT_CTX, void *p)
{
	struct vmod_cookie *vcp;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CAST_OBJ_NOTNULL(vcp, p, VMOD_COOKIE_MAGIC);
	FREE_OBJ(vcp);
}

static const struct vmod_priv_methods cookie_cobj_priv_methods[1] = {{
	.magic = VMOD_PRIV_METHODS_MAGIC,
	.type = "vmod_cookie_cobj",
	.fini = cobj_free
}};

static struct vmod_cookie *
cobj_get(struct vmod_priv *priv)
{
	struct vmod_cookie *vcp;

	if (priv->priv == NULL) {
		ALLOC_OBJ(vcp, VMOD_COOKIE_MAGIC);
		AN(vcp);
		VTAILQ_INIT(&vcp->cookielist);
		priv->priv = vcp;
		priv->methods = cookie_cobj_priv_methods;
	} else
		CAST_OBJ_NOTNULL(vcp, priv->priv, VMOD_COOKIE_MAGIC);

	return (vcp);
}

VCL_VOID
vmod_parse(VRT_CTX, struct vmod_priv *priv, VCL_STRING cookieheader)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	char *name, *value;
	const char *p, *sep;
	int i = 0;

	if (cookieheader == NULL || *cookieheader == '\0') {
		VSLb(ctx->vsl, SLT_Debug, "cookie: nothing to parse");
		return;
	}

	/* If called twice during the same request, clean out old state. */
	if (!VTAILQ_EMPTY(&vcp->cookielist))
		vmod_clean(ctx, priv);

	p = cookieheader;
	while (*p != '\0') {
		while (isspace(*p))
			p++;
		sep = strchr(p, '=');
		if (sep == NULL)
			break;
		name = strndup(p, pdiff(p, sep));
		p = sep + 1;

		sep = p;
		while (*sep != '\0' && *sep != ';')
			sep++;
		value = strndup(p, pdiff(p, sep));

		vmod_set(ctx, priv, name, value);
		free(name);
		free(value);
		i++;
		if (*sep == '\0')
			break;
		p = sep + 1;
	}

	VSLb(ctx->vsl, SLT_Debug, "cookie: parsed %i cookies.", i);
}

static struct cookie *
find_cookie(const struct vmod_cookie *vcp, VCL_STRING name)
{
	struct cookie *cookie;

	VTAILQ_FOREACH(cookie, &vcp->cookielist, list) {
		CHECK_OBJ_NOTNULL(cookie, VMOD_COOKIE_ENTRY_MAGIC);
		if (!strcmp(cookie->name, name))
			break;
	}
	return (cookie);
}

VCL_VOID
vmod_set(VRT_CTX, struct vmod_priv *priv, VCL_STRING name, VCL_STRING value)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	struct cookie *cookie;
	const char *p;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(ctx->ws, WS_MAGIC);

	/* Empty cookies should be ignored. */
	if (name == NULL || *name == '\0')
		return;
	if (value == NULL || *value == '\0')
		return;

	cookie = find_cookie(vcp, name);
	if (cookie != NULL) {
		p = WS_Printf(ctx->ws, "%s", value);
		if (p == NULL) {
			VSLb(ctx->vsl, SLT_Error,
			    "cookie: Workspace overflow in set()");
		} else
			cookie->value = p;
		return;
	}

	cookie = WS_Alloc(ctx->ws, sizeof *cookie);
	if (cookie == NULL) {
		VSLb(ctx->vsl, SLT_Error,
		    "cookie: unable to get storage for cookie");
		return;
	}
	INIT_OBJ(cookie, VMOD_COOKIE_ENTRY_MAGIC);
	cookie->name = WS_Printf(ctx->ws, "%s", name);
	cookie->value = WS_Printf(ctx->ws, "%s", value);
	if (cookie->name == NULL || cookie->value == NULL) {
		VSLb(ctx->vsl, SLT_Error,
		    "cookie: unable to get storage for cookie");
		return;
	}
	VTAILQ_INSERT_TAIL(&vcp->cookielist, cookie, list);
}

VCL_BOOL
vmod_isset(VRT_CTX, struct vmod_priv *priv, const char *name)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	struct cookie *cookie;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (name == NULL || *name == '\0')
		return (0);

	cookie = find_cookie(vcp, name);
	return (cookie ? 1 : 0);
}

VCL_STRING
vmod_get(VRT_CTX, struct vmod_priv *priv, VCL_STRING name)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	struct cookie *cookie;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (name == NULL || *name == '\0')
		return (NULL);

	cookie = find_cookie(vcp, name);
	return (cookie ? cookie->value : NULL);
}


VCL_STRING
vmod_get_re(VRT_CTX, struct vmod_priv *priv, VCL_REGEX re)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	struct cookie *cookie = NULL;
	struct cookie *current;
	unsigned match;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(re);

	VTAILQ_FOREACH(current, &vcp->cookielist, list) {
		CHECK_OBJ_NOTNULL(current, VMOD_COOKIE_ENTRY_MAGIC);
		VSLb(ctx->vsl, SLT_Debug, "cookie: checking %s", current->name);
		match = VRT_re_match(ctx, current->name, re);
		if (!match)
			continue;
		cookie = current;
		break;
	}

	return (cookie ? cookie->value : NULL);
}

VCL_VOID
vmod_delete(VRT_CTX, struct vmod_priv *priv, VCL_STRING name)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	struct cookie *cookie;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	if (name == NULL || *name == '\0')
		return;

	cookie = find_cookie(vcp, name);

	if (cookie != NULL)
		VTAILQ_REMOVE(&vcp->cookielist, cookie, list);
}

VCL_VOID
vmod_clean(VRT_CTX, struct vmod_priv *priv)
{
	struct vmod_cookie *vcp = cobj_get(priv);

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(vcp);
	VTAILQ_INIT(&vcp->cookielist);
}

static void
filter_cookies(struct vmod_priv *priv, VCL_STRING list_s,
    enum filter_action mode)
{
	struct cookie *cookieptr, *safeptr;
	struct vmod_cookie *vcp = cobj_get(priv);
	struct matchlist *mlentry, *mlsafe;
	char const *p = list_s, *q;
	int matched = 0;
	VTAILQ_HEAD(, matchlist) matchlist_head;

	VTAILQ_INIT(&matchlist_head);

	/* Parse the supplied list. */
	while (p && *p != '\0') {
		while (isspace(*p))
			p++;
		if (*p == '\0')
			break;

		q = p;
		while (*q != '\0' && *q != ',')
			q++;

		if (q == p) {
			p++;
			continue;
		}

		/* XXX: can we reserve/release lumps of txt instead of
		 * malloc/free?
		 */
		mlentry = malloc(sizeof *mlentry);
		AN(mlentry);
		mlentry->name = strndup(p, q - p);
		AN(mlentry->name);

		VTAILQ_INSERT_TAIL(&matchlist_head, mlentry, list);

		p = q;
		if (*p != '\0')
			p++;
	}

	/* Filter existing cookies that either aren't in the whitelist or
	 * are in the blacklist (depending on the filter_action) */
	VTAILQ_FOREACH_SAFE(cookieptr, &vcp->cookielist, list, safeptr) {
		CHECK_OBJ_NOTNULL(cookieptr, VMOD_COOKIE_ENTRY_MAGIC);
		matched = 0;

		VTAILQ_FOREACH(mlentry, &matchlist_head, list) {
			if (strcmp(cookieptr->name, mlentry->name) == 0) {
				matched = 1;
				break;
			}
		}
		if (matched != mode)
			VTAILQ_REMOVE(&vcp->cookielist, cookieptr, list);
	}

	VTAILQ_FOREACH_SAFE(mlentry, &matchlist_head, list, mlsafe) {
		VTAILQ_REMOVE(&matchlist_head, mlentry, list);
		free(mlentry->name);
		free(mlentry);
	}
}

VCL_VOID
vmod_keep(VRT_CTX, struct vmod_priv *priv, VCL_STRING whitelist_s)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	filter_cookies(priv, whitelist_s, whitelist);
}


VCL_VOID
vmod_filter(VRT_CTX, struct vmod_priv *priv, VCL_STRING blacklist_s)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	filter_cookies(priv, blacklist_s, blacklist);
}

static VCL_VOID
re_filter(VRT_CTX, struct vmod_priv *priv, VCL_REGEX re, enum filter_action mode)
{
	struct vmod_cookie *vcp = cobj_get(priv);
	struct cookie *current, *safeptr;
	unsigned match;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	AN(re);

	VTAILQ_FOREACH_SAFE(current, &vcp->cookielist, list, safeptr) {
		CHECK_OBJ_NOTNULL(current, VMOD_COOKIE_ENTRY_MAGIC);

		match = VRT_re_match(ctx, current->name, re);

		switch (mode) {
		case blacklist:
			if (!match)
				continue;
			VSLb(ctx->vsl, SLT_Debug,
			    "Removing matching cookie %s (value: %s)",
			    current->name, current->value);
			VTAILQ_REMOVE(&vcp->cookielist, current, list);
			break;
		case whitelist:
			if (match)
				continue;

			VSLb(ctx->vsl, SLT_Debug,
			    "Removing cookie %s (value: %s)",
			    current->name, current->value);
			VTAILQ_REMOVE(&vcp->cookielist, current, list);
			break;
		default:
			WRONG("invalid mode");
		}
	}
}


VCL_VOID
vmod_keep_re(VRT_CTX, struct vmod_priv *priv, VCL_REGEX re)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	re_filter(ctx, priv, re, whitelist);
}


VCL_VOID
vmod_filter_re(VRT_CTX, struct vmod_priv *priv, VCL_REGEX re)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	re_filter(ctx, priv, re, blacklist);
}


VCL_STRING
vmod_get_string(VRT_CTX, struct vmod_priv *priv)
{
	struct cookie *curr;
	struct vsb output[1];
	struct vmod_cookie *vcp = cobj_get(priv);
	const char *sep = "", *res;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(ctx->ws, WS_MAGIC);
	WS_VSB_new(output, ctx->ws);

	VTAILQ_FOREACH(curr, &vcp->cookielist, list) {
		CHECK_OBJ_NOTNULL(curr, VMOD_COOKIE_ENTRY_MAGIC);
		AN(curr->name);
		AN(curr->value);
		VSB_printf(output, "%s%s=%s", sep, curr->name, curr->value);
		sep = "; ";
	}
	res = WS_VSB_finish(output, ctx->ws, NULL);
	if (res == NULL)
		VSLb(ctx->vsl, SLT_Error, "cookie: Workspace overflow");
	return (res);
}

VCL_STRING
vmod_format_date(VRT_CTX, VCL_TIME ts, VCL_DURATION duration)
{

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	return (VRT_TIME_string(ctx, ts + duration));
}
