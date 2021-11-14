/*-
 * Copyright (c) 2021 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
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
 * Runtime support for compiled VCL programs
 */

#include "config.h"

#include <stdlib.h>

#include "cache_varnishd.h"

#include "cache/cache_filter.h"
#include "cache/cache_transport.h"

#include "vsb.h"
#include "vtim.h"

/**********************************************************************
 * VSRQ - Sub Requests
 */

static const char * const VSRQ_STATE_NEW = "NEW";
static const char * const VSRQ_STATE_FETCH_HDR = "FETCH_HDR";
static const char * const VSRQ_STATE_FETCH_BODY = "FETCH_BODY";
static const char * const VSRQ_STATE_DONE = "DONE";

struct subrequest {
	unsigned		magic;
#define SUBREQUEST_MAGIC	0x9ae568f0
	int			released;
	struct sess		*sess;
	struct req		*req;
	struct vsb		*body;
	uint16_t		resp_status;
	pthread_mutex_t		mtx;
	pthread_cond_t		cond;
	const char		*state;
};

/**********************************************************************
 * srq->body as req.body
 */

static enum vfp_status v_matchproto_(vfp_pull_f)
vsrq_vfp_bytes(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *lp)
{
	struct subrequest *srq;
	ssize_t l;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	CAST_OBJ_NOTNULL(srq, vfe->priv1, SUBREQUEST_MAGIC);

	CHECK_OBJ_NOTNULL(srq->body, VSB_MAGIC);
	l = VSB_len(srq->body) - vfe->priv2;
	if (l > *lp)
		l = *lp;
	assert(l > 0);
	*lp = l;
	memcpy(p, VSB_data(srq->body + vfe->priv2), l);
	vfe->priv2 += l;
	if (vfe->priv2 == VSB_len(srq->body))
		return (VFP_END);
	return (VFP_OK);
}

static const struct vfp srq_vfp = {
	.name =		"VSRQ",
	.pull =		vsrq_vfp_bytes,
};

static void v_matchproto_(vtr_req_body_t)
vsrq_req_body(struct req *req)
{
	struct subrequest *srq;
	struct vfp_entry *vfe;

	CAST_OBJ_NOTNULL(srq, req->transport_priv, SUBREQUEST_MAGIC);

	CHECK_OBJ_NOTNULL(srq->body, VSB_MAGIC);
	assert(VSB_len(srq->body) > 0);
	vfe = VFP_Push(req->vfc, &srq_vfp);
	XXXAN(vfe);
	vfe->priv1 = srq;
	vfe->priv2 = 0;
}

/**********************************************************************
 * srq->body as resp.body
 */

static int v_matchproto_(vdp_bytes_f)
vsrq_vdp_bytes(struct vdp_ctx *vdx, enum vdp_action act, void **priv,
    const void *ptr, ssize_t len)
{
	struct subrequest *srq;

	CHECK_OBJ_NOTNULL(vdx, VDP_CTX_MAGIC);

	CAST_OBJ_NOTNULL(srq, *priv, SUBREQUEST_MAGIC);
	CHECK_OBJ_NOTNULL(srq->body, VSB_MAGIC);
	(void)act;
	(void)priv;

	AZ(vdx->nxt);	   /* always at the bottom of the pile */

	if (len > 0)
		VSB_bcat(srq->body, ptr, len);
	return (0);
}

static const struct vdp vsrq_vdp = {
	.name =		"VSRQ",
	.bytes =	vsrq_vdp_bytes,
};

static void
vsrq_deliver(struct req *req, struct boc *boc, int sendbody)
{
	int err = 0;
	struct subrequest *srq;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CHECK_OBJ_ORNULL(boc, BOC_MAGIC);
	CAST_OBJ_NOTNULL(srq, req->transport_priv, SUBREQUEST_MAGIC);

	AZ(pthread_mutex_lock(&srq->mtx));
	srq->resp_status = req->resp->status;
	srq->state = VSRQ_STATE_FETCH_BODY;
	AZ(pthread_cond_broadcast(&srq->cond));
	AZ(pthread_mutex_unlock(&srq->mtx));

	VSLb(req->vsl, SLT_Debug, "VSRQ: deliver(%p, %p, %d)", req, boc, sendbody);
	if (sendbody) {
		if (srq->body == NULL) {
			srq->body = VSB_new_auto();
			AN(srq->body);
		} else {
			VSB_clear(srq->body);
		}
		if (VDP_Push(req->vdc, req->ws, &vsrq_vdp, srq)) {
			WRONG("WORKSPACE OVERFLOW");
		}
		err = VDP_DeliverObj(req->vdc, req->objcore);
		AZ(err);
	}
	AZ(VSB_finish(srq->body));
	VSLb(req->vsl, SLT_Debug, "VSRQ: body %zd", VSB_len(srq->body));
	AZ(pthread_mutex_lock(&srq->mtx));
	srq->state = VSRQ_STATE_DONE;
	AZ(pthread_cond_broadcast(&srq->cond));
	AZ(pthread_mutex_unlock(&srq->mtx));
}


/**********************************************************************/

static int v_matchproto_(vtr_minimal_response_f)
vsrq_minimal_response(struct req *req, uint16_t status)
{
	struct subrequest *srq;

	CAST_OBJ_NOTNULL(srq, req->transport_priv, SUBREQUEST_MAGIC);
	VSLb(req->vsl, SLT_Debug, "VSRQ: minimal(%p, %u)", req, status);
	srq->resp_status = status;
	AZ(pthread_mutex_lock(&srq->mtx));

	VSB_clear(srq->body);
	AZ(VSB_finish(srq->body));
	srq->state = VSRQ_STATE_DONE;
	AZ(pthread_cond_broadcast(&srq->cond));
	AZ(pthread_mutex_unlock(&srq->mtx));
	return (0);
}

static void v_matchproto_(task_func_t)
vsrq_new_session(struct worker *wrk, void *arg)
{
	VSL(SLT_Debug, 999, "VSRQ: new_sess(%p, %p)", wrk, arg);
}


static void
vsrq_sess_panic(struct vsb *vsb, const struct sess *sp)
{

	VSB_printf(vsb, "VSRQ: sess_panic %p\n", sp);
}

static void
vsrq_req_panic(struct vsb *vsb, const struct req *req)
{

	VSB_printf(vsb, "VSRQ: req_panic %p\n", req);
}

static void v_matchproto_(vtr_req_fail_f)
vsrq_req_fail(struct req *req, enum sess_close reason)
{
	VSLb(req->vsl, SLT_Debug, "VSRQ: req_fail(%p, %u)", req, reason);
}

struct transport VSRQ_transport = {
	.magic =		TRANSPORT_MAGIC,
	.name =			"VSRQ_XP",
	.proto_ident =		"VSRQ_XP",
	.deliver =		vsrq_deliver,
	.minimal_response =	vsrq_minimal_response,
	.new_session =		vsrq_new_session,
	.req_body =		vsrq_req_body,
	.req_fail =		vsrq_req_fail,
	.req_panic =		vsrq_req_panic,
	.sess_panic =		vsrq_sess_panic,
};

static void v_matchproto_(task_func_t)
SRQ_task(struct worker *wrk, void *arg)
{
	int i;
	struct subrequest *srq;
	struct req *req;

	CAST_OBJ_NOTNULL(srq, arg, SUBREQUEST_MAGIC);
	req = srq->req;
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	THR_SetRequest(req);

	CNT_Embark(wrk, req);
	while (1) {
		/* XXX: waiting list ? */
		i = CNT_Request(req);
		VSL(SLT_Debug, 999, "VSRQ: cnt_request(%p) = %d", wrk, i);
		if (i == REQ_FSM_DONE)
			break;
	}

	AZ(pthread_mutex_lock(&srq->mtx));
	while (!srq->released)
		AZ(pthread_cond_wait(&srq->cond, &srq->mtx));
	AZ(pthread_mutex_unlock(&srq->mtx));
	req->transport_priv = NULL;
	Req_AcctLogCharge(wrk->stats, req);
	Req_Cleanup(srq->sess, wrk, req);
	Req_Release(req);
	SES_Rel(srq->sess);
}

struct subrequest *
VSRQ_New(struct req *preq)
{
	struct subrequest *srq;
	struct req *req;
	struct sess *sp;

	CHECK_OBJ_NOTNULL(preq, REQ_MAGIC);
	CHECK_OBJ_NOTNULL(preq->sp, SESS_MAGIC);

	ALLOC_OBJ(srq, SUBREQUEST_MAGIC);
	AN(srq);

	sp = preq->sp;
	SES_Ref(sp);
	srq->sess = sp;

	AZ(pthread_mutex_init(&srq->mtx, &mtxattr_errorcheck));
	AZ(pthread_cond_init(&srq->cond, NULL));
	srq->state = VSRQ_STATE_NEW;

	req = Req_New(sp);
	srq->req = req;
	req->sp = sp;
	req->top = preq->top;
	req->req_body_status = BS_NONE;
	req->vsl->wid = VXID_Get(preq->wrk, VSL_CLIENTMARKER);
	VSLb(preq->vsl, SLT_Link, "req %u subreq", VXID(req->vsl->wid));

	HTTP_Setup(req->http, req->ws, req->vsl, SLT_ReqMethod);
	http_SetH(req->http, HTTP_HDR_PROTO, "HTTP/1.1");
	http_SetH(req->http, HTTP_HDR_METHOD, "HEAD");
	http_SetH(req->http, HTTP_HDR_URL, "/");
	http_SetHeader(req->http, "Host: localhost");

	return(srq);
}

struct http *
VSRQ_Req(struct subrequest *srq)
{
	CHECK_OBJ_NOTNULL(srq, SUBREQUEST_MAGIC);
	return (srq->req->http);
}

struct vsb *
VSRQ_Body(struct subrequest *srq)
{
	CHECK_OBJ_NOTNULL(srq, SUBREQUEST_MAGIC);
	if (srq->body == NULL) {
		srq->body = VSB_new_auto();
		AN(srq->body);
	}
	return (srq->body);
}

void
VSRQ_Launch(struct subrequest *srq)
{
	struct req *req;
	int i;

	CHECK_OBJ_NOTNULL(srq, SUBREQUEST_MAGIC);
	req = srq->req;
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	req->t_first = VTIM_real();
	req->t_prev = VTIM_real();
	req->t_req = VTIM_real();
	req->task->func = SRQ_task;
	req->task->priv = srq;
	req->transport = &VSRQ_transport;
	req->transport_priv = srq;

	/* We always "send" a Content-Length.  The main FSM will DTRT. */
	if (srq->body == NULL || VSB_len(srq->body) == 0) {
		http_PrintfHeader(srq->req->http, "Content-Length: 0");
		req->req_body_status = BS_NONE;
	} else {
		AZ(VSB_finish(srq->body));
		http_PrintfHeader(srq->req->http,
		    "Content-Length: %zd", VSB_len(srq->body));
		req->req_body_status = BS_LENGTH;
	}

	AZ(pthread_mutex_lock(&srq->mtx));
	srq->state = VSRQ_STATE_FETCH_HDR;
	AZ(pthread_mutex_unlock(&srq->mtx));

	i = Pool_Task(srq->sess->pool, req->task, TASK_QUEUE_REQ);
	XXXAZ(i);
}

int
VSRQ_Waitfor(struct subrequest *srq, vtim_dur patience)
{
	struct timespec ts = {0, 0};
	vtim_real tfin = -1;
	int retval;

	CHECK_OBJ_NOTNULL(srq, SUBREQUEST_MAGIC);
	if (patience > 0) {
		tfin = VTIM_real() + patience;
		ts = VTIM_timespec(tfin);
	}
	AZ(pthread_mutex_lock(&srq->mtx));
	while (srq->state != VSRQ_STATE_DONE) {
		if (tfin <= 0) {
			AZ(pthread_cond_wait(&srq->cond, &srq->mtx));
		} else {
			errno = pthread_cond_timedwait(
			    &srq->cond, &srq->mtx, &ts);
			assert(errno == 0 || errno == ETIMEDOUT);
		}
		if (tfin < VTIM_real())
			break;
	}
	retval = srq->state == VSRQ_STATE_DONE;
	AZ(pthread_mutex_unlock(&srq->mtx));
	return (retval);
}

uint16_t
VSRQ_Resp_Status(struct subrequest *srq)
{
	(void)VSRQ_Waitfor(srq, -1);
	assert(srq->resp_status >= 100 && srq->resp_status < 1000);
	return (srq->resp_status);
}

void
VSRQ_Release(struct subrequest **srqp)
{
	struct subrequest *srq;

	TAKE_OBJ_NOTNULL(srq, srqp, SUBREQUEST_MAGIC);
	VSLb(srq->req->vsl, SLT_Debug, "VSRQ: Done(%p)", srq);

	AZ(pthread_mutex_lock(&srq->mtx));
	srq->released = 1;
	AZ(pthread_cond_broadcast(&srq->cond));
	AZ(pthread_mutex_unlock(&srq->mtx));
}
