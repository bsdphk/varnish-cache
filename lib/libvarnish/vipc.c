/*-
 * Copyright (c) 2024 Varnish Software AS
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
 */

#include "config.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>
#include <math.h>
#include <unistd.h>
#include <sys/socket.h>

#include "vdef.h"
#include "miniobj.h"
#include "vas.h"
#include "vipc.h"
#include "vcli.h"

#define VIPC_ID_LEN		8
#define VIPC_DEFAULT_BUFFER	4096

#define VIPC_HELLO		"Hello"

struct vipc {
	unsigned	magic;
#define VIPC_MAGIC	0x178fd00c
	int		fd;
	char		iam[VIPC_ID_LEN];
	char		youare[VIPC_ID_LEN];
	size_t		rx_buf_size;
	size_t		tx_buf_size;
	void		*rx_buf;
	uint64_t	tx_sequence;
	uint64_t	rx_sequence;
};

struct vipm {
	unsigned	magic;
#define VIPM_MAGIC	0x2e290167
	char		iam[VIPC_ID_LEN];
	char		youare[VIPC_ID_LEN];
	char		subject[VIPC_ID_LEN];
	uint64_t	sequence;
	size_t		length;
	uint8_t		payload[];
};

struct vipc *
VIPC_Create(int fd, const char *iam, const char *youare)
{
	struct vipc *vp;

	AN(iam);
	AN(youare);
	ALLOC_OBJ(vp, VIPC_MAGIC);
	AN(vp);
	vp->fd = fd;
	vp->tx_buf_size = VIPC_DEFAULT_BUFFER;
	vp->rx_buf_size = VIPC_DEFAULT_BUFFER;
	vp->rx_buf = malloc(vp->rx_buf_size);
	AN(vp->rx_buf);
	assert(strlen(iam) < VIPC_ID_LEN);
	strncpy(vp->iam, iam, VIPC_ID_LEN);
	assert(strlen(youare) < VIPC_ID_LEN);
	strncpy(vp->youare, youare, VIPC_ID_LEN);
	//AZ(VIPC_SendMsg(vp, VIPC_HELLO, "", 0));
	return (vp);
}

void
VIPC_Destroy(struct vipc **vpp)
{
	struct vipc *vp;

	AN(vpp);
	TAKE_OBJ_NOTNULL(vp, vpp, VIPC_MAGIC);
	free(vp->rx_buf);
	FREE_OBJ(vp);
}

int
VIPC_SendMsg(struct vipc *vp, const char *subject, const void *ptr, size_t len)
{
	struct vipm *vm;
	size_t wsz;
	ssize_t sz;

	CHECK_OBJ_NOTNULL(vp, VIPC_MAGIC);
	AN(subject);
	AN(*subject);
	assert(strlen(subject) < VIPC_ID_LEN);
	AN(ptr);
	vm = malloc(sizeof *vm + len);
	AN(vm);
	INIT_OBJ(vm, VIPM_MAGIC);
	memcpy(vm->iam, vp->iam, VIPC_ID_LEN);
	memcpy(vm->youare, vp->youare, VIPC_ID_LEN);

	wsz = sizeof *vm + len;
	if (wsz > vp->tx_buf_size) {
		vp->tx_buf_size = wsz + VIPC_DEFAULT_BUFFER;
		vm->length = vp->tx_buf_size;
		vm->sequence = vp->tx_sequence++;
		sz = send(vp->fd, vm, sizeof *vm, 0);
		assert(sz == sizeof *vm);
		//usleep(10000);
	}

	vm->length = len;
	strncpy(vm->subject, subject, VIPC_ID_LEN);
	if (len > 0)
		memcpy(vm->payload, ptr, len);
	assert(wsz <= vp->tx_buf_size);
	vm->sequence = vp->tx_sequence++;
	sz = send(vp->fd, vm, wsz, 0);
	assert(sz == wsz);
	FREE_OBJ(vm);
	return (0);
}

#include <stdio.h>

int
VIPC_RecvMsg(struct vipc *vp, char **subjectp, void **ptr, size_t *lenp, double tmo)
{
	ssize_t rsz;
	struct vipm *vm;
	struct pollfd pfd[1];

	CHECK_OBJ_NOTNULL(vp, VIPC_MAGIC);
	AN(subjectp);
	AN(ptr);
	AN(lenp);
	*lenp = 0;
	*ptr = NULL;
	if (!isnan(tmo)) {
		pfd[0].fd = vp->fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (poll(pfd, 1, (int)(1000 * tmo)) != 1) 
			return (-1);
	}
	while (1) {
		AN(vp->rx_buf);
		memset(vp->rx_buf, 0x55, vp->rx_buf_size);
		rsz = recv(vp->fd, vp->rx_buf, vp->rx_buf_size, 0);
		if (rsz <= 0)
			return (-1);
		assert((size_t)rsz >= sizeof *vm);
		vm = vp->rx_buf;
		CHECK_OBJ_NOTNULL(vm, VIPM_MAGIC);
		assert(!memcmp(vm->iam, vp->youare, VIPC_ID_LEN));
		assert(!memcmp(vm->youare, vp->iam, VIPC_ID_LEN));
		assert(vm->sequence == vp->rx_sequence);
		vp->rx_sequence++;
		if (vm->subject[0] == '\0') {
			vp->rx_buf_size = vm->length;
			free(vp->rx_buf);
			vp->rx_buf = malloc(vp->rx_buf_size);
			AN(vp->rx_buf);
			continue;
		}
		assert(rsz == sizeof *vm + vm->length);
		if (!strcmp(vm->subject, VIPC_HELLO)) {
			assert(vm->length == 0);
			continue;
		}
		break;
	}
	*subjectp = strdup(vm->subject);
	AN(*subjectp);
	*lenp = vm->length;
	if (vm->length > 0) {
		*ptr = malloc(vm->length);
		AN(*ptr);
		memcpy(*ptr, vm->payload, vm->length);
	} else {
		*ptr = NULL;
	}
	return (0);
}

#define SUBJECT_CLI_RESULT "CLIRES"

struct vipc_m_cli_result {
	unsigned	magic;
#define VIPC_M_CLI_RESULT_MAGIC 0xbfd472c0
	unsigned	status;
	char		body[];
};

int
VIPC_SendCliResult(struct vipc *vp, unsigned status, const char *result)
{
	struct vipc_m_cli_result *vcr;
	size_t bodylen = strlen(result) + 1;
	size_t msglen = sizeof *vcr + bodylen;
	int retval;

	vcr = malloc(msglen);
	AN(vcr);
	INIT_OBJ(vcr, VIPC_M_CLI_RESULT_MAGIC);
	vcr->status = status;
	strncpy(vcr->body, result, bodylen);
	retval = VIPC_SendMsg(vp, SUBJECT_CLI_RESULT, vcr, msglen);
	FREE_OBJ(vcr);
	return (retval);
}

/*
 * This is an placeholder function until we dispatch on the subject
 * of received messages.
 */

int
VIPC_RecvCliResult(struct vipc *vp, unsigned *status, char **result, double tmo)
{
	void *p;
	struct vipc_m_cli_result *vcr;
	size_t len;
	char *subject;
	int retval;

	AN(status);
	AN(result);
	*status = CLIS_COMMS;
	*result = NULL;

	retval = VIPC_RecvMsg(vp, &subject, &p, &len, tmo);
	if (retval)
		return (retval);
	AN(subject);
	assert(!strcmp(subject, SUBJECT_CLI_RESULT));
	assert(len > sizeof *vcr);
	vcr = p;
	CHECK_OBJ_NOTNULL(vcr, VIPC_M_CLI_RESULT_MAGIC);
	*status = vcr->status;
	*result = strdup(vcr->body);
	AN(*result);
	FREE_OBJ(vcr);
	return (retval);
}
