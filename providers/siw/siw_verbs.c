/*
 * Software iWARP library for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2017, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "siw_user.h"
#include "siw.h"
#include "siw_abi.h"

const int siw_debug;

int siw_query_device(struct ibv_context *ctx, struct ibv_device_attr *attr)
{
	struct ibv_query_device	cmd;
	uint64_t raw_fw_ver;
	unsigned int major, minor, sub_minor;
	int rv;

	memset(&cmd, 0, sizeof(cmd));

	rv = ibv_cmd_query_device(ctx, attr, &raw_fw_ver, &cmd, sizeof(cmd));
	if (rv)
		return rv;

	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof(attr->fw_ver),
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

int siw_query_port(struct ibv_context *ctx, uint8_t port,
		   struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	memset(&cmd, 0, sizeof(cmd));

	return ibv_cmd_query_port(ctx, port, attr, &cmd, sizeof(cmd));
}

int siw_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		 int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	memset(&cmd, 0, sizeof(cmd));

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr,
				&cmd, sizeof(cmd));
}

struct ibv_pd *siw_alloc_pd(struct ibv_context *ctx)
{
	struct ibv_alloc_pd cmd;
	struct siw_alloc_pd_resp resp;
	struct siw_pd *pd;

	memset(&cmd, 0, sizeof(cmd));

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(ctx, &pd->base_pd, &cmd, sizeof(cmd),
			     &resp.base, sizeof(resp))) {
		free(pd);
		return NULL;
	}
	return &pd->base_pd;
}

int siw_free_pd(struct ibv_pd *pd)
{
	int rv;

	rv = ibv_cmd_dealloc_pd(pd);
	if (rv)
		return rv;

	free(pd);
	return 0;
}

struct ibv_mr *siw_reg_mr(struct ibv_pd *pd, void *addr,
			  size_t len, int access)
{
	struct siw_cmd_reg_umr_req cmd;
	struct siw_cmd_reg_umr_resp resp;
	struct verbs_mr *base_mr;
	int rv;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	base_mr = calloc(1, sizeof(*base_mr));
	if (!base_mr)
		return NULL;

	rv = ibv_cmd_reg_mr(pd, addr, len, (uintptr_t)addr, access,
			    base_mr, &cmd.base, sizeof(cmd),
			    &resp.base, sizeof(resp));
	if (rv) {
		free(base_mr);
		return NULL;
	}
	return &base_mr->ibv_mr;
}

int siw_dereg_mr(struct verbs_mr *base_mr)
{
	int rv;

	rv = ibv_cmd_dereg_mr(base_mr);
	if (rv)
		return rv;

	free(base_mr);
	return 0;
}

struct ibv_cq *siw_create_cq(struct ibv_context *ctx, int num_cqe,
			     struct ibv_comp_channel *channel, int comp_vector)
{
	struct siw_cmd_create_cq cmd;
	struct siw_cmd_create_cq_resp resp;
	struct siw_cq *cq;
	int rv;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	rv = ibv_cmd_create_cq(ctx, num_cqe, channel, comp_vector,
			       &cq->base_cq, &cmd.base, sizeof(cmd),
			       &resp.base, sizeof(resp));
	if (rv) {
		if (siw_debug)
			printf("libsiw: CQ creation failed: %d\n", rv);
		free(cq);
		return NULL;
	}
	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	cq->id = resp.siw.cq_id;
	cq->num_cqe = resp.siw.num_cqe;

	if (resp.siw.cq_key <= SIW_MAX_UOBJ_KEY) {
		int cq_size = resp.siw.num_cqe * sizeof(struct siw_cqe)
				+ sizeof(struct siw_cq_ctrl);

		cq->queue = mmap(NULL, cq_size,
				 PROT_READ|PROT_WRITE, MAP_SHARED,
				  ctx->cmd_fd, resp.siw.cq_key);

		if (cq->queue == MAP_FAILED) {
			if (siw_debug)
				printf("libsiw: CQ mapping failed: %d", errno);
			goto fail;
		}
		cq->ctrl = (struct siw_cq_ctrl *)&cq->queue[cq->num_cqe];
		cq->ctrl->notify = SIW_NOTIFY_NOT;

		return &cq->base_cq;
	}
	if (siw_debug)
		printf("libsiw: prepare CQ mapping failed\n");
fail:
	ibv_cmd_destroy_cq(&cq->base_cq);
	free(cq);

	return NULL;
}

int siw_resize_cq(struct ibv_cq *base_cq, int num_cqe)
{
	return -EOPNOTSUPP;
}

int siw_destroy_cq(struct ibv_cq *base_cq)
{
	struct siw_cq *cq = cq_base2siw(base_cq);
	int rv;

	pthread_spin_lock(&cq->lock);

	if (cq->queue)
		munmap(cq->queue, cq->num_cqe * sizeof(struct siw_cqe)
			+ sizeof(struct siw_cq_ctrl));

	rv = ibv_cmd_destroy_cq(base_cq);
	if (rv) {
		pthread_spin_unlock(&cq->lock);
		return rv;
	}
	pthread_spin_unlock(&cq->lock);

	free(cq);

	return 0;
}

struct ibv_srq *siw_create_srq(struct ibv_pd *pd,
			       struct ibv_srq_init_attr *attr)
{
	struct siw_cmd_create_srq cmd;
	struct siw_cmd_create_srq_resp resp;
	struct siw_srq *srq;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	srq = calloc(1, sizeof(*srq));
	if (!srq)
		return NULL;

	if (ibv_cmd_create_srq(pd, &srq->base_srq, attr, &cmd.base,
			       sizeof(cmd), &resp.base, sizeof(resp))) {
		free(srq);
		return NULL;
	}
	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);

	if (resp.siw.srq_key <= SIW_MAX_UOBJ_KEY) {
		struct ibv_context *ctx = pd->context;
		int rq_size = resp.siw.num_rqe * sizeof(struct siw_rqe);

		srq->num_rqe = resp.siw.num_rqe;

		srq->recvq = mmap(NULL, rq_size, PROT_READ|PROT_WRITE,
				  MAP_SHARED, ctx->cmd_fd, resp.siw.srq_key);

		if (srq->recvq == MAP_FAILED) {
			if (siw_debug)
				printf("libsiw: SRQ mapping failed: %d",
					errno);
			goto fail;
		}
		return &srq->base_srq;
	}
	if (siw_debug)
		printf("libsiw: prepare SRQ mapping failed\n");
fail:
	ibv_cmd_destroy_srq(&srq->base_srq);
	free(srq);

	return NULL;
}

int siw_modify_srq(struct ibv_srq *base_srq, struct ibv_srq_attr *attr,
		   int attr_mask)
{
	struct ibv_modify_srq cmd;
	struct siw_srq *srq = srq_base2siw(base_srq);
	int rv;

	memset(&cmd, 0, sizeof(cmd));

	pthread_spin_lock(&srq->lock);
	rv = ibv_cmd_modify_srq(base_srq, attr, attr_mask, &cmd, sizeof(cmd));
	pthread_spin_unlock(&srq->lock);

	return rv;
}

int siw_destroy_srq(struct ibv_srq *base_srq)
{
	struct siw_srq *srq = srq_base2siw(base_srq);

	pthread_spin_lock(&srq->lock);
	ibv_cmd_destroy_srq(base_srq);
	pthread_spin_unlock(&srq->lock);

	if (srq->recvq)
		munmap(srq->recvq, srq->num_rqe * sizeof(struct siw_rqe));

	free(srq);

	return 0;
}

struct ibv_qp *siw_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct siw_cmd_create_qp cmd;
	struct siw_cmd_create_qp_resp resp;
	struct siw_qp *qp;
	struct ibv_context *base_ctx = pd->context;
	int rv;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;

	rv = ibv_cmd_create_qp(pd, &qp->base_qp, attr, &cmd.base,
			       sizeof(cmd), &resp.base, sizeof(resp));
	if (rv)
		goto fail;

	qp->id = resp.siw.qp_id;
	qp->num_sqe = resp.siw.num_sqe;
	qp->num_rqe = resp.siw.num_rqe;
	qp->sq_sig_all = attr->sq_sig_all;

	/* Init doorbell request structure */
	qp->db_req.hdr.command = IB_USER_VERBS_CMD_POST_SEND;
	qp->db_req.hdr.in_words = sizeof(qp->db_req) / 4;
	qp->db_req.hdr.out_words = sizeof(qp->db_resp) / 4;
	qp->db_req.response = (uintptr_t)&qp->db_resp;
	qp->db_req.wr_count = 0;
	qp->db_req.sge_count = 0;
	qp->db_req.wqe_size = sizeof(struct ibv_send_wr);

	pthread_spin_init(&qp->sq_lock, PTHREAD_PROCESS_PRIVATE);
	pthread_spin_init(&qp->rq_lock, PTHREAD_PROCESS_PRIVATE);

	if (resp.siw.sq_key <= SIW_MAX_UOBJ_KEY) {
		int sq_size = resp.siw.num_sqe * sizeof(struct siw_sqe);

		qp->sendq = mmap(NULL, sq_size,
				 PROT_READ|PROT_WRITE, MAP_SHARED,
				 base_ctx->cmd_fd, resp.siw.sq_key);

		if (qp->sendq == MAP_FAILED) {
			if (siw_debug)
				printf("libsiw: SQ mapping failed: %d", errno);

			qp->sendq = NULL;
			goto fail;
		}
	} else {
		if (siw_debug)
			printf("libsiw: prepare SQ mapping failed\n");
		goto fail;
	}
	if (attr->srq) {
		qp->srq = srq_base2siw(attr->srq);
	} else if (resp.siw.rq_key <= SIW_MAX_UOBJ_KEY) {
		int rq_size = resp.siw.num_rqe * sizeof(struct siw_rqe);

		qp->recvq = mmap(NULL, rq_size, PROT_READ|PROT_WRITE,
				 MAP_SHARED, base_ctx->cmd_fd,
				 resp.siw.rq_key);

		if (qp->recvq == MAP_FAILED) {
			if (siw_debug)
				printf("libsiw: RQ mapping failed: %d\n",
					resp.siw.num_rqe);
			qp->recvq = NULL;
			goto fail;
		}
	} else {
		if (siw_debug)
			printf("libsiw: prepare RQ mapping failed\n");
		goto fail;
	}
	qp->db_req.qp_handle = qp->base_qp.handle;

	return &qp->base_qp;
fail:
	ibv_cmd_destroy_qp(&qp->base_qp);

	if (qp->sendq)
		munmap(qp->sendq, qp->num_sqe * sizeof(struct siw_sqe));
	if (qp->recvq)
		munmap(qp->recvq, qp->num_rqe * sizeof(struct siw_rqe));

	free(qp);

	return NULL;
}

int siw_modify_qp(struct ibv_qp *base_qp, struct ibv_qp_attr *attr,
		  int attr_mask)
{
	struct ibv_modify_qp cmd;
	struct siw_qp *qp = qp_base2siw(base_qp);
	int rv;

	memset(&cmd, 0, sizeof(cmd));

	pthread_spin_lock(&qp->sq_lock);
	pthread_spin_lock(&qp->rq_lock);

	rv = ibv_cmd_modify_qp(base_qp, attr, attr_mask, &cmd, sizeof(cmd));

	pthread_spin_unlock(&qp->rq_lock);
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

int siw_destroy_qp(struct ibv_qp *base_qp)
{
	struct siw_qp *qp = qp_base2siw(base_qp);
	int rv;

	pthread_spin_lock(&qp->sq_lock);
	pthread_spin_lock(&qp->rq_lock);

	if (qp->sendq)
		munmap(qp->sendq, qp->num_sqe * sizeof(struct siw_sqe));
	if (qp->recvq)
		munmap(qp->recvq, qp->num_rqe * sizeof(struct siw_rqe));

	rv = ibv_cmd_destroy_qp(base_qp);
	if (rv) {
		pthread_spin_unlock(&qp->rq_lock);
		pthread_spin_unlock(&qp->sq_lock);
		return rv;
	}
	pthread_spin_unlock(&qp->rq_lock);
	pthread_spin_unlock(&qp->sq_lock);

	free(qp);

	return 0;
}

struct ibv_ah *siw_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	return NULL;
}

int siw_destroy_ah(struct ibv_ah *ah)
{
	return -EOPNOTSUPP;
}

void siw_async_event(struct ibv_async_event *event)
{
	struct ibv_qp *base_qp = event->element.qp;
	struct ibv_cq *base_cq = event->element.cq;

	switch (event->event_type) {

	case IBV_EVENT_CQ_ERR:
		printf("libsiw: CQ[%d] event: error\n",
			cq_base2siw(base_cq)->id);
		break;

	case IBV_EVENT_QP_FATAL:
		printf("libsiw: QP[%d] event: fatal error\n",
			qp_base2siw(base_qp)->id);
		break;

	case IBV_EVENT_QP_REQ_ERR:
		printf("libsiw: QP[%d] event: request error\n",
			qp_base2siw(base_qp)->id);
		break;

	case IBV_EVENT_QP_ACCESS_ERR:
		printf("libsiw: QP[%d] event: access error\n",
			qp_base2siw(base_qp)->id);
		break;

	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		break;

	default:
		break;
	}
}
