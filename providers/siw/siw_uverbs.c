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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "siw_user.h"
#include "siw.h"
#include "siw_abi.h"

#ifdef __STDC_NO_ATOMICS__
#error "No built-in atomics defined!"
#else
#define _load_mmapped(a)	__atomic_load_n(&(a), __ATOMIC_RELAXED)
#define _store_mmaped(a, b)	__atomic_store_n(&(a), b, __ATOMIC_RELAXED)
#endif

extern const int siw_debug;

int siw_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct siw_cq *cq = cq_base2siw(ibcq);
	int rv = 0;

	if (solicited)
		_store_mmaped(cq->ctrl->notify, SIW_NOTIFY_SOLICITED);
	else
		_store_mmaped(cq->ctrl->notify, SIW_NOTIFY_SOLICITED |
			      SIW_NOTIFY_NEXT_COMPLETION);
	return rv;
}

static enum siw_opcode map_send_opcode(enum ibv_wr_opcode ibv_op)
{
	switch (ibv_op) {

	case IBV_WR_SEND:	return SIW_OP_SEND;
	case IBV_WR_RDMA_WRITE:	return SIW_OP_WRITE;
	case IBV_WR_RDMA_READ:	return SIW_OP_READ;
	default:
		printf("libsiw: op %d not supported\n", ibv_op);
	}
	return SIW_NUM_OPCODES + 1;
}

static inline uint16_t map_send_flags(int ibv_flags)
{
	uint16_t flags = SIW_WQE_VALID;

	if (ibv_flags & IBV_SEND_SIGNALED)
		flags |= SIW_WQE_SIGNALLED;
	if (ibv_flags & IBV_SEND_SOLICITED)
		flags |= SIW_WQE_SOLICITED;
	if (ibv_flags & IBV_SEND_INLINE)
		flags |= SIW_WQE_INLINE;
	if (ibv_flags & IBV_SEND_FENCE)
		flags |= SIW_WQE_READ_FENCE;

	return flags;
}

static inline int push_send_wqe(struct ibv_send_wr *base_wr,
				struct siw_sqe *siw_sqe, int sig_all)
{
	uint32_t flags = map_send_flags(base_wr->send_flags);

	siw_sqe->id		= base_wr->wr_id;
	siw_sqe->num_sge	= base_wr->num_sge;
	siw_sqe->raddr		= base_wr->wr.rdma.remote_addr;
	siw_sqe->rkey		= base_wr->wr.rdma.rkey;

	siw_sqe->opcode = map_send_opcode(base_wr->opcode);
	if (siw_sqe->opcode > SIW_NUM_OPCODES) {
		if (siw_debug)
			printf("libsiw: opcode %d unsupported\n",
				base_wr->opcode);
		return -EINVAL;
	}
	if (sig_all)
		flags |= SIW_WQE_SIGNALLED;

	if (flags & SIW_WQE_INLINE) {
		char *data = (char *)&siw_sqe->sge[1];
		int bytes = 0, i = 0;

		/* Allow more than SIW_MAX_SGE, since content copied here */
		while (i < base_wr->num_sge) {
			bytes += base_wr->sg_list[i].length;
			if (bytes > (int)SIW_MAX_INLINE) {
				if (siw_debug)
					printf("libsiw: inline data: %d:%d\n",
						bytes, (int)SIW_MAX_INLINE);
				return -EINVAL;
			}
			memcpy(data, (void *)base_wr->sg_list[i].addr,
				base_wr->sg_list[i].length);
			data += base_wr->sg_list[i++].length;
		}
		siw_sqe->sge[0].length = bytes;

	} else if (base_wr->num_sge == 1) {
		siw_sqe->sge[0].laddr	= base_wr->sg_list[0].addr;
		siw_sqe->sge[0].length	= base_wr->sg_list[0].length;
		siw_sqe->sge[0].lkey	= base_wr->sg_list[0].lkey;
	} else if (base_wr->num_sge && base_wr->num_sge <= SIW_MAX_SGE)
		/* this assumes same layout of siw and base SGE */
		memcpy(siw_sqe->sge, base_wr->sg_list,
		       siw_sqe->num_sge * sizeof(struct ibv_sge));
	else
		return -EINVAL;

	_store_mmaped(siw_sqe->flags, flags);

	return 0;
}

static int siw_db(struct siw_qp *qp)
{
	int rv;

	rv = write(qp->base_qp.context->cmd_fd, &qp->db_req,
		   sizeof(qp->db_req));
	if (rv == sizeof(qp->db_req))
		return 0;

	if (siw_debug)
		printf("libsiw: QP[%d]: Doorbell call failed: %d\n",
			qp->id, rv);

	return rv;
}

int siw_post_send(struct ibv_qp *base_qp, struct ibv_send_wr *wr,
		  struct ibv_send_wr **bad_wr)
{
	struct siw_qp *qp = qp_base2siw(base_qp);
	uint32_t sq_put;
	int sq_busy, rv = 0;

	*bad_wr = NULL;

	pthread_spin_lock(&qp->sq_lock);

	sq_put = qp->sq_put;

	/* If last WQE is idle, we assume SQ is not actively
	 * processed. Only then, the doorbell system call will
	 * be issued. This may significantly reduce unnecessary
	 * doorbell system calls on a busy SQ.
	 */
	sq_busy = _load_mmapped((&qp->sendq[(sq_put-1) % qp->num_sqe])->flags);
	sq_busy &= SIW_WQE_VALID;

	/*
	 * Push all current work requests into mmapped SQ
	 */
	while (wr) {
		int idx = sq_put % qp->num_sqe;
		struct siw_sqe *sqe = &qp->sendq[idx];
		uint16_t sqe_flags = _load_mmapped(sqe->flags);

		if (!(sqe_flags & SIW_WQE_VALID)) {
			rv = push_send_wqe(wr, sqe, qp->sq_sig_all);
			if (rv) {
				*bad_wr = wr;
				break;
			}
		} else {
			if (siw_debug)
				printf("libsiw: QP[%d]: SQ overflow, idx %d\n",
					qp->id, idx);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		sq_put++;
		wr = wr->next;
	}
	if (sq_put != qp->sq_put) {
		if (!sq_busy) {
			rv = siw_db(qp);
			if (rv)
				*bad_wr = wr;
		}
		qp->sq_put = sq_put;
	}
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

static inline int push_recv_wqe(struct ibv_recv_wr *base_wr,
				struct siw_rqe *siw_rqe)
{
	siw_rqe->id = base_wr->wr_id;
	siw_rqe->num_sge = base_wr->num_sge;

	if (base_wr->num_sge == 1) {
		siw_rqe->sge[0].laddr = base_wr->sg_list[0].addr;
		siw_rqe->sge[0].length = base_wr->sg_list[0].length;
		siw_rqe->sge[0].lkey = base_wr->sg_list[0].lkey;
	} else if (base_wr->num_sge && base_wr->num_sge <= SIW_MAX_SGE)
		/* this assumes same layout of siw and base SGE */
		memcpy(siw_rqe->sge, base_wr->sg_list,
		       sizeof(struct ibv_sge) * base_wr->num_sge);
	else
		return -EINVAL;

	_store_mmaped(siw_rqe->flags, SIW_WQE_VALID);

	return 0;
}

int siw_post_recv(struct ibv_qp *base_qp, struct ibv_recv_wr *wr,
		  struct ibv_recv_wr **bad_wr)
{
	struct siw_qp *qp = qp_base2siw(base_qp);
	uint32_t rq_put;
	int rv = 0;

	pthread_spin_lock(&qp->rq_lock);

	rq_put = qp->rq_put;

	while (wr) {
		int idx = rq_put % qp->num_rqe;
		struct siw_rqe *rqe = &qp->recvq[idx];
		uint32_t rqe_flags = _load_mmapped(rqe->flags);

		if (!(rqe_flags & SIW_WQE_VALID)) {
			if (push_recv_wqe(wr, rqe)) {
				*bad_wr = wr;
				rv = -EINVAL;
				break;
			}
		} else {
			if (siw_debug)
				printf("libsiw: QP[%d]: RQ overflow, idx %d\n",
					qp->id, idx);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		rq_put++;
		wr = wr->next;
	}
	qp->rq_put = rq_put;

	pthread_spin_unlock(&qp->rq_lock);

	return rv;
}

int siw_post_srq_recv(struct ibv_srq *base_srq, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct siw_srq *srq = srq_base2siw(base_srq);
	uint32_t srq_put;
	int rv = 0;

	pthread_spin_lock(&srq->lock);

	srq_put = srq->rq_put;

	while (wr) {
		int idx = srq_put % srq->num_rqe;
		struct siw_rqe *rqe = &srq->recvq[idx];
		uint32_t rqe_flags = _load_mmapped(rqe->flags);

		if (!(rqe_flags & SIW_WQE_VALID)) {
			if (push_recv_wqe(wr, rqe)) {
				*bad_wr = wr;
				rv = -EINVAL;
				break;
			}
		} else {
			if (siw_debug)
				printf("libsiw: SRQ[%p]: SRQ overflow\n", srq);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		srq_put++;
		wr = wr->next;
	}
	srq->rq_put = srq_put;

	pthread_spin_unlock(&srq->lock);

	return rv;
}

static struct {
	enum siw_opcode siw;
	enum ibv_wc_opcode base;
} map_cqe_opcode[SIW_NUM_OPCODES] = {
	{SIW_OP_WRITE,		IBV_WC_RDMA_WRITE},
	{SIW_OP_READ,		IBV_WC_RDMA_READ},
	{SIW_OP_READ_LOCAL_INV, IBV_WC_RDMA_READ},
	{SIW_OP_SEND,		IBV_WC_SEND},
	{SIW_OP_SEND_WITH_IMM,	IBV_WC_SEND},
	{SIW_OP_SEND_REMOTE_INV, IBV_WC_SEND},
	{SIW_OP_FETCH_AND_ADD,	IBV_WC_FETCH_ADD},
	{SIW_OP_COMP_AND_SWAP,	IBV_WC_COMP_SWAP},
	{SIW_OP_RECEIVE,	IBV_WC_RECV}
};

static struct {
	enum siw_opcode siw;
	enum ibv_wc_opcode base;
} map_cqe_status[SIW_NUM_WC_STATUS] = {
	{SIW_WC_SUCCESS,	IBV_WC_SUCCESS},
	{SIW_WC_LOC_LEN_ERR,	IBV_WC_LOC_LEN_ERR},
	{SIW_WC_LOC_PROT_ERR,	IBV_WC_LOC_PROT_ERR},
	{SIW_WC_LOC_QP_OP_ERR,	IBV_WC_LOC_QP_OP_ERR},
	{SIW_WC_WR_FLUSH_ERR,	IBV_WC_WR_FLUSH_ERR},
	{SIW_WC_BAD_RESP_ERR,	IBV_WC_BAD_RESP_ERR},
	{SIW_WC_LOC_ACCESS_ERR,	IBV_WC_LOC_ACCESS_ERR},
	{SIW_WC_REM_ACCESS_ERR,	IBV_WC_REM_ACCESS_ERR},
	{SIW_WC_REM_INV_REQ_ERR, IBV_WC_REM_INV_REQ_ERR},
	{SIW_WC_GENERAL_ERR,	IBV_WC_GENERAL_ERR}
};

static inline void copy_cqe(struct siw_cqe *cqe, struct ibv_wc *wc)
{
	wc->wr_id = cqe->id;
	wc->byte_len = cqe->bytes;

	/* No immediate data supported yet */
	wc->wc_flags = 0;
	wc->imm_data = 0;

	wc->vendor_err = 0;
	wc->opcode = map_cqe_opcode[cqe->opcode].base;
	wc->status = map_cqe_status[cqe->status].base;
	wc->qp_num = (uint32_t)cqe->qp_id;
}

int siw_poll_cq(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct siw_cq *cq = cq_base2siw(ibcq);
	int new = 0;

	pthread_spin_lock(&cq->lock);

	for (; num_entries--; wc++) {
		struct siw_cqe *cqe;

		cqe = &cq->queue[cq->cq_get % cq->num_cqe];

		if (_load_mmapped(cqe->flags) & SIW_WQE_VALID) {
			copy_cqe(cqe, wc);
			_store_mmaped(cqe->flags, 0);
			cq->cq_get++;
			new++;
		} else
			break;

	}
	pthread_spin_unlock(&cq->lock);

	return new;
}
