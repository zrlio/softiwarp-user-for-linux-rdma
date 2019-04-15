/*
 * Software iWARP library for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2019, IBM Corporation
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

#ifndef _SIW_H
#define _SIW_H

#include <pthread.h>
#include <inttypes.h>
#include <stddef.h>

#include <infiniband/driver.h>
#include <infiniband/kern-abi.h>

struct siw_device {
	struct verbs_device base_dev;
};

struct siw_srq {
	struct ibv_srq base_srq;
	struct siw_rqe *recvq;
	uint32_t rq_put;
	uint32_t num_rqe;
	pthread_spinlock_t lock;
};

struct siw_mr {
	struct verbs_mr base_mr;
};

struct siw_qp {
	struct ibv_qp base_qp;
	struct siw_device *siw_dev;

	uint32_t id;

	pthread_spinlock_t sq_lock;
	pthread_spinlock_t rq_lock;

	struct ibv_post_send db_req;
	struct ib_uverbs_post_send_resp db_resp;

	uint32_t num_sqe;
	uint32_t sq_put;
	int sq_sig_all;
	struct siw_sqe *sendq;

	uint32_t num_rqe;
	uint32_t rq_put;
	struct siw_rqe *recvq;
	struct siw_srq *srq;
};

struct siw_cq {
	struct ibv_cq base_cq;
	struct siw_device *siw_dev;
	uint32_t id;

	/* Points to kernel shared control
	 * object at the end of CQE array
	 */
	struct siw_cq_ctrl *ctrl;

	int num_cqe;
	uint32_t cq_get;
	struct siw_cqe *queue;
	pthread_spinlock_t lock;
};

struct siw_context {
	struct verbs_context base_ctx;
	uint32_t dev_id;
};

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	({                                                                     \
		const typeof(((type *)0)->member)(*__mptr) = (ptr);            \
		(type *)((char *)__mptr - offsetof(type, member));             \
	})
#endif

#define ctx_base2siw(base_ctx)                                                 \
	container_of(base_ctx, struct siw_context, base_ctx)
#define ctx_ibv2siw(ibv_ctx)                                                   \
	container_of(ibv_ctx, struct siw_context, base_ctx.context)
#define qp_base2siw(ibv_qp) container_of(ibv_qp, struct siw_qp, base_qp)
#define cq_base2siw(ibv_cq) container_of(ibv_cq, struct siw_cq, base_cq)
#define mr_base2siw(verbs_mr) container_of(verbs_mr, struct siw_mr, base_mr)
#define srq_base2siw(ibv_srq) container_of(ibv_srq, struct siw_srq, base_srq)

#endif /* _SIW_H */
