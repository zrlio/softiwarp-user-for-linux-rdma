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
#include <net/if.h>
#include <pthread.h>

#include "siw.h"
#include "siw_abi.h"

extern const int siw_debug;

static const struct verbs_match_ent rnic_table[] = {
	VERBS_NAME_MATCH("siw", NULL),
	{},
};

static struct verbs_context_ops siw_context_ops = {
	.query_device	= siw_query_device,
	.query_port	= siw_query_port,
	.query_qp       = siw_query_qp,
	.alloc_pd	= siw_alloc_pd,
	.dealloc_pd	= siw_free_pd,
	.reg_mr		= siw_reg_mr,
	.dereg_mr	= siw_dereg_mr,
	.create_cq	= siw_create_cq,
	.resize_cq	= siw_resize_cq,
	.destroy_cq	= siw_destroy_cq,
	.create_srq	= siw_create_srq,
	.modify_srq	= siw_modify_srq,
	.destroy_srq	= siw_destroy_srq,
	.create_qp	= siw_create_qp,
	.modify_qp	= siw_modify_qp,
	.destroy_qp	= siw_destroy_qp,
	.post_send	= siw_post_send,
	.post_recv	= siw_post_recv,
	.post_srq_recv	= siw_post_srq_recv,
	.poll_cq	= siw_poll_cq,
	.create_ah	= siw_create_ah,
	.destroy_ah	= siw_destroy_ah,
	.attach_mcast	= NULL,
	.detach_mcast	= NULL,
	.req_notify_cq	= siw_notify_cq,
	.async_event	= siw_async_event
};

static struct verbs_context *siw_alloc_context(struct ibv_device *base_dev,
					       int fd)
{
	struct siw_context *ctx;
	struct ibv_get_context cmd;
	struct siw_alloc_ucontext_resp resp;

	memset(&cmd, 0, sizeof(cmd));
	memset(&resp, 0, sizeof(resp));

	ctx = verbs_init_and_alloc_context(base_dev, fd, ctx, base_ctx);
	if (!ctx)
		return NULL;

	if (ibv_cmd_get_context(&ctx->base_ctx, &cmd, sizeof(cmd),
				&resp.base, sizeof(resp))) {
		verbs_uninit_context(&ctx->base_ctx);
		free(ctx);

		return NULL;
	}
	verbs_set_ops(&ctx->base_ctx, &siw_context_ops);
	ctx->dev_id = resp.siw.dev_id;

	return &ctx->base_ctx;
}

static void siw_free_context(struct ibv_context *ibv_ctx)
{
	struct siw_context *ctx = ctx_ibv2siw(ibv_ctx);

	verbs_uninit_context(&ctx->base_ctx);
	free(ctx);
}

static struct verbs_device *siw_device_alloc(struct verbs_sysfs_dev *unused)
{
	struct siw_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->base_dev;
}

static void siw_device_free(struct verbs_device *vdev)
{
	struct siw_device *dev = container_of(vdev, struct siw_device,
					      base_dev);
	free(dev);
}

static struct verbs_device_ops siw_dev_ops = {
	.name = "siw",
	.match_min_abi_version = 0,
	.match_max_abi_version = INT_MAX,
	.match_table = rnic_table,
	.alloc_device = siw_device_alloc,
	.uninit_device = siw_device_free,
	.alloc_context = siw_alloc_context,
	.free_context = siw_free_context
};

PROVIDER_DRIVER(siw_dev_ops);
