/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "select_cpu_vtime.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(select_cpu_vtime);

static enum scx_test_status run(void *ctx)
{
	struct select_cpu_vtime_ctx *tctx = ctx;

	SCX_ASSERT(!tctx->skel->bss->consumed);

	SCX_TEST_ATTACH(tctx, select_cpu_vtime_ops);

	sleep(1);

	SCX_ASSERT(tctx->skel->bss->consumed);

	return SCX_TEST_PASS;
}

struct scx_test select_cpu_vtime = {
	.name = "select_cpu_vtime",
	.description = "Test doing direct vtime-dispatching from "
		       "ops.select_cpu(), to a non-built-in DSQ",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&select_cpu_vtime)
