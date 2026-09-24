/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "select_cpu_dispatch_dbl_dsp.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(select_cpu_dispatch_dbl_dsp);

static enum scx_test_status run(void *ctx)
{
	struct select_cpu_dispatch_dbl_dsp_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, select_cpu_dispatch_dbl_dsp_ops);

	sleep(1);

	SCX_EQ(tctx->skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));

	return SCX_TEST_PASS;
}

struct scx_test select_cpu_dispatch_dbl_dsp = {
	.name = "select_cpu_dispatch_dbl_dsp",
	.description = "Verify graceful failure if we dispatch twice to a "
		       "DSQ in ops.select_cpu()",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&select_cpu_dispatch_dbl_dsp)
