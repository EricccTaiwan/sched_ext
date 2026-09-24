/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <unistd.h>
#include "ddsp_vtimelocal_fail.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(ddsp_vtimelocal_fail);

static enum scx_test_status run(void *ctx)
{
	struct ddsp_vtimelocal_fail_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, ddsp_vtimelocal_fail_ops);

	sleep(1);

	SCX_EQ(tctx->skel->data->uei.kind, EXIT_KIND(SCX_EXIT_ERROR));

	return SCX_TEST_PASS;
}

struct scx_test ddsp_vtimelocal_fail = {
	.name = "ddsp_vtimelocal_fail",
	.description = "Verify we gracefully fail, and fall back to using a "
		       "built-in DSQ, if we do a direct vtime dispatch to a "
		       "built-in DSQ from DSQ in ops.select_cpu()",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&ddsp_vtimelocal_fail)
