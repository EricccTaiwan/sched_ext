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
#include "enq_last_no_enq_fails.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(enq_last_no_enq_fails);

static enum scx_test_status run(void *ctx)
{
	struct enq_last_no_enq_fails_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, enq_last_no_enq_fails_ops);
	SCX_FAIL_IF(!tctx->skel->bss->exit_kind, "Incorrectly stayed loaded");

	return SCX_TEST_PASS;
}

struct scx_test enq_last_no_enq_fails = {
	.name = "enq_last_no_enq_fails",
	.description = "Verify we eject a scheduler if we specify "
		       "the SCX_OPS_ENQ_LAST flag without defining "
		       "ops.enqueue()",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&enq_last_no_enq_fails)
