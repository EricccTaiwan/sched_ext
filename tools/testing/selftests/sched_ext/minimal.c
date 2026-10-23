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
#include "minimal.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(minimal)

static enum scx_test_status run(void *ctx)
{
	struct minimal_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, minimal_ops);
	SCX_ASSERT_ENABLED();

	return SCX_TEST_PASS;
}

struct scx_test minimal = {
	.name = "minimal",
	.description = "Verify we can load a fully minimal scheduler",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&minimal)
