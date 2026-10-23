/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "maximal.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX_TYPE(maximal);
SCX_TEST_DEFINE_CLEANUP(maximal)

static enum scx_test_status setup(void **ctx)
{
	struct maximal_ctx *tctx;

	SCX_TEST_OPEN(tctx, maximal);
	SCX_TEST_LOAD(tctx, maximal);

	bpf_map__set_autoattach(tctx->skel->maps.maximal_ops, false);
	if (maximal__attach(tctx->skel)) {
		maximal__destroy(tctx->skel);
		free(tctx);
		SCX_FAIL("Failed to attach skel");
	}

	*ctx = tctx;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct maximal_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, maximal_ops);
	SCX_ASSERT_ALIVE(tctx->skel, uei);

	return SCX_TEST_PASS;
}

struct scx_test maximal = {
	.name = "maximal",
	.description = "Verify we can load a scheduler with every callback defined",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&maximal)
