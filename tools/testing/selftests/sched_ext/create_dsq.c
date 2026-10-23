/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "create_dsq.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(create_dsq)

static enum scx_test_status run(void *ctx)
{
	struct create_dsq_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, create_dsq_ops);
	SCX_ASSERT_ALIVE(tctx->skel, uei);

	bpf_link__destroy(tctx->link);
	tctx->link = NULL;

	SCX_EQ(tctx->skel->bss->nr_lifecycle_tests, 1024);

	return SCX_TEST_PASS;
}

struct scx_test create_dsq = {
	.name = "create_dsq",
	.description = "Create, reject duplicates, destroy and recreate DSQs",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&create_dsq)
