// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "numa.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX_TYPE(numa);
SCX_TEST_DEFINE_CLEANUP(numa)

static enum scx_test_status setup(void **ctx)
{
	struct numa_ctx *tctx;

	SCX_TEST_OPEN(tctx, numa);
	tctx->skel->rodata->__COMPAT_SCX_PICK_IDLE_IN_NODE = SCX_PICK_IDLE_IN_NODE;
	tctx->skel->struct_ops.numa_ops->flags = SCX_OPS_BUILTIN_IDLE_PER_NODE;
	SCX_TEST_LOAD(tctx, numa);

	*ctx = tctx;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct numa_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, numa_ops);

	/* Just sleeping is fine, plenty of scheduling events happening */
	sleep(1);

	SCX_EQ(tctx->skel->data->uei.kind, EXIT_KIND(SCX_EXIT_NONE));

	return SCX_TEST_PASS;
}

struct scx_test numa = {
	.name = "numa",
	.description = "Verify NUMA-aware functionalities",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&numa)
