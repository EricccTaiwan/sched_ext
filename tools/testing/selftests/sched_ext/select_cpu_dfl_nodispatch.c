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
#include "select_cpu_dfl_nodispatch.bpf.skel.h"
#include "scx_test.h"

#define NUM_CHILDREN 1028

SCX_TEST_DEFINE_CTX(select_cpu_dfl_nodispatch);

static enum scx_test_status run(void *ctx)
{
	struct select_cpu_dfl_nodispatch_ctx *tctx = ctx;
	pid_t pids[NUM_CHILDREN];
	int i, status, nforked = 0, nfailed = 0;

	SCX_TEST_ATTACH(tctx, select_cpu_dfl_nodispatch_ops);

	for (i = 0; i < NUM_CHILDREN; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			sleep(1);
			exit(0);
		}
		if (pids[i] > 0)
			nforked++;
	}

	/* Reap every child before reporting */
	for (i = 0; i < NUM_CHILDREN; i++) {
		if (pids[i] <= 0)
			continue;
		if (waitpid(pids[i], &status, 0) != pids[i] || status)
			nfailed++;
	}

	/* With this many children, some forks may fail on a loaded machine */
	SCX_GT(nforked, 0);
	SCX_EQ(nfailed, 0);
	SCX_ASSERT(tctx->skel->bss->saw_local);

	return SCX_TEST_PASS;
}

struct scx_test select_cpu_dfl_nodispatch = {
	.name = "select_cpu_dfl_nodispatch",
	.description = "Verify behavior of scx_bpf_select_cpu_dfl() in "
		       "ops.select_cpu()",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&select_cpu_dfl_nodispatch)
