/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "select_cpu_dfl.bpf.skel.h"
#include "scx_test.h"

#define NUM_CHILDREN 1028

SCX_TEST_DEFINE_CTX(select_cpu_dfl);

static enum scx_test_status run(void *ctx)
{
	struct select_cpu_dfl_ctx *tctx = ctx;
	pid_t pids[NUM_CHILDREN];
	int i, status, nforked = 0;

	SCX_TEST_ATTACH(tctx, select_cpu_dfl_ops);

	for (i = 0; i < NUM_CHILDREN; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			sleep(1);
			exit(0);
		}
		if (pids[i] > 0)
			nforked++;
	}

	for (i = 0; i < NUM_CHILDREN; i++) {
		if (pids[i] <= 0)
			continue;
		SCX_EQ(waitpid(pids[i], &status, 0), pids[i]);
		SCX_EQ(status, 0);
	}

	SCX_GT(nforked, 0);
	SCX_ASSERT(!tctx->skel->bss->saw_local);

	return SCX_TEST_PASS;
}

struct scx_test select_cpu_dfl = {
	.name = "select_cpu_dfl",
	.description = "Verify the default ops.select_cpu() dispatches tasks "
		       "when idles cores are found, and skips ops.enqueue()",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&select_cpu_dfl)
