// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "enq_select_cpu.bpf.skel.h"
#include "scx_test.h"

SCX_TEST_DEFINE_CTX(enq_select_cpu);

static int test_select_cpu_from_user(const struct enq_select_cpu *skel)
{
	int fd, ret;
	__u64 args[1];

	LIBBPF_OPTS(bpf_test_run_opts, attr,
		.ctx_in = args,
		.ctx_size_in = sizeof(args),
	);

	args[0] = getpid();
	fd = bpf_program__fd(skel->progs.select_cpu_from_user);
	if (fd < 0)
		return fd;

	ret = bpf_prog_test_run_opts(fd, &attr);
	if (ret < 0)
		return ret;

	fprintf(stderr, "%s: CPU %d\n", __func__, attr.retval);

	return 0;
}

static enum scx_test_status run(void *ctx)
{
	struct enq_select_cpu_ctx *tctx = ctx;

	SCX_TEST_ATTACH(tctx, enq_select_cpu_ops);

	/* Pick an idle CPU from user-space */
	SCX_FAIL_IF(test_select_cpu_from_user(tctx->skel), "Failed to pick idle CPU");

	sleep(1);

	SCX_EQ(tctx->skel->data->uei.kind, EXIT_KIND(SCX_EXIT_NONE));

	return SCX_TEST_PASS;
}

struct scx_test enq_select_cpu = {
	.name = "enq_select_cpu",
	.description = "Verify scx_bpf_select_cpu_dfl() from multiple contexts",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&enq_select_cpu)
