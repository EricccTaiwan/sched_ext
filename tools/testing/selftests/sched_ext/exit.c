/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#include <bpf/bpf.h>
#include <sched.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "exit.bpf.skel.h"
#include "scx_test.h"

#include "exit_test.h"

static enum scx_test_status run_exit_test(enum exit_test_case tc)
{
	enum scx_test_status status = SCX_TEST_FAIL;
	struct bpf_link *link = NULL;
	struct exit *skel;
	char buf[16];

	skel = exit__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	skel->rodata->exit_point = tc;
	if (exit__load(skel)) {
		SCX_ERR("Failed to load skel");
		goto out;
	}

	link = bpf_map__attach_struct_ops(skel->maps.exit_ops);
	if (!link) {
		SCX_ERR("Failed to attach scheduler");
		goto out;
	}

	/* Assumes uei.kind is written last */
	while (skel->data->uei.kind == EXIT_KIND(SCX_EXIT_NONE))
		sched_yield();

	if (skel->data->uei.kind != EXIT_KIND(SCX_EXIT_UNREG_BPF)) {
		SCX_ERR("Unexpected exit kind: %llu",
			(unsigned long long)skel->data->uei.kind);
		goto out;
	}
	if (skel->data->uei.exit_code != tc) {
		SCX_ERR("Unexpected exit code: %lld",
			(long long)skel->data->uei.exit_code);
		goto out;
	}
	sprintf(buf, "%d", tc);
	if (strcmp(skel->data->uei.msg, buf)) {
		SCX_ERR("Unexpected exit msg: %s", skel->data->uei.msg);
		goto out;
	}

	status = SCX_TEST_PASS;
out:
	if (link)
		bpf_link__destroy(link);
	exit__destroy(skel);

	return status;
}

static enum scx_test_status run(void *ctx)
{
	enum exit_test_case tc;

	for (tc = 0; tc < NUM_EXITS; tc++) {
		enum scx_test_status status;

		/*
		 * On single-CPU systems, ops.select_cpu() is never
		 * invoked, so skip this test to avoid getting stuck
		 * indefinitely.
		 */
		if (tc == EXIT_SELECT_CPU && libbpf_num_possible_cpus() == 1)
			continue;

		status = run_exit_test(tc);
		if (status != SCX_TEST_PASS)
			return status;
	}

	return SCX_TEST_PASS;
}

struct scx_test exit_test = {
	.name = "exit",
	.description = "Verify we can cleanly exit a scheduler in multiple places",
	.run = run,
};
REGISTER_SCX_TEST(&exit_test)
