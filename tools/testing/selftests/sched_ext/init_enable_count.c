/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include "scx_test.h"
#include "init_enable_count.bpf.skel.h"

#define SCHED_EXT 7

/* In helpers, so a failing SCX_*() check cannot skip run_test()'s teardown */
static enum scx_test_status check_pre_fork_counts(const struct init_enable_count *skel,
						  u32 num_pre_forks)
{
	SCX_GE(skel->bss->init_task_cnt, num_pre_forks);
	SCX_GE(skel->bss->exit_task_cnt, num_pre_forks);

	return SCX_TEST_PASS;
}

static enum scx_test_status check_counts(const struct init_enable_count *skel,
					 bool global, u32 num_children)
{
	SCX_GE(skel->bss->init_task_cnt, 2 * num_children);
	SCX_GE(skel->bss->exit_task_cnt, 2 * num_children);

	if (global) {
		SCX_GE(skel->bss->enable_cnt, 2 * num_children);
		SCX_GE(skel->bss->disable_cnt, 2 * num_children);
	} else {
		SCX_EQ(skel->bss->enable_cnt, num_children);
		SCX_EQ(skel->bss->disable_cnt, num_children);
	}
	/*
	 * We forked a ton of tasks before we attached the scheduler above, so
	 * this should be fine. Technically it could be flaky if a ton of forks
	 * are happening at the same time in other processes, but that should
	 * be exceedingly unlikely.
	 */
	SCX_GT(skel->bss->init_transition_cnt, skel->bss->init_fork_cnt);
	SCX_GE(skel->bss->init_fork_cnt, 2 * num_children);

	return SCX_TEST_PASS;
}

static enum scx_test_status run_test(bool global)
{
	const u32 num_children = 5, num_pre_forks = 1024;
	enum scx_test_status status = SCX_TEST_FAIL;
	struct init_enable_count *skel = NULL;
	struct bpf_link *link = NULL;
	int ret, i, wstatus, nforked, nfailed = 0;
	struct sched_param param = {};
	pid_t pids[num_pre_forks];
	int pipe_fds[2] = { -1, -1 };

	SCX_FAIL_IF(pipe(pipe_fds) < 0, "Failed to create pipe");

	skel = init_enable_count__open();
	if (!skel) {
		SCX_ERR("Failed to open");
		goto out;
	}
	SCX_ENUM_INIT(skel);

	if (!global)
		skel->struct_ops.init_enable_count_ops->flags |= SCX_OPS_SWITCH_PARTIAL;

	if (init_enable_count__load(skel)) {
		SCX_ERR("Failed to load skel");
		goto out;
	}

	/*
	 * Fork a bunch of children before we attach the scheduler so that we
	 * ensure (at least in practical terms) that there are more tasks that
	 * transition from SCHED_OTHER -> SCHED_EXT than there are tasks that
	 * take the fork() path either below or in other processes.
	 *
	 * All children will block on read() on the pipe until the parent closes
	 * the write end after attaching the scheduler, which signals all of
	 * them to exit simultaneously. Auto-reap so we don't have to wait on
	 * them.
	 */
	signal(SIGCHLD, SIG_IGN);
	for (i = 0; i < num_pre_forks; i++) {
		pid_t pid = fork();

		if (pid < 0) {
			SCX_ERR("Failed to fork child");
			goto out;
		}
		if (pid == 0) {
			char buf;

			close(pipe_fds[1]);
			if (read(pipe_fds[0], &buf, 1) < 0)
				exit(1);
			close(pipe_fds[0]);
			exit(0);
		}
	}
	close(pipe_fds[0]);
	pipe_fds[0] = -1;

	link = bpf_map__attach_struct_ops(skel->maps.init_enable_count_ops);
	if (!link) {
		SCX_ERR("Failed to attach struct_ops");
		goto out;
	}

	/* Signal all pre-forked children to exit. */
	close(pipe_fds[1]);
	pipe_fds[1] = -1;
	signal(SIGCHLD, SIG_DFL);

	bpf_link__destroy(link);
	link = NULL;

	if (check_pre_fork_counts(skel, num_pre_forks) != SCX_TEST_PASS)
		goto out;

	link = bpf_map__attach_struct_ops(skel->maps.init_enable_count_ops);
	if (!link) {
		SCX_ERR("Failed to attach struct_ops");
		goto out;
	}

	/* SCHED_EXT children */
	nforked = 0;
	for (i = 0; i < num_children; i++) {
		pids[i] = fork();
		if (pids[i] == 0) {
			ret = sched_setscheduler(0, SCHED_EXT, &param);
			SCX_BUG_ON(ret, "Failed to set sched to sched_ext");

			/*
			 * Reset to SCHED_OTHER for half of them. Counts for
			 * everything should still be the same regardless, as
			 * ops.disable() is invoked even if a task is still on
			 * SCHED_EXT before it exits.
			 */
			if (i % 2 == 0) {
				ret = sched_setscheduler(0, SCHED_OTHER, &param);
				SCX_BUG_ON(ret, "Failed to reset sched to normal");
			}
			exit(0);
		}
		if (pids[i] > 0)
			nforked++;
	}
	/* Reap every child before reporting */
	for (i = 0; i < num_children; i++) {
		if (pids[i] <= 0)
			continue;
		if (waitpid(pids[i], &wstatus, 0) != pids[i] || wstatus)
			nfailed++;
	}
	if (nforked < num_children || nfailed) {
		SCX_ERR("SCX children: forked %d of %u, %d failed",
			nforked, num_children, nfailed);
		goto out;
	}

	/* SCHED_OTHER children */
	nforked = 0;
	for (i = 0; i < num_children; i++) {
		pids[i] = fork();
		if (pids[i] == 0)
			exit(0);
		if (pids[i] > 0)
			nforked++;
	}
	for (i = 0; i < num_children; i++) {
		if (pids[i] <= 0)
			continue;
		if (waitpid(pids[i], &wstatus, 0) != pids[i] || wstatus)
			nfailed++;
	}
	if (nforked < num_children || nfailed) {
		SCX_ERR("Normal children: forked %d of %u, %d failed",
			nforked, num_children, nfailed);
		goto out;
	}

	bpf_link__destroy(link);
	link = NULL;

	status = check_counts(skel, global, num_children);
out:
	if (link)
		bpf_link__destroy(link);
	/* Close the pipe first so SIG_IGN can reap the woken children */
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	if (pipe_fds[0] >= 0)
		close(pipe_fds[0]);
	init_enable_count__destroy(skel);
	signal(SIGCHLD, SIG_DFL);

	return status;
}

static enum scx_test_status run(void *ctx)
{
	enum scx_test_status status;

	status = run_test(true);
	if (status != SCX_TEST_PASS)
		return status;

	return run_test(false);
}

struct scx_test init_enable_count = {
	.name = "init_enable_count",
	.description = "Verify we correctly count the occurrences of init, "
		       "enable, etc callbacks.",
	.run = run,
};
REGISTER_SCX_TEST(&init_enable_count)
