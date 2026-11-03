// SPDX-License-Identifier: GPL-2.0
/*
 * Test that a SCHED_EXT task still gets the ext_server's share of a CPU hogged
 * by an RT task after an ext_server pick on that CPU came back empty while the
 * task was queued on another DSQ.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "rt_stall_hold.bpf.skel.h"
#include "scx_test.h"

#define CORE_ID		0
#define HOLD_NS		(2500ULL * 1000 * 1000)
#define MEASURE_SECS	3

/* if @nap, sleep briefly every 2ms so that wakeups go through ops.enqueue() */
static void pin_and_spin(int policy, int prio, bool nap, int ready_fd)
{
	struct sched_param param = { .sched_priority = prio };
	struct timespec start, now;
	cpu_set_t mask;
	char c = 1;

	CPU_ZERO(&mask);
	CPU_SET(CORE_ID, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) ||
	    sched_setscheduler(0, policy, &param) ||
	    write(ready_fd, &c, 1) != 1)
		exit(EXIT_FAILURE);
	close(ready_fd);

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		do {
			clock_gettime(CLOCK_MONOTONIC, &now);
		} while ((now.tv_sec - start.tv_sec) * 1000000000L +
			 now.tv_nsec - start.tv_nsec < 2000000L);
		if (nap)
			usleep(500);
	}
}

static pid_t spawn(int policy, int prio, bool nap)
{
	int fds[2];
	pid_t pid;
	char c;

	if (pipe(fds))
		return -1;

	pid = fork();
	if (!pid) {
		close(fds[0]);
		pin_and_spin(policy, prio, nap, fds[1]);
	}

	close(fds[1]);
	if (pid > 0 && read(fds[0], &c, 1) != 1) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		pid = -1;
	}
	close(fds[0]);
	return pid;
}

static double runtime_secs(pid_t pid)
{
	unsigned long long ns;
	char path[64];
	FILE *f;
	int n;

	snprintf(path, sizeof(path), "/proc/%d/schedstat", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	n = fscanf(f, "%llu", &ns);
	fclose(f);
	if (n != 1)
		return -1;

	return ns / 1e9;
}

static enum scx_test_status setup(void **ctx)
{
	struct rt_stall_hold *skel;

	if (!__COMPAT_struct_has_field("rq", "ext_server")) {
		fprintf(stderr, "SKIP: ext DL server not supported\n");
		return SCX_TEST_SKIP;
	}

	skel = rt_stall_hold__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	skel->bss->hold_ns = HOLD_NS;
	SCX_FAIL_IF(rt_stall_hold__load(skel), "Failed to load skel");

	*ctx = skel;
	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct rt_stall_hold *skel = ctx;
	enum scx_test_status status = SCX_TEST_FAIL;
	struct bpf_link *link;
	pid_t ext_pid, rt_pid = -1;
	double before, after;
	int i;

	link = bpf_map__attach_struct_ops(skel->maps.rt_stall_hold_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	ext_pid = spawn(SCHED_EXT, 0, true);
	if (ext_pid < 0) {
		SCX_ERR("Failed to start the EXT task");
		goto out;
	}
	skel->bss->target_pid = ext_pid;

	rt_pid = spawn(SCHED_FIFO, 50, false);
	if (rt_pid < 0) {
		SCX_ERR("Failed to start the RT task");
		goto out;
	}

	/*
	 * Hold the EXT task on its next wakeup. While it's held, an ext_server
	 * pick on CORE_ID comes back empty. The timer then moves it to the
	 * local DSQ of CORE_ID, which the RT task is hogging.
	 */
	sleep(1);
	skel->bss->arm = true;
	for (i = 0; i < 100 && !skel->bss->nr_moved; i++)
		usleep(100 * 1000);
	if (!skel->bss->nr_moved) {
		SCX_ERR("EXT task wasn't held and moved (held=%llu)",
			(unsigned long long)skel->bss->nr_held);
		goto out;
	}

	before = runtime_secs(ext_pid);
	sleep(MEASURE_SECS);
	after = runtime_secs(ext_pid);
	if (before < 0 || after < 0) {
		SCX_ERR("Failed to read the EXT task's runtime");
		goto out;
	}

	fprintf(stderr, "EXT task ran %.3fs in %ds after it was moved to the local DSQ\n",
		after - before, MEASURE_SECS);
	if (after - before < 0.05) {
		SCX_ERR("EXT task starved behind the RT task");
		goto out;
	}

	if (skel->data->uei.kind != EXIT_KIND(SCX_EXIT_NONE)) {
		SCX_ERR("Scheduler exited (kind %lld)", (long long)skel->data->uei.kind);
		goto out;
	}

	status = SCX_TEST_PASS;
out:
	if (rt_pid > 0) {
		kill(rt_pid, SIGKILL);
		waitpid(rt_pid, NULL, 0);
	}
	if (ext_pid > 0) {
		kill(ext_pid, SIGKILL);
		waitpid(ext_pid, NULL, 0);
	}
	bpf_link__destroy(link);
	return status;
}

static void cleanup(void *ctx)
{
	rt_stall_hold__destroy(ctx);
}

struct scx_test rt_stall_hold = {
	.name = "rt_stall_hold",
	.description = "Verify RT tasks can't stall SCHED_EXT tasks after an empty server pick",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&rt_stall_hold)
