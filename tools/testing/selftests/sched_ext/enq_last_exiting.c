// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <scx/common.h>
#include "enq_last_exiting.bpf.skel.h"
#include "scx_test.h"

#define NR_EXITS	20
#define EXIT_BYTES	(256UL << 20)

/*
 * A CPU that goes idle with a task left on its local DSQ is rescheduled right
 * away, in well under a millisecond even under KASAN. A stranded task waits
 * for an unrelated wakeup instead, often for seconds. Allow 10ms for slow and
 * overcommitted machines.
 */
#define MAX_IDLE_QUEUED_NS	(10ULL * 1000 * 1000)

static enum scx_test_status setup(void **ctx)
{
	struct enq_last_exiting *skel;

	skel = enq_last_exiting__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(enq_last_exiting__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

/* Fault in a large buffer so that tearing it down outlasts the slice */
static void exit_child(int cpu)
{
	cpu_set_t mask;
	void *buf;

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask))
		_exit(1);

	/* Base pages take longer to tear down than THPs */
	prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
	buf = mmap(NULL, EXIT_BYTES, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (buf == MAP_FAILED)
		_exit(1);
	_exit(0);
}

static long read_skip_exiting(void)
{
	char line[128];
	long val = -1;
	FILE *f;

	f = fopen("/sys/kernel/sched_ext/root/events", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "SCX_EV_ENQ_SKIP_EXITING %ld", &val) == 1)
			break;
	fclose(f);

	return val;
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static enum scx_test_status run(void *ctx)
{
	struct enq_last_exiting *skel = ctx;
	enum scx_test_status status = SCX_TEST_FAIL;
	double start, ms, max_ms = 0;
	int i, cpu, wstatus;
	struct bpf_link *link;
	cpu_set_t mask;
	long skipped;
	pid_t pid;

	SCX_FAIL_IF(sched_getaffinity(0, sizeof(mask), &mask),
		    "Failed to get affinity");
	/* the highest allowed CPU, which the runner is least likely to be on */
	for (cpu = CPU_SETSIZE - 1; cpu >= 0; cpu--)
		if (CPU_ISSET(cpu, &mask))
			break;
	SCX_FAIL_IF(cpu < 0, "No allowed CPU");

	link = bpf_map__attach_struct_ops(skel->maps.enq_last_exiting_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	for (i = 0; i < NR_EXITS; i++) {
		start = now_ms();
		pid = fork();
		if (pid < 0) {
			SCX_ERR("Failed to fork");
			goto out;
		}
		if (!pid)
			exit_child(cpu);
		if (waitpid(pid, &wstatus, 0) != pid || !WIFEXITED(wstatus) ||
		    WEXITSTATUS(wstatus)) {
			SCX_ERR("Child %d failed", i);
			goto out;
		}
		ms = now_ms() - start;
		if (ms > max_ms)
			max_ms = ms;

		if (UEI_EXITED(skel, uei)) {
			SCX_ERR("Scheduler exited after %d exits (%.0fms): %s",
				i + 1, ms, skel->data->uei.msg);
			goto out;
		}
	}

	skipped = read_skip_exiting();
	fprintf(stderr, "exit %.0fms skip %ld idle-queued %llu/%.3fms\n",
		max_ms, skipped, (unsigned long long)skel->bss->nr_idle_queued,
		skel->bss->max_idle_queued_ns / 1e6);
	if (skipped <= 0) {
		fprintf(stderr, "SKIP: no exiting task bypassed ops.enqueue()\n");
		status = SCX_TEST_SKIP;
		goto out;
	}

	if (skel->bss->max_idle_queued_ns > MAX_IDLE_QUEUED_NS) {
		SCX_ERR("CPU %d idled for %.3fms with a task on its local DSQ",
			cpu, skel->bss->max_idle_queued_ns / 1e6);
		goto out;
	}

	status = SCX_TEST_PASS;
out:
	bpf_link__destroy(link);

	return status;
}

static void cleanup(void *ctx)
{
	struct enq_last_exiting *skel = ctx;

	enq_last_exiting__destroy(skel);
}

struct scx_test enq_last_exiting = {
	.name		= "enq_last_exiting",
	.description	= "Verify an exiting task stranded by SCX_ENQ_LAST runs",
	.setup		= setup,
	.run		= run,
	.cleanup	= cleanup,
};
REGISTER_SCX_TEST(&enq_last_exiting)
