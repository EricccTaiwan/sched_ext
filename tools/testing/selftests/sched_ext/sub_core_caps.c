// SPDX-License-Identifier: GPL-2.0
/*
 * Verify that core-scheduling task selection (sched_core_find()) honors
 * sub-scheduler SCX_CAP_BASE grants instead of running a cookie-matching
 * sub-scheduler task on a CPU where its scheduler lacks SCX_CAP_BASE.
 *
 * Copyright (c) 2026 Google LLC.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <scx/common.h>

#include "cgroup_util.h"
#include "scx_test.h"
#include "sub_core_caps_root.bpf.skel.h"
#include "sub_core_caps_sub.bpf.skel.h"

#ifndef PR_SCHED_CORE
#define PR_SCHED_CORE			62
#define PR_SCHED_CORE_GET		0
#define PR_SCHED_CORE_CREATE		1
#define PR_SCHED_CORE_SHARE_FROM	2
#define PR_SCHED_CORE_SCOPE_THREAD	0
#endif

#ifndef SCHED_EXT
#define SCHED_EXT			7
#endif

#define WAIT_TIMEOUT_MS			1000

struct sub_core_caps_ctx {
	struct sub_core_caps_root *root_skel;
	struct sub_core_caps_sub *sub_skel;
	cpu_set_t orig_mask;
	char sub_cg[PATH_MAX];
	u64 sub_cgid;
	bool cg_created;
	int sib0;
	int sib1;
	int ctrl_cpu;
};

struct shared_state {
	int stop_all;
	pid_t root_cookied_tid;
};

struct worker_arg {
	struct shared_state *sh;
	int cpu;
	bool create_cookie;
};

static pid_t gettid_sys(void)
{
	return syscall(SYS_gettid);
}

static u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int pin_current(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static int switch_pid_to_ext(pid_t pid)
{
	struct sched_param sp = { .sched_priority = 0 };

	return sched_setscheduler(pid, SCHED_EXT, &sp);
}

static u64 get_cgroup_id(const char *path)
{
	union {
		u64 id;
		unsigned char bytes[8];
	} id = {};
	struct file_handle *handle;
	int mount_id, ret;

	handle = calloc(1, sizeof(*handle) + sizeof(id));
	if (!handle)
		return 0;
	handle->handle_bytes = sizeof(id);
	ret = name_to_handle_at(AT_FDCWD, path, handle, &mount_id, 0);
	if (!ret && handle->handle_bytes == sizeof(id))
		memcpy(id.bytes, handle->f_handle, sizeof(id));
	free(handle);

	return ret ? 0 : id.id;
}

static int find_smt_pair(const cpu_set_t *allowed, int *sib0, int *sib1,
			 int *ctrl_cpu)
{
	int cpu;

	*sib0 = -1;
	*sib1 = -1;
	*ctrl_cpu = -1;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		char path[128], buf[256];
		FILE *f;
		char *tok, *saveptr = NULL;
		int pair[2] = { -1, -1 };
		int found = 0;

		if (!CPU_ISSET(cpu, allowed))
			continue;

		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
			 cpu);
		f = fopen(path, "r");
		if (!f)
			continue;
		if (!fgets(buf, sizeof(buf), f)) {
			fclose(f);
			continue;
		}
		fclose(f);

		for (tok = strtok_r(buf, ",\n", &saveptr); tok && found < 2;
		     tok = strtok_r(NULL, ",\n", &saveptr)) {
			int a, b, c;

			if (sscanf(tok, "%d-%d", &a, &b) == 2) {
				for (c = a; c <= b && found < 2; c++) {
					if (CPU_ISSET(c, allowed))
						pair[found++] = c;
				}
			} else if (sscanf(tok, "%d", &a) == 1) {
				if (CPU_ISSET(a, allowed))
					pair[found++] = a;
			}
		}

		if (found == 2) {
			int c;

			*sib0 = pair[0];
			*sib1 = pair[1];
			for (c = 0; c < CPU_SETSIZE; c++) {
				if (CPU_ISSET(c, allowed) &&
				    c != pair[0] && c != pair[1]) {
					*ctrl_cpu = c;
					return 0;
				}
			}
			return -ENOENT;
		}
	}

	return -ENOENT;
}

static bool wait_pid_sleeping(pid_t pid, u64 timeout_ms)
{
	char path[64], buf[256];
	u64 deadline = now_ns() + timeout_ms * 1000000ULL;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	while (now_ns() < deadline) {
		int fd = open(path, O_RDONLY);

		if (fd >= 0) {
			ssize_t n = read(fd, buf, sizeof(buf) - 1);

			close(fd);
			if (n > 0) {
				char *rp;

				buf[n] = '\0';
				rp = strrchr(buf, ')');
				if (rp && rp[1] == ' ' && rp[2] == 'S')
					return true;
			}
		}
		usleep(500);
	}
	return false;
}

static void *root_worker_fn(void *arg)
{
	struct worker_arg *wa = arg;

	if (pin_current(wa->cpu))
		return (void *)(uintptr_t)errno;

	if (wa->create_cookie &&
	    prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0,
		  PR_SCHED_CORE_SCOPE_THREAD, 0))
		return (void *)(uintptr_t)errno;

	if (switch_pid_to_ext(0))
		return (void *)(uintptr_t)errno;

	if (wa->create_cookie)
		__atomic_store_n(&wa->sh->root_cookied_tid, gettid_sys(),
				 __ATOMIC_RELEASE);

	while (!__atomic_load_n(&wa->sh->stop_all, __ATOMIC_ACQUIRE))
		__asm__ volatile("" ::: "memory");

	return NULL;
}

static bool wait_u64_nonzero(u64 *ptr, u64 timeout_ms)
{
	u64 deadline = now_ns() + timeout_ms * 1000000ULL;

	while (now_ns() < deadline) {
		if (__atomic_load_n(ptr, __ATOMIC_ACQUIRE))
			return true;
		usleep(1000);
	}
	return __atomic_load_n(ptr, __ATOMIC_ACQUIRE) != 0;
}

static bool wait_u32_nonzero(u32 *ptr, u64 timeout_ms)
{
	u64 deadline = now_ns() + timeout_ms * 1000000ULL;

	while (now_ns() < deadline) {
		if (__atomic_load_n(ptr, __ATOMIC_ACQUIRE))
			return true;
		usleep(1000);
	}
	return __atomic_load_n(ptr, __ATOMIC_ACQUIRE) != 0;
}

static void close_pipe(int p[2])
{
	if (p[0] >= 0) {
		close(p[0]);
		p[0] = -1;
	}
	if (p[1] >= 0) {
		close(p[1]);
		p[1] = -1;
	}
}

static enum scx_test_status setup(void **ctx_ptr)
{
	struct sub_core_caps_ctx *ctx;
	char root[PATH_MAX];
	u64 cookie = 0;

	if (!__COMPAT_struct_has_field("sched_ext_ops", "sub_cgroup_id")) {
		printf("SKIP: sub-schedulers not supported\n");
		return SCX_TEST_SKIP;
	}

	if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, 0,
		  PR_SCHED_CORE_SCOPE_THREAD, (unsigned long)&cookie)) {
		printf("SKIP: core scheduling not supported (%d)\n", errno);
		return SCX_TEST_SKIP;
	}

	if (cg_find_unified_root(root, sizeof(root), NULL)) {
		printf("SKIP: cgroup v2 root not found\n");
		return SCX_TEST_SKIP;
	}

	ctx = calloc(1, sizeof(*ctx));
	SCX_FAIL_IF(!ctx, "Failed to allocate context");

	if (sched_getaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask)) {
		free(ctx);
		SCX_FAIL("Failed to get affinity (%d)", errno);
	}

	if (find_smt_pair(&ctx->orig_mask, &ctx->sib0, &ctx->sib1, &ctx->ctrl_cpu)) {
		printf("SKIP: SMT sibling pair plus third CPU required\n");
		free(ctx);
		return SCX_TEST_SKIP;
	}

	if (pin_current(ctx->ctrl_cpu)) {
		int ctrl_cpu = ctx->ctrl_cpu;

		free(ctx);
		SCX_FAIL("Failed to pin controller to CPU %d (%d)",
			 ctrl_cpu, errno);
	}

	if (snprintf(ctx->sub_cg, sizeof(ctx->sub_cg), "%s/scx_sub_core_caps_%d",
		     root, getpid()) >= (int)sizeof(ctx->sub_cg)) {
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Sub cgroup path too long");
	}
	if (cg_create(ctx->sub_cg)) {
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Failed to create sub cgroup (%d)", errno);
	}
	ctx->cg_created = true;

	ctx->sub_cgid = get_cgroup_id(ctx->sub_cg);
	if (!ctx->sub_cgid) {
		cg_destroy(ctx->sub_cg);
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Failed to read sub cgroup ID");
	}

	ctx->root_skel = sub_core_caps_root__open();
	if (!ctx->root_skel) {
		cg_destroy(ctx->sub_cg);
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Failed to open root skel");
	}
	SCX_ENUM_INIT(ctx->root_skel);
	if (sub_core_caps_root__load(ctx->root_skel)) {
		sub_core_caps_root__destroy(ctx->root_skel);
		cg_destroy(ctx->sub_cg);
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Failed to load root skel");
	}

	ctx->sub_skel = sub_core_caps_sub__open();
	if (!ctx->sub_skel) {
		sub_core_caps_root__destroy(ctx->root_skel);
		cg_destroy(ctx->sub_cg);
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Failed to open sub skel");
	}
	SCX_ENUM_INIT(ctx->sub_skel);
	ctx->sub_skel->struct_ops.sub_core_caps_sub_ops->sub_cgroup_id = ctx->sub_cgid;
	if (sub_core_caps_sub__load(ctx->sub_skel)) {
		sub_core_caps_sub__destroy(ctx->sub_skel);
		sub_core_caps_root__destroy(ctx->root_skel);
		cg_destroy(ctx->sub_cg);
		sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
		free(ctx);
		SCX_FAIL("Failed to load sub skel");
	}

	*ctx_ptr = ctx;
	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx_ptr)
{
	struct sub_core_caps_ctx *ctx = ctx_ptr;
	struct sub_core_caps_root *root_skel = ctx->root_skel;
	struct sub_core_caps_sub *sub_skel = ctx->sub_skel;
	struct bpf_link *root_link = NULL, *sub_link = NULL;
	struct shared_state *sh;
	struct worker_arg root_arg, untagged_arg;
	pthread_t t_root, t_untagged;
	bool root_started = false, untagged_started = false;
	int step_pipe[2] = { -1, -1 };
	int ready_pipe[2] = { -1, -1 };
	int wake_pipe[2] = { -1, -1 };
	pid_t sub_pid = -1;
	enum scx_test_status status = SCX_TEST_FAIL;
	char c = 1;

	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED) {
		SCX_ERR("Failed to mmap shared state (%d)", errno);
		return SCX_TEST_FAIL;
	}

	if (pipe(step_pipe) || pipe(ready_pipe) || pipe(wake_pipe)) {
		SCX_ERR("Failed to create pipes (%d)", errno);
		goto out;
	}

	/* Fork before spawning pthreads so child setup is async-signal-safe. */
	sub_pid = fork();
	if (sub_pid < 0) {
		SCX_ERR("Failed to fork sub worker (%d)", errno);
		goto out;
	}
	if (sub_pid == 0) {
		close(step_pipe[1]);
		close(ready_pipe[0]);
		close(wake_pipe[1]);
		if (read(step_pipe[0], &c, 1) != 1)
			_exit(1);
		if (pin_current(ctx->sib1))
			_exit(2);
		if (prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_FROM,
			  sh->root_cookied_tid, PR_SCHED_CORE_SCOPE_THREAD, 0))
			_exit(3);
		if (write(ready_pipe[1], &c, 1) != 1)
			_exit(4);
		if (read(wake_pipe[0], &c, 1) != 1)
			_exit(5);
		while (!__atomic_load_n(&sh->stop_all, __ATOMIC_ACQUIRE))
			__asm__ volatile("" ::: "memory");
		_exit(0);
	}
	close(step_pipe[0]);
	step_pipe[0] = -1;
	close(ready_pipe[1]);
	ready_pipe[1] = -1;
	close(wake_pipe[0]);
	wake_pipe[0] = -1;

	root_skel->bss->sub_cgid = ctx->sub_cgid;
	root_skel->bss->grant_cpu = ctx->sib1;
	root_skel->bss->want_grant = 0;
	root_skel->bss->grant_done = 0;
	root_skel->bss->grant_err = 0;
	memset(&root_skel->data->uei, 0, sizeof(root_skel->data->uei));

	sub_skel->bss->target_cpu = ctx->sib1;
	sub_skel->bss->deny_phase = 1;
	sub_skel->bss->sub_enq_cnt = 0;
	sub_skel->bss->sub_deq_cse_denied = 0;
	sub_skel->bss->sub_run_denied = 0;
	sub_skel->bss->sub_run_granted = 0;
	memset(&sub_skel->data->uei, 0, sizeof(sub_skel->data->uei));

	root_link = bpf_map__attach_struct_ops(root_skel->maps.sub_core_caps_root_ops);
	if (!root_link) {
		SCX_ERR("Failed to attach root scheduler");
		goto out;
	}

	sub_link = bpf_map__attach_struct_ops(sub_skel->maps.sub_core_caps_sub_ops);
	if (!sub_link) {
		if (errno == EOPNOTSUPP) {
			printf("SKIP: CONFIG_EXT_SUB_SCHED not enabled\n");
			status = SCX_TEST_SKIP;
		} else {
			SCX_ERR("Failed to attach sub scheduler (%d)", errno);
		}
		goto out;
	}

	root_arg.sh = sh;
	root_arg.cpu = ctx->sib0;
	root_arg.create_cookie = true;
	if (pthread_create(&t_root, NULL, root_worker_fn, &root_arg)) {
		SCX_ERR("Failed to start root cookied worker");
		goto out;
	}
	root_started = true;

	untagged_arg.sh = sh;
	untagged_arg.cpu = ctx->sib1;
	untagged_arg.create_cookie = false;
	if (pthread_create(&t_untagged, NULL, root_worker_fn, &untagged_arg)) {
		SCX_ERR("Failed to start root untagged worker");
		goto out;
	}
	untagged_started = true;

	if (!wait_u32_nonzero((u32 *)&sh->root_cookied_tid, WAIT_TIMEOUT_MS)) {
		SCX_ERR("Root cookied worker did not initialize");
		goto out;
	}

	/* Let sub_pid share root_worker's cookie, pin to sib1, and sleep. */
	if (write(step_pipe[1], &c, 1) != 1 || read(ready_pipe[0], &c, 1) != 1) {
		SCX_ERR("Sub worker handshake failed");
		goto out;
	}
	if (!wait_pid_sleeping(sub_pid, WAIT_TIMEOUT_MS)) {
		SCX_ERR("Sub worker did not enter sleep");
		goto out;
	}

	/*
	 * Move sub_pid into the sub-scheduler cgroup and switch it to
	 * SCHED_EXT while asleep so it never executes on sib1 prior to being
	 * queued in SUB_DSQ.
	 */
	if (cg_enter(ctx->sub_cg, sub_pid)) {
		SCX_ERR("Failed to move sub worker into sub cgroup");
		goto out;
	}
	if (switch_pid_to_ext(sub_pid)) {
		SCX_ERR("Failed to switch sub worker to SCHED_EXT (%d)", errno);
		goto out;
	}
	if (write(wake_pipe[1], &c, 1) != 1) {
		SCX_ERR("Failed to wake sub worker");
		goto out;
	}

	if (!wait_u64_nonzero(&sub_skel->bss->sub_enq_cnt, WAIT_TIMEOUT_MS)) {
		SCX_ERR("Sub worker was never enqueued");
		goto out;
	}

	/*
	 * Phase 1: sub-scheduler has no SCX_CAP_BASE on sib1. Even though
	 * sub_pid shares a core-scheduling cookie with root_worker on sib0,
	 * sched_core_find() must not pick or run it on sib1.
	 */
	usleep(150000);

	if (sub_skel->bss->sub_run_denied || sub_skel->bss->sub_deq_cse_denied) {
		SCX_ERR("Sub task ran on denied CPU %d via core-sched (run=%llu deq_cse=%llu)",
			ctx->sib1,
			(unsigned long long)sub_skel->bss->sub_run_denied,
			(unsigned long long)sub_skel->bss->sub_deq_cse_denied);
		goto out;
	}

	/*
	 * Phase 2: grant SCX_CAP_BASE on sib1 and verify the sub-scheduler
	 * task is now eligible and runs on sib1.
	 */
	__atomic_store_n(&sub_skel->bss->deny_phase, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&root_skel->bss->want_grant, 1, __ATOMIC_RELEASE);
	if (!wait_u32_nonzero(&root_skel->bss->grant_done, WAIT_TIMEOUT_MS)) {
		SCX_ERR("Root scheduler failed to grant SCX_CAP_BASE on CPU %d (err=%d)",
			ctx->sib1, root_skel->bss->grant_err);
		goto out;
	}
	if (!wait_u64_nonzero(&sub_skel->bss->sub_run_granted, WAIT_TIMEOUT_MS)) {
		SCX_ERR("Sub task did not run on CPU %d after SCX_CAP_BASE grant",
			ctx->sib1);
		goto out;
	}

	if (UEI_EXITED(root_skel, uei)) {
		SCX_ERR("Root scheduler exited unexpectedly (kind=%llu code=%lld msg='%s')",
			(unsigned long long)root_skel->data->uei.kind,
			(long long)root_skel->data->uei.exit_code,
			root_skel->data->uei.msg);
		goto out;
	}

	if (UEI_EXITED(sub_skel, uei)) {
		SCX_ERR("Sub scheduler exited unexpectedly (kind=%llu code=%lld msg='%s')",
			(unsigned long long)sub_skel->data->uei.kind,
			(long long)sub_skel->data->uei.exit_code,
			sub_skel->data->uei.msg);
		goto out;
	}

	status = SCX_TEST_PASS;
out:
	__atomic_store_n(&sh->stop_all, 1, __ATOMIC_RELEASE);
	close_pipe(step_pipe);
	close_pipe(ready_pipe);
	close_pipe(wake_pipe);
	if (sub_link)
		bpf_link__destroy(sub_link);
	if (root_link)
		bpf_link__destroy(root_link);
	if (sub_pid > 0)
		waitpid(sub_pid, NULL, 0);
	if (untagged_started)
		pthread_join(t_untagged, NULL);
	if (root_started)
		pthread_join(t_root, NULL);
	munmap(sh, sizeof(*sh));
	return status;
}

static void cleanup(void *ctx_ptr)
{
	struct sub_core_caps_ctx *ctx = ctx_ptr;

	if (ctx->sub_skel)
		sub_core_caps_sub__destroy(ctx->sub_skel);
	if (ctx->root_skel)
		sub_core_caps_root__destroy(ctx->root_skel);
	if (ctx->cg_created)
		cg_destroy(ctx->sub_cg);
	sched_setaffinity(0, sizeof(ctx->orig_mask), &ctx->orig_mask);
	free(ctx);
}

static struct scx_test sub_core_caps = {
	.name = "sub_core_caps",
	.description = "Verify core scheduling enforces sub-scheduler SCX_CAP_BASE",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};

REGISTER_SCX_TEST(&sub_core_caps)
