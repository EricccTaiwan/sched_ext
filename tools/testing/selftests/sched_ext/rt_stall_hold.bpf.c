// SPDX-License-Identifier: GPL-2.0
/*
 * A scheduler that holds the target task on a DSQ that its CPU doesn't consume
 * on its first wakeup after @arm is set, and moves it to the CPU's local DSQ
 * from a BPF timer after @hold_ns.
 * While the target is held, an ext_server pick on its CPU comes back empty.
 * Once the target is on the local DSQ, it should still get the ext_server's
 * share of a CPU that an RT task is hogging.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define HOLD_DSQ 0

UEI_DEFINE(uei);

s32 target_pid;		/* set by userspace */
bool arm;		/* set by userspace, cleared when holding */
u64 hold_ns;		/* set by userspace */
u64 nr_held;
u64 nr_moved;

static s32 target_cpu;

struct move_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct move_timer);
} move_timer SEC(".maps");

static int move_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	struct task_struct *p;

	bpf_for_each(scx_dsq, p, HOLD_DSQ, 0) {
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
				     SCX_DSQ_LOCAL_ON | target_cpu, 0))
			__sync_fetch_and_add(&nr_moved, 1);
	}
	return 0;
}

void BPF_STRUCT_OPS(rt_stall_hold_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct move_timer *mt;
	u32 key = 0;

	if (p->pid != target_pid || !arm || !(enq_flags & SCX_ENQ_WAKEUP)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	arm = false;
	target_cpu = scx_bpf_task_cpu(p);
	scx_bpf_dsq_insert(p, HOLD_DSQ, SCX_SLICE_DFL, enq_flags);
	__sync_fetch_and_add(&nr_held, 1);

	mt = bpf_map_lookup_elem(&move_timer, &key);
	if (!mt) {
		scx_bpf_error("failed to look up the move timer");
		return;
	}
	bpf_timer_start(&mt->timer, hold_ns, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rt_stall_hold_init)
{
	struct move_timer *mt;
	u32 key = 0;
	s32 ret;

	ret = scx_bpf_create_dsq(HOLD_DSQ, -1);
	if (ret)
		return ret;

	mt = bpf_map_lookup_elem(&move_timer, &key);
	if (!mt)
		return -ESRCH;

	bpf_timer_init(&mt->timer, &move_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&mt->timer, move_timerfn);
	return 0;
}

void BPF_STRUCT_OPS(rt_stall_hold_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops rt_stall_hold_ops = {
	.enqueue		= (void *)rt_stall_hold_enqueue,
	.init			= (void *)rt_stall_hold_init,
	.exit			= (void *)rt_stall_hold_exit,
	.flags			= SCX_OPS_SWITCH_PARTIAL,
	.name			= "rt_stall_hold",
};
