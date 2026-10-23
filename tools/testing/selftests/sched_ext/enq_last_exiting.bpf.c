// SPDX-License-Identifier: GPL-2.0
/*
 * With SCX_OPS_ENQ_LAST but not SCX_OPS_ENQ_EXITING, an exiting task that is
 * the last runnable task on its CPU skips ops.enqueue() and is queued on the
 * CPU's local DSQ. The CPU must run it instead of idling with it queued.
 *
 * ops.enqueue() keeps a SCX_ENQ_LAST task on its CPU and kicks the CPU, so
 * only the exiting path that bypasses ops.enqueue() can strand a task.
 *
 * A CPU going idle with tasks on its local DSQ is timed until the next task
 * starts running there. An unrelated wakeup eventually ends a strand, so the
 * longest such idle period, not a watchdog stall, tells whether it happened.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/* Short enough to expire while a task tears down its address space */
#define SLICE_NS	(1000ULL * 1000)

UEI_DEFINE(uei);

u64 nr_idle_queued;
u64 max_idle_queued_ns;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} idle_since SEC(".maps");

void BPF_STRUCT_OPS(enq_last_exiting_enqueue, struct task_struct *p,
		    u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_LAST) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_NS, enq_flags);
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_IDLE);
		return;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SLICE_NS, enq_flags);
}

void BPF_STRUCT_OPS(enq_last_exiting_update_idle, s32 cpu, bool idle)
{
	u32 zero = 0;
	u64 *since;

	if (!idle)
		return;

	since = bpf_map_lookup_elem(&idle_since, &zero);
	if (since && scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) > 0) {
		*since = bpf_ktime_get_ns();
		__sync_fetch_and_add(&nr_idle_queued, 1);
	}
}

void BPF_STRUCT_OPS(enq_last_exiting_running, struct task_struct *p)
{
	u32 zero = 0;
	u64 *since, dur;

	since = bpf_map_lookup_elem(&idle_since, &zero);
	if (!since || !*since)
		return;

	dur = bpf_ktime_get_ns() - *since;
	*since = 0;
	if (dur > max_idle_queued_ns)
		max_idle_queued_ns = dur;
}

void BPF_STRUCT_OPS(enq_last_exiting_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops enq_last_exiting_ops = {
	.enqueue		= (void *)enq_last_exiting_enqueue,
	.update_idle		= (void *)enq_last_exiting_update_idle,
	.running		= (void *)enq_last_exiting_running,
	.exit			= (void *)enq_last_exiting_exit,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
	.timeout_ms		= 5000U,
	.name			= "enq_last_exiting",
};
