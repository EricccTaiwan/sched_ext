// SPDX-License-Identifier: GPL-2.0
/*
 * Child cid-form sub-scheduler for the sub_core_caps selftest.
 *
 * Copyright (c) 2026 Google LLC.
 */
#include <scx/common.bpf.h>

#define SUB_DSQ		0x200

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 4);
} arena SEC(".maps");

u64 __arena_global arena_touch;

s32 target_cpu;
u32 deny_phase;
u64 sub_enq_cnt;
u64 sub_deq_cse_denied;
u64 sub_run_denied;
u64 sub_run_granted;

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(sub_select_cid, struct task_struct *p, s32 prev_cid,
		   u64 wake_flags)
{
	return prev_cid;
}

void BPF_STRUCT_OPS(sub_enqueue, struct task_struct *p, u64 enq_flags)
{
	__sync_fetch_and_add(&sub_enq_cnt, 1);
	scx_bpf_dsq_insert(p, SUB_DSQ, 1000000ULL, enq_flags);
}

void BPF_STRUCT_OPS(sub_dequeue, struct task_struct *p, u64 deq_flags)
{
	if ((deq_flags & SCX_DEQ_CORE_SCHED_EXEC) && deny_phase)
		__sync_fetch_and_add(&sub_deq_cse_denied, 1);
}

void BPF_STRUCT_OPS(sub_dispatch, s32 cid, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SUB_DSQ, 0);
}

void BPF_STRUCT_OPS(sub_running, struct task_struct *p)
{
	if (bpf_get_smp_processor_id() != target_cpu)
		return;

	if (deny_phase)
		__sync_fetch_and_add(&sub_run_denied, 1);
	else
		__sync_fetch_and_add(&sub_run_granted, 1);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(sub_init)
{
	arena_touch++;
	return scx_bpf_create_dsq(SUB_DSQ, -1);
}

void BPF_STRUCT_OPS(sub_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_CID_DEFINE(sub_core_caps_sub_ops,
		   .select_cid		= (void *)sub_select_cid,
		   .enqueue		= (void *)sub_enqueue,
		   .dequeue		= (void *)sub_dequeue,
		   .dispatch		= (void *)sub_dispatch,
		   .running		= (void *)sub_running,
		   .init		= (void *)sub_init,
		   .exit		= (void *)sub_exit,
		   .flags		= SCX_OPS_SWITCH_PARTIAL,
		   .name		= "sub_core_caps_sub");
