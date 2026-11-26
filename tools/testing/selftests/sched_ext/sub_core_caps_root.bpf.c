// SPDX-License-Identifier: GPL-2.0
/*
 * Root cid-form scheduler for the sub_core_caps selftest.
 *
 * Copyright (c) 2026 Google LLC.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1 << 4);
} arena SEC(".maps");

u64 __arena_global grant_cmask[4];

u64 sub_cgid;
s32 grant_cpu;
u32 want_grant;
u32 grant_done;
s32 grant_err;

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS(root_select_cid, struct task_struct *p, s32 prev_cid,
		   u64 wake_flags)
{
	return prev_cid;
}

void BPF_STRUCT_OPS(root_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, 1000000ULL, enq_flags);
}

void BPF_STRUCT_OPS(root_tick, struct task_struct *p)
{
	struct scx_cmask __arena *m = (struct scx_cmask __arena *)grant_cmask;
	s32 cid;
	s32 ret;

	if (!want_grant || grant_done)
		return;

	cid = scx_bpf_cpu_to_cid(grant_cpu);
	if (cid < 0)
		return;

	cmask_init(m, cid, 1);
	cmask_set(cid, m);
	ret = scx_bpf_sub_grant(sub_cgid, SCX_CAP_ENQ_IMMED | SCX_CAP_ENQ,
				m, NULL);
	grant_err = ret;
	if (!ret)
		grant_done = 1;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(root_sub_attach, struct scx_sub_attach_args *args)
{
	grant_cmask[0] = 0;
	return 0;
}

void BPF_STRUCT_OPS(root_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_CID_DEFINE(sub_core_caps_root_ops,
		   .select_cid		= (void *)root_select_cid,
		   .enqueue		= (void *)root_enqueue,
		   .tick		= (void *)root_tick,
		   .sub_attach		= (void *)root_sub_attach,
		   .exit		= (void *)root_exit,
		   .flags		= SCX_OPS_SWITCH_PARTIAL,
		   .name		= "sub_core_caps_root");
