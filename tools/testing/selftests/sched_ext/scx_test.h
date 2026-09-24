/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 */

#ifndef __SCX_TEST_H__
#define __SCX_TEST_H__

#include <errno.h>
#include <stdlib.h>
#include <scx/common.h>
#include <scx/compat.h>

enum scx_test_status {
	SCX_TEST_PASS = 0,
	SCX_TEST_SKIP,
	SCX_TEST_FAIL,
};

#define EXIT_KIND(__ent) __COMPAT_ENUM_OR_ZERO("scx_exit_kind", #__ent)

struct scx_test {
	/**
	 * name - The name of the testcase.
	 */
	const char *name;

	/**
	 * description - A description of your testcase: what it tests and is
	 * meant to validate.
	 */
	const char *description;

	/*
	 * setup - Setup the test.
	 * @ctx: A pointer to a context object that will be passed to run and
	 *	 cleanup.
	 *
	 * An optional callback that allows a testcase to perform setup for its
	 * run. A test may return SCX_TEST_SKIP to skip the run.
	 */
	enum scx_test_status (*setup)(void **ctx);

	/*
	 * run - Run the test.
	 * @ctx: Context set in the setup() callback. If @ctx was not set in
	 *	 setup(), it is NULL.
	 *
	 * The main test. Callers should return one of:
	 *
	 * - SCX_TEST_PASS: Test passed
	 * - SCX_TEST_SKIP: Test should be skipped
	 * - SCX_TEST_FAIL: Test failed
	 *
	 * This callback must be defined.
	 */
	enum scx_test_status (*run)(void *ctx);

	/*
	 * cleanup - Perform cleanup following the test
	 * @ctx: Context set in the setup() callback. If @ctx was not set in
	 *	 setup(), it is NULL.
	 *
	 * An optional callback that allows a test to perform cleanup after
	 * being run. This callback is run even if the run() callback returns
	 * SCX_TEST_SKIP or SCX_TEST_FAIL. It is not run if setup() returns
	 * SCX_TEST_SKIP or SCX_TEST_FAIL.
	 */
	void (*cleanup)(void *ctx);
};

void scx_test_register(struct scx_test *test);

#define REGISTER_SCX_TEST(__test)			\
	__attribute__((constructor))			\
	static void ___scxregister##__LINE__(void)	\
	{						\
		scx_test_register(__test);		\
	}

#define SCX_ERR(__fmt, ...)						\
	do {								\
		fprintf(stderr, "ERR: %s:%d\n", __FILE__, __LINE__);	\
		fprintf(stderr, __fmt"\n", ##__VA_ARGS__);			\
	} while (0)

#define SCX_FAIL(__fmt, ...)						\
	do {								\
		SCX_ERR(__fmt, ##__VA_ARGS__);				\
		return SCX_TEST_FAIL;					\
	} while (0)

#define SCX_FAIL_IF(__cond, __fmt, ...)					\
	do {								\
		if (__cond)						\
			SCX_FAIL(__fmt, ##__VA_ARGS__);			\
	} while (0)

#define SCX_GT(_x, _y) SCX_FAIL_IF((_x) <= (_y), "Expected %s > %s (%lu > %lu)",	\
				   #_x, #_y, (u64)(_x), (u64)(_y))
#define SCX_GE(_x, _y) SCX_FAIL_IF((_x) < (_y), "Expected %s >= %s (%lu >= %lu)",	\
				   #_x, #_y, (u64)(_x), (u64)(_y))
#define SCX_LT(_x, _y) SCX_FAIL_IF((_x) >= (_y), "Expected %s < %s (%lu < %lu)",	\
				   #_x, #_y, (u64)(_x), (u64)(_y))
#define SCX_LE(_x, _y) SCX_FAIL_IF((_x) > (_y), "Expected %s <= %s (%lu <= %lu)",	\
				   #_x, #_y, (u64)(_x), (u64)(_y))
#define SCX_EQ(_x, _y) SCX_FAIL_IF((_x) != (_y), "Expected %s == %s (%lu == %lu)",	\
				   #_x, #_y, (u64)(_x), (u64)(_y))
#define SCX_ASSERT(_x) SCX_FAIL_IF(!(_x), "Expected %s to be true (%lu)",		\
				   #_x, (u64)(_x))

#define SCX_ECODE_VAL(__ecode) ({						\
        u64 __val = 0;								\
	bool __found = false;							\
										\
	__found = __COMPAT_read_enum("scx_exit_code", #__ecode, &__val);	\
	SCX_ASSERT(__found);							\
	(s64)__val;								\
})

#define SCX_KIND_VAL(__kind) ({							\
        u64 __val = 0;								\
	bool __found = false;							\
										\
	__found = __COMPAT_read_enum("scx_exit_kind", #__kind, &__val);		\
	SCX_ASSERT(__found);							\
	__val;									\
})

/*
 * Test context owning a skeleton and its struct_ops link. cleanup() destroys
 * both however run() returns, so a failing SCX_*() check cannot leave the
 * scheduler loaded for the tests that follow:
 *
 *	SCX_TEST_DEFINE_CTX(foo);
 *
 *	static enum scx_test_status run(void *ctx)
 *	{
 *		struct foo_ctx *tctx = ctx;
 *
 *		SCX_TEST_ATTACH(tctx, foo_ops);
 *		SCX_EQ(tctx->skel->bss->nr_enqueues, 1);
 *		return SCX_TEST_PASS;
 *	}
 *
 * Tests that configure the skeleton before loading build their own setup()
 * from SCX_TEST_OPEN() and SCX_TEST_LOAD(), with SCX_TEST_DEFINE_CTX_TYPE()
 * and SCX_TEST_DEFINE_CLEANUP() for the rest.
 */
#define SCX_TEST_DEFINE_CTX_TYPE(__name)				\
struct __name##_ctx {							\
	struct __name		*skel;					\
	struct bpf_link		*link;					\
}

/* Allocate @__tctx and open the skeleton into it, failing setup() on error */
#define SCX_TEST_OPEN(__tctx, __name)					\
	do {								\
		(__tctx) = calloc(1, sizeof(*(__tctx)));		\
		SCX_FAIL_IF(!(__tctx), "Failed to allocate test context"); \
		(__tctx)->skel = __name##__open();			\
		if (!(__tctx)->skel) {					\
			free(__tctx);					\
			SCX_FAIL("Failed to open");			\
		}							\
		SCX_ENUM_INIT((__tctx)->skel);				\
	} while (0)

/* Load the skeleton, freeing @__tctx on failure since cleanup() won't run */
#define SCX_TEST_LOAD(__tctx, __name)					\
	do {								\
		if (__name##__load((__tctx)->skel)) {			\
			__name##__destroy((__tctx)->skel);		\
			free(__tctx);					\
			SCX_FAIL("Failed to load skel");		\
		}							\
	} while (0)

#define SCX_TEST_DEFINE_SETUP(__name)					\
static enum scx_test_status setup(void **ctx)				\
{									\
	struct __name##_ctx *tctx;					\
									\
	SCX_TEST_OPEN(tctx, __name);					\
	SCX_TEST_LOAD(tctx, __name);					\
									\
	*ctx = tctx;							\
									\
	return SCX_TEST_PASS;						\
}

#define SCX_TEST_DEFINE_CLEANUP(__name)					\
static void cleanup(void *ctx)						\
{									\
	struct __name##_ctx *tctx = ctx;				\
									\
	if (!tctx)							\
		return;							\
	if (tctx->link)							\
		bpf_link__destroy(tctx->link);				\
	__name##__destroy(tctx->skel);					\
	free(tctx);							\
}

/* Context type, setup() and cleanup() for tests with no custom setup */
#define SCX_TEST_DEFINE_CTX(__name)					\
	SCX_TEST_DEFINE_CTX_TYPE(__name);				\
	SCX_TEST_DEFINE_SETUP(__name)					\
	SCX_TEST_DEFINE_CLEANUP(__name)

/* Attach @__map and keep the link in @__tctx for cleanup() to destroy */
#define SCX_TEST_ATTACH(__tctx, __map)					\
	do {								\
		(__tctx)->link = bpf_map__attach_struct_ops(		\
					(__tctx)->skel->maps.__map);	\
		SCX_FAIL_IF(!(__tctx)->link, "Failed to attach scheduler"); \
	} while (0)

#endif  // # __SCX_TEST_H__
