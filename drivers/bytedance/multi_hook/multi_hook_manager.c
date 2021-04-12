/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Bytedance, Inc. All rights reserved.
 *
 * Authors: Qianyu Zhang <zhangqianyu.sys@bytedance.com>
 *
 * this file provides several preallocated hook_ctxs and a proc file to display hook states.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/multi_hook/multi_hook.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

#define MULTI_HOOK_VERSION "1.1.0"

#define MAX_HOOKS 32

static struct hook_ctx_t ctxs[MAX_HOOKS];

#define define_hook_func(idx) \
static long hook_func##idx(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) \
{ \
	return hook_generic_func(&ctxs[(idx)], arg0, arg1, arg2, arg3, arg4, arg5);  \
}

define_hook_func(0)
define_hook_func(1)
define_hook_func(2)
define_hook_func(3)
define_hook_func(4)
define_hook_func(5)
define_hook_func(6)
define_hook_func(7)
define_hook_func(8)
define_hook_func(9)
define_hook_func(10)
define_hook_func(11)
define_hook_func(12)
define_hook_func(13)
define_hook_func(14)
define_hook_func(15)
define_hook_func(16)
define_hook_func(17)
define_hook_func(18)
define_hook_func(19)
define_hook_func(20)
define_hook_func(21)
define_hook_func(22)
define_hook_func(23)
define_hook_func(24)
define_hook_func(25)
define_hook_func(26)
define_hook_func(27)
define_hook_func(28)
define_hook_func(29)
define_hook_func(30)
define_hook_func(31)


static unsigned long hook_funcs[MAX_HOOKS] = {
	(unsigned long)hook_func0,
	(unsigned long)hook_func1,
	(unsigned long)hook_func2,
	(unsigned long)hook_func3,
	(unsigned long)hook_func4,
	(unsigned long)hook_func5,
	(unsigned long)hook_func6,
	(unsigned long)hook_func7,
	(unsigned long)hook_func8,
	(unsigned long)hook_func9,
	(unsigned long)hook_func10,
	(unsigned long)hook_func11,
	(unsigned long)hook_func12,
	(unsigned long)hook_func13,
	(unsigned long)hook_func14,
	(unsigned long)hook_func15,
	(unsigned long)hook_func16,
	(unsigned long)hook_func17,
	(unsigned long)hook_func18,
	(unsigned long)hook_func19,
	(unsigned long)hook_func20,
	(unsigned long)hook_func21,
	(unsigned long)hook_func22,
	(unsigned long)hook_func23,
	(unsigned long)hook_func24,
	(unsigned long)hook_func25,
	(unsigned long)hook_func26,
	(unsigned long)hook_func27,
	(unsigned long)hook_func28,
	(unsigned long)hook_func29,
	(unsigned long)hook_func30,
	(unsigned long)hook_func31,
};

#define HOOK_CTX_WRAPPER_DESC_LEN 32

struct hook_ctx_wrapper_t {
	struct hook_ctx_t *ctx;
	unsigned long hook_func;
	unsigned long user_func;
	int user_ref_cnt;
	int blank;
	char desc[HOOK_CTX_WRAPPER_DESC_LEN];
};

static struct hook_ctx_wrapper_t wrappers[MAX_HOOKS];
static DEFINE_MUTEX(wrappers_mutex);

static int hook_ctx_wrapper_init(struct hook_ctx_wrapper_t *wrapper,
				 unsigned long user_func, const char *desc)
{
	int ret;

	wrapper->user_func = user_func;
	if ((ret = hook_ctx_init(wrapper->ctx, wrapper->user_func,
			   wrapper->hook_func)) < 0)
		return ret;

	wrapper->user_ref_cnt = 1;
	strncpy(wrapper->desc, desc, HOOK_CTX_WRAPPER_DESC_LEN - 1);
	pr_info("hook_ctx_wrapper init ctx with desc %s\n", desc);

	return 0;
}

static void hook_ctx_wrapper_exit(struct hook_ctx_wrapper_t *wrapper)
{
	hook_ctx_exit(wrapper->ctx);
	wrapper->user_func = 0;
	memset(wrapper->desc, 0, HOOK_CTX_WRAPPER_DESC_LEN);
}

/*
 * must used in thread context, not atomic context, not spinlock
 * find, alloc, init
 */
struct hook_ctx_t *multi_hook_manager_get(unsigned long addr, const char *desc)
{
	int i;
	struct hook_ctx_t *ctx = NULL;
	struct hook_ctx_wrapper_t *wrapper = NULL;

	mutex_lock(&wrappers_mutex);

	for (i = 0; i < MAX_HOOKS; i++) {
		if (wrappers[i].user_func == addr && wrappers[i].user_ref_cnt > 0) {
			wrappers[i].user_ref_cnt++;
			pr_debug("multi_hook_manager: found existed ctx, new_user_ref_cnt: %d\n",
				wrappers[i].user_ref_cnt);
			ctx = wrappers[i].ctx;
			goto out_unlock;
		}
	}

	for (i = 0; i < MAX_HOOKS; i++) {
		if (!wrappers[i].user_ref_cnt) {
			wrapper = &wrappers[i];
			break;
		}
	}

	if (!wrapper)
		goto out_unlock;

	if (hook_ctx_wrapper_init(wrapper, addr, desc) < 0)
		goto out_unlock;
	ctx = wrapper->ctx;

out_unlock:
	mutex_unlock(&wrappers_mutex);

	return ctx;
}

EXPORT_SYMBOL(multi_hook_manager_get);

int multi_hook_manager_put(unsigned long addr)
{
	int i;
	int ret = -EINVAL;

	mutex_lock(&wrappers_mutex);

	for (i = 0; i < MAX_HOOKS; i++) {
		struct hook_ctx_wrapper_t *wrapper = &wrappers[i];
		if (wrapper->user_func == addr && wrapper->user_ref_cnt > 0) {
			if (!--wrapper->user_ref_cnt) 
				hook_ctx_wrapper_exit(wrapper);
			ret = 0;
			break;
		}
	}

	mutex_unlock(&wrappers_mutex);

	return ret;
}

EXPORT_SYMBOL(multi_hook_manager_put);

static int __init multi_hook_manager_init(void)
{
	int i;

	for (i = 0; i < MAX_HOOKS; i++) {
		wrappers[i].ctx = &ctxs[i];
		wrappers[i].hook_func = hook_funcs[i];

		wrappers[i].user_func = 0;
		wrappers[i].user_ref_cnt = 0;
		wrappers[i].blank = 0;
		memset(wrappers[i].desc, 0, HOOK_CTX_WRAPPER_DESC_LEN);
	}

	return 0;
}

static void multi_hook_manager_exit(void)
{
	int i;

	mutex_lock(&wrappers_mutex);

	for (i = 0; i < MAX_HOOKS; i++) {
		if (wrappers[i].user_ref_cnt) {
			hook_ctx_exit(wrappers[i].ctx);
			wrappers[i].user_ref_cnt = 0;
		}
	}

	mutex_unlock(&wrappers_mutex);
}

static void hook_ctx_wrapper_display(struct seq_file *seq,
					 struct hook_ctx_wrapper_t *wrapper,
					 int index)
{
	int i;

	seq_printf(seq,
		   "index: %d, user_ref_cnt: %d, user_func: %lx, hook_func: %lx, desc: %s\n",
		   index, wrapper->user_ref_cnt, wrapper->user_func,
		   wrapper->hook_func, wrapper->desc);

	rcu_read_lock();
	for (i = 0; i < HOOK_CTX_PREV_NUM; i++) {
		struct hook_func_t *hook_func =
			rcu_dereference(wrapper->ctx->prev_func[i]);
		if (hook_func)
			seq_printf(seq, 
				   "    prev func %d, func_addr: %lx, enable_post: %d, %s\n",
				   i, hook_func->func,
				   hook_func->flag & HOOK_ENABLE_POST_RUN,
				   i == HOOK_CTX_PREV_NUM - 1 ? "originral func" : "");
	}

	for (i = 0; i < HOOK_CTX_POST_NUM; i++) {
		struct hook_func_t *hook_func =
			rcu_dereference(wrapper->ctx->post_func[i]);
		if (hook_func)
			seq_printf(seq,
				   "    post func %d, func_addr: %lx, enable_post: %d\n",
				   i, hook_func->func,
				   hook_func->flag & HOOK_ENABLE_POST_RUN);
	}
	rcu_read_unlock();

	seq_puts(seq, "\n");
}

/* just use global data, not use inode data */
static int multi_hook_manager_proc_fs_show(struct seq_file *seq, void *arg)
{
	int i;

	seq_printf(seq, "multi_hook_manager, version: %s\n",
		   MULTI_HOOK_VERSION);

	mutex_lock(&wrappers_mutex);
	for (i = 0; i < MAX_HOOKS; i++)
		hook_ctx_wrapper_display(seq, &wrappers[i], i);
	mutex_unlock(&wrappers_mutex);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(multi_hook_manager_proc_fs);

static int __init multi_hook_init(void)
{
	struct proc_dir_entry *folder_entry;
	struct proc_dir_entry *stats_entry;
	int ret;

	pr_info("multi_hook_init begin, version: %s\n", MULTI_HOOK_VERSION);

	ret = multi_hook_manager_init();
	if (ret < 0)
		return ret;

	folder_entry = proc_mkdir("multi_hook_manager", NULL);
	if (!folder_entry)
		goto err_folder_entry;

	stats_entry =
		proc_create("stats", 0, folder_entry, &multi_hook_manager_proc_fs_fops);
	if (!stats_entry)
		goto err_stats_entry;

	pr_info("multi_hook_init end\n");
	return 0;

err_stats_entry:
	remove_proc_entry("multi_hook_manager", NULL);
err_folder_entry:
	multi_hook_manager_exit();

	pr_debug("multi_hook_init failed\n");
	return ret;
}

static void __exit multi_hook_exit(void)
{
	pr_info("multi_hook_exit begin, version: %s\n", MULTI_HOOK_VERSION);

	remove_proc_subtree("multi_hook_manager", NULL);

	multi_hook_manager_exit();

	pr_info("multi_hook_exit end\n");
}

module_init(multi_hook_init);
module_exit(multi_hook_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION(MULTI_HOOK_VERSION);
MODULE_DESCRIPTION("multi_hook: to expand one function pointer to multi inserted functions");
MODULE_AUTHOR("Qianyu Zhang <zhangianyu.sys@bytedance.com>");
