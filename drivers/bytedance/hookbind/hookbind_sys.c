/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2024, ByteDance Ltd. and/or its affiliates. All rights reserved. */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ctype.h>
#include <linux/signal.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/kprobes.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include "hookbind.h"

#ifdef CONFIG_X86_64
#define VIRT_TO_PAGE(addr)		virt_to_page(addr)
#endif

#ifdef CONFIG_ARM64
#define VIRT_TO_PAGE(addr)		phys_to_page(virt_to_phys(addr))
#endif

#ifndef VIRT_TO_PAGE
#error "Unsupported architecture"
#endif

struct mapping_rule {
	int	port;		// mapping from
	int	mport;		// mapping to
	struct	pid *pgrp;
	pid_t	nr;
	bool	sig_sent;
	struct	list_head list;
};

static LIST_HEAD(rules);
static DEFINE_SPINLOCK(lock);	// protecting list above

/* Called _without_ lock on */
static void add(int port, int mport, struct task_struct *tsk)
{
	int nr;
	struct mapping_rule *t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return;

	t->port = port;
	t->mport = mport;
	t->sig_sent = false;

	rcu_read_lock();
	t->pgrp = task_pgrp(tsk);
	get_pid(t->pgrp);
	t->nr	= pid_nr(t->pgrp);
	nr = t->nr;
	rcu_read_unlock();

	spin_lock(&lock);
	list_add_tail(&t->list, &rules);
	spin_unlock(&lock);

	pr_info("%s rule: pgrp: %d, mapping port %d --> %d\n", __func__, nr,
		port, mport);
}

/* Called with lock on */
static void delete(struct mapping_rule *t)
{
	if (t) {
		pr_info("del rule: pgrp: %d, mapping port %d --> %d\n",
				t->nr, t->port, t->mport);
		put_pid(t->pgrp);
		list_del(&t->list);
		kfree(t);
	}
}

static bool rule_valid(struct mapping_rule *t)
{
	struct task_struct *p;
	if (t->nr != pid_nr(t->pgrp))
		return false;
	do_each_pid_task(t->pgrp, PIDTYPE_PGID, p) {
		if (p)
			return true;
	} while_each_pid_task(t->pgrp, PIDTYPE_PGID, p);
	return false;
}

static inline void __hook_bind_func(struct socket *sock, struct sockaddr *kaddr,
				    int len)
{
	int nr, port, mport;
	bool hit = false;
	struct pid *group;
	struct mapping_rule *t, *tmp;
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;

	if (!try_module_get(THIS_MODULE))
		goto out;
	if (list_empty(&rules) )
		goto end;
	if (len < sizeof(struct sockaddr_in))
		goto end;
	if (kaddr->sa_family != AF_INET && kaddr->sa_family != AF_INET6)
		goto end;
	addr = (struct sockaddr_in *)kaddr;
	addr6 = (struct sockaddr_in6 *)kaddr;

	rcu_read_lock();
	group = task_pgrp(current);

	spin_lock(&lock);
	list_for_each_entry_safe(t, tmp, &rules, list) {
		if (!rule_valid(t)) {
			delete(t);
			continue;
		}
		if (t->pgrp != group)
			continue;
		nr = t->nr;
		port = t->port;
		mport = t->mport;
		if (kaddr->sa_family == AF_INET &&
				addr->sin_port == htons(t->port)) {
			addr->sin_port = htons(t->mport);
			hit = true;
			break;
		} else if (kaddr->sa_family == AF_INET6 &&
				addr6->sin6_port == htons(t->port)) {
			addr6->sin6_port = htons(t->mport);
			hit = true;
			break;
		}
	}
	spin_unlock(&lock);
	rcu_read_unlock();

	if (hit) {
		/* Now we don't copy back to the user, like BPF bind point: */
		pr_info("hit: pid: %d, pgrp: %d, mapping port %d --> %d\n",
				task_pid_nr(current), nr, port, mport);
	}
end:
	module_put(THIS_MODULE);
out:
	smp_rmb();
}

/* No security_socket_bind as BPF hook bind will not do as well: */
static int hook_bind_func(struct socket *sock, struct sockaddr *kaddr, int len)
{
	__hook_bind_func(sock, kaddr, len);
	return inet_bind(sock, kaddr, len);
}

static int hook_bind6_func(struct socket *sock, struct sockaddr *kaddr, int len)
{
	__hook_bind_func(sock, kaddr, len);
	return inet6_bind(sock, kaddr, len);
}

static size_t decode(char *argenv,size_t length)
{
	int iport = 0, import = 0, flag = 0;
	ssize_t i = 0;
	while (i < length) {
		if (isspace(argenv[i]) || argenv[i] == '\0') {
			i++;
		} else if (isdigit(argenv[i])) {
			if (flag == 0)
				iport = iport*10 + (argenv[i] - '0');
			else
				import = import*10 + (argenv[i] - '0');
			i++;
		} else if (argenv[i] == ':') {
			flag = 1;
			i++;
		} else if (argenv[i] == '/') {
			if (iport > 0xFFFF || import > 0xFFFF ||
				iport <= 0 || import <= 0) {
				pr_info("add rule: WRONG port %d --> %d\n",
					iport, import);
				i++;
				continue;
			}
			add(iport, import, current);
			flag = 0;
			iport =0;
			import = 0;
			i++;
		} else{
			pr_info("str %s\n", argenv);
			pr_info("bad str %s\n", &argenv[i]);
			break;
		}
	}
	if (flag == 1 && iport <= 0xFFFF && iport > 0 &&
			import <= 0xFFFF && import > 0)
		add(iport, import, current);
	return i;
}

ssize_t dump_dmesg(void)
{
	struct mapping_rule *t, *tmp;
	struct task_struct *p;
	bool valid;

	rcu_read_lock();
	spin_lock(&lock);
	list_for_each_entry_safe(t, tmp, &rules, list) {
		valid = false;
		if (t->nr == pid_nr(t->pgrp)) {
			do_each_pid_task(t->pgrp, PIDTYPE_PGID, p) {
				if (p) {
					pr_info("read task: pid: %d, mapping port %d --> %d\n",
						task_pid_nr(p), t->port, t->mport);
					valid = true;
					/* no break here */
				}
			} while_each_pid_task(t->pgrp, PIDTYPE_PGID, p);
		}
		if (!valid)
			delete(t);
	}
	spin_unlock(&lock);
	rcu_read_unlock();

	return 0;
}

ssize_t add_new_rule(const char __user *buffer,size_t length)
{
	ssize_t res = 0;
	char *bmp = kmalloc((length + 1) * sizeof(char), GFP_KERNEL);
	if (!bmp) {
		res = -ENOMEM;
		goto out;
	}
	res = copy_from_user(bmp, buffer, length);
	if (res != 0) {
		res = -EFAULT;
		goto free_bmp;
	}
	bmp[length]='\0';
	res = decode(bmp,length+1);
free_bmp:
	kfree(bmp);
out:
	return res;
}

static void *my_kallsyms_lookup_name(const char *symbol)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	static unsigned long (*kallsyms_lookup_name)(const char *symbol);
	void *addr;
	int ret;

	if (kallsyms_lookup_name)
		goto lookup;

	// Sync with toa_core.c:
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe err %d\n", ret);
		return NULL;
	}

	pr_debug("kallsyms_lookup_name at %p\n", kp.addr);
	kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);

lookup:
	// Lookup real things here:
	addr = (void *)kallsyms_lookup_name(symbol);
	if (!addr)
		pr_err("kallsyms_lookup_name(%s) err\n", symbol);

	pr_debug("%s at %p\n", symbol, addr);
	return addr;
}

static int sys_bind_replace(unsigned long target,
			    unsigned long *vmapped_target_pp, unsigned long new,
			    unsigned long *prev_p)
{
	const char *vaddr;
	struct page *page;

	// @see is_vmalloc_or_module_addr, which is not exported:
	if ((target >= MODULES_VADDR && target < MODULES_END) ||
	    is_vmalloc_addr((const void *)target))
		page = vmalloc_to_page((const void *)target);
	else if (virt_addr_valid((void *)target))
		page = VIRT_TO_PAGE((void *)target);
	else
		return -EINVAL;

	vaddr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!vaddr)
		return -EPERM;

	*vmapped_target_pp =
		(unsigned long)(vaddr + ((unsigned long)target & ~PAGE_MASK));
	*prev_p = xchg((unsigned long *)(*vmapped_target_pp), new);
	flush_kernel_vmap_range((void *)vaddr, sizeof(vaddr));
	invalidate_kernel_vmap_range((void *)target, sizeof(target));

	return 0;
}

static inline void sys_bind_restore(const void *addr,
				    unsigned long *vmapped_target_p,
				    unsigned long func)
{
	const void *vaddr =
		(void *)((unsigned long)vmapped_target_p & PAGE_MASK);

	xchg(vmapped_target_p, func);
	vunmap(vaddr);
	invalidate_kernel_vmap_range((void *)addr, sizeof(addr));
}

/* covers only normal tcp + udp + raw, ignoring sctp | mptcp | dccp | ... */
static struct proto_info_t {
	const char *name;
	int (*bind)(struct socket *sock, struct sockaddr *myaddr,
		    int sockaddr_len);
	int (*ops_bind)(struct socket *sock, struct sockaddr *myaddr,
			int sockaddr_len);
	const struct proto_ops *ops;
	unsigned long vmapped_ops_bind;
} hookbind_protos[] = {
	// @see inetsw_array
	{
		.name = "inet_stream_ops",
		.bind = hook_bind_func,
		.ops_bind = inet_bind,
	},
	{
		.name = "inet_dgram_ops",
		.bind = hook_bind_func,
		.ops_bind = inet_bind,
	},
	{
		.name = "inet_sockraw_ops",
		.bind = hook_bind_func,
		.ops_bind = inet_bind,
	},
#if IS_ENABLED(CONFIG_IPV6)
	// @see net/ipv6/af_inet6.c
	{
		.name = "inet6_stream_ops",
		.bind = hook_bind6_func,
		.ops_bind = inet6_bind,
	},
	{
		.name = "inet6_dgram_ops",
		.bind = hook_bind6_func,
		.ops_bind = inet6_bind,
	},
	// @see net/ipv6/raw.c
	{
		.name = "inet6_sockraw_ops",
		.bind = hook_bind6_func,
		.ops_bind = inet6_bind,
	},
#endif
};

int __init register_hookbind(void)
{
	int err, i;

	for (i = 0; i < ARRAY_SIZE(hookbind_protos); ++i) {
		struct proto_info_t *p = &hookbind_protos[i];
		const struct proto_ops *ops = p->ops;

		if (ops)
			continue;

		ops = my_kallsyms_lookup_name(p->name);
		if (!ops) {
			pr_err("failed to lookup %s symbol!\n", p->name);
			err = -ENOENT;
			goto err_kallsyms_lookup;
		}

		if (ops->bind != p->ops_bind) {
			pr_err("mismatched bind point, %p != %p\n", ops->bind,
			       p->ops_bind);
			err = -EINVAL;
			goto err_kallsyms_lookup;
		}

		p->ops = ops;
	}

	for (i = 0; i < ARRAY_SIZE(hookbind_protos); ++i) {
		struct proto_info_t *p = &hookbind_protos[i];
		const struct proto_ops *ops = p->ops;

		// replace ops->bind to p->bind:
		err = sys_bind_replace((unsigned long)&ops->bind,
				       &p->vmapped_ops_bind,
				       (unsigned long)p->bind,
				       (unsigned long *)&p->ops_bind);
		if (err)
			goto err_bind_replace;

		pr_info("replaced %s :: bind\n", p->name);
	}

	pr_info("registered successfully\n");
	return 0;

err_bind_replace:
	unregister_hookbind();
err_kallsyms_lookup:
	return err;
}

void unregister_hookbind(void)
{
	struct mapping_rule *t, *tmp;
	int i;

	for (i = 0; i < ARRAY_SIZE(hookbind_protos); ++i) {
		struct proto_info_t *p = &hookbind_protos[i];
		const struct proto_ops *ops = p->ops;

		if (!ops || !p->vmapped_ops_bind)
			continue;

		sys_bind_restore((const void *)&ops->bind,
				 (unsigned long *)p->vmapped_ops_bind,
				 (unsigned long)p->ops_bind);
		p->vmapped_ops_bind = 0;
		pr_info("restored %s :: bind\n", p->name);
	}

	// wait a rcu gp that no bind call is happening:
	synchronize_rcu();

	spin_lock(&lock);
	list_for_each_entry_safe(t, tmp, &rules, list) {
		delete(t);
	}
	spin_unlock(&lock);

	pr_info("unregistered successfully\n");
}
