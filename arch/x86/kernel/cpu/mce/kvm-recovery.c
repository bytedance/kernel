// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/kstrtox.h>
#include <linux/mce.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

bool mce_kvm __read_mostly = true;
bool mce_kill_kvm __read_mostly = true;

static int mce_kvm_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", mce_kvm);
	return 0;
}

static ssize_t
mce_kvm_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	unsigned long val;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtoul_from_user(buf, len, 0, &val);
	if (ret)
		return ret;

	mce_kvm = !!val;
	return len;
}

static int mce_kvm_open(struct inode *inode, struct file *file)
{
	return single_open(file, mce_kvm_show, NULL);
}

static const struct proc_ops mce_kvm_fops = {
	.proc_open	= mce_kvm_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= mce_kvm_write,
	.proc_release	= single_release,
};

static int mce_kill_kvm_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", mce_kill_kvm);
	return 0;
}

static ssize_t
mce_kill_kvm_write(struct file *file, const char __user *buf, size_t len,
		   loff_t *ppos)
{
	unsigned long val;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtoul_from_user(buf, len, 0, &val);
	if (ret)
		return ret;

	mce_kill_kvm = !!val;
	return len;
}

static int mce_kill_kvm_open(struct inode *inode, struct file *file)
{
	return single_open(file, mce_kill_kvm_show, NULL);
}

static const struct proc_ops mce_kill_kvm_fops = {
	.proc_open	= mce_kill_kvm_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= mce_kill_kvm_write,
	.proc_release	= single_release,
};

static int __init proc_mce_kvm_recovery_init(void)
{
	if (!proc_create("mce_kvm", 0644, NULL, &mce_kvm_fops)) {
		pr_warn("Failed to register /proc/mce_kvm");
		return -ENOMEM;
	}
	if (!proc_create("mce_kill_kvm", 0644, NULL, &mce_kill_kvm_fops)) {
		pr_warn("Failed to register /proc/mce_kill_kvm");
		goto remove_mce_kvm;
	}

	return 0;

remove_mce_kvm:
	remove_proc_entry("mce_kvm", NULL);
	return -ENOMEM;
}
late_initcall(proc_mce_kvm_recovery_init);
