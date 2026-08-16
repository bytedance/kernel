// SPDX-License-Identifier: GPL-2.0-only
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/mce.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

struct mce_stat {
	bool cmci;
	bool hpage;
	int signal;
	pid_t pid;
	unsigned long addr;
	u64 time;
	char comm[TASK_COMM_LEN];
};
#define MAX_NR_RECORD 256
static struct mce_stat mcestat[MAX_NR_RECORD];
static DEFINE_SPINLOCK(mcestat_lock);
static int mce_records;
static bool mcestat_enabled __read_mostly = true;

static int mcestat_enabled_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", mcestat_enabled);
	return 0;
}

static ssize_t
mcestat_enabled_write(struct file *file, const char __user *buf, size_t len,
		      loff_t *ppos)
{
	unsigned long val;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = kstrtoul_from_user(buf, len, 0, &val);
	if (ret)
		return ret;

	mcestat_enabled = !!val;
	return len;
}

static int mcestat_enabled_open(struct inode *inode, struct file *file)
{
	return single_open(file, mcestat_enabled_show, NULL);
}

static const struct proc_ops mcestat_enabled_fops = {
	.proc_open	= mcestat_enabled_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= mcestat_enabled_write,
	.proc_release	= single_release,
};

static void mcestat_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&mcestat_lock, flags);
	mce_records = 0;
	spin_unlock_irqrestore(&mcestat_lock, flags);
}

static bool is_hugepage(unsigned long pfn)
{
	struct page *page;
	struct folio *folio;
	bool huge = false;

	rcu_read_lock();

	page = pfn_to_online_page(pfn);
	if (!page)
		goto out;

	folio = page_folio(page);
	if (!folio_try_get(folio))
		goto out;

	if (likely(page_folio(page) == folio))
		huge = folio_test_large(folio);

	folio_put(folio);
out:
	rcu_read_unlock();
	return huge;
}

void mcestat_record(struct task_struct *task,
		    unsigned long addr, int signal, bool cmci)
{
	struct mce_stat record = {
		.pid = -1,
	};
	unsigned long flags;

	if (!mcestat_enabled)
		return;

	record.addr = addr;
	record.signal = signal;
	record.cmci = cmci;
	record.hpage = is_hugepage(addr >> PAGE_SHIFT);
	record.time = ktime_get_ns();

	if (task) {
		record.pid = task->pid;
		strscpy(record.comm, task->comm, sizeof(record.comm));
	} else {
		strscpy(record.comm, "kernel", sizeof(record.comm));
	}

	spin_lock_irqsave(&mcestat_lock, flags);
	if (mce_records < MAX_NR_RECORD)
		mcestat[mce_records++] = record;
	spin_unlock_irqrestore(&mcestat_lock, flags);
}

static int mcestat_proc_show(struct seq_file *m, void *v)
{
	struct mce_stat record;
	unsigned long flags;
	int records;
	int i;

	seq_puts(m, "INDEX      PID         COMMAND             ADDR HUGE SIGNUM         TIME INTERRUPT\n");
	spin_lock_irqsave(&mcestat_lock, flags);
	records = mce_records;
	spin_unlock_irqrestore(&mcestat_lock, flags);

	for (i = 0; i < records; i++) {
		u64 ts;
		unsigned long rem_nsec;

		spin_lock_irqsave(&mcestat_lock, flags);
		/*
		 * A concurrent O_TRUNC reset can shrink mce_records after
		 * the loop limit is sampled.
		 */
		if (i >= mce_records) {
			spin_unlock_irqrestore(&mcestat_lock, flags);
			break;
		}
		record = mcestat[i];
		spin_unlock_irqrestore(&mcestat_lock, flags);

		ts = record.time;
		rem_nsec = do_div(ts, 1000000000);

		seq_printf(m, "%5d %8d%16.16s %16lx    %1d  %5d %5lu.%06lu %s\n",
			   i, record.pid, record.comm,
			   record.addr,
			   (int)record.hpage,
			   record.signal,
			   (unsigned long)ts, rem_nsec / 1000,
			   record.cmci ? "CMCI" : "MachineCheck");
	}
	return 0;
}

static ssize_t
mcestat_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return len;
}

static int mcestat_open(struct inode *inode, struct file *file)
{
	/* If this file was open for write, then erase contents */
	if ((file->f_mode & FMODE_WRITE) && (file->f_flags & O_TRUNC)) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		mcestat_reset();
	}

	return single_open_size(file, mcestat_proc_show, NULL, 128 * (1 + MAX_NR_RECORD));
}

static const struct proc_ops mcestat_fops = {
	.proc_open	= mcestat_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_write	= mcestat_write,
	.proc_release	= single_release,
};

static int __init proc_mce_init(void)
{
	if (!proc_create("mcestat", 0644, NULL, &mcestat_fops)) {
		pr_warn("Failed to register /proc/mcestat");
		return -ENOMEM;
	}
	if (!proc_create("mcestat_enabled", 0644, NULL,
			 &mcestat_enabled_fops)) {
		pr_warn("Failed to register /proc/mcestat_enabled");
		goto remove_mcestat;
	}
	return 0;

remove_mcestat:
	remove_proc_entry("mcestat", NULL);
	return -ENOMEM;
}
late_initcall(proc_mce_init);
