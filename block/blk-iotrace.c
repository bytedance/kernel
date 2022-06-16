// SPDX-License-Identifier: GPL-2.0
/*
 * Block iotrace code
 */
#include <linux/kernel.h>
#include <linux/blk_types.h>
#include <linux/backing-dev.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/memcontrol.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/signal.h>
#include <trace/events/block.h>
#include <linux/blk-mq.h>
#include "blk-rq-qos.h"
#include "blk-stat.h"

static struct blkcg_policy blkcg_policy_iotrace;

struct blk_iotrace {
	struct rq_qos rqos;
};

#define LAT_BUCKET_NR ARRAY_SIZE(def_latb_thresh)
/* default latency bucket(ns) */
static uint64_t def_latb_thresh[] = {
	5000000,          /* 5 ms */
	10000000,         /* 10 ms */
	30000000,         /* 30 ms */
	50000000,         /* 50 ms */
	100000000,        /* 100 ms */
};

enum {
	IOT_READ,
	IOT_WRITE,
	IOT_OTHER,
	IOT_NR,
};

struct iotrace_stat {
	struct blk_rq_stat rqs;
	uint64_t ios[IOT_NR];
	uint64_t sts[IOT_NR];
	uint64_t tms[IOT_NR];
	uint64_t dtms[IOT_NR];
	uint64_t hit[IOT_NR][LAT_BUCKET_NR + 1];
	uint64_t dhit[IOT_NR][LAT_BUCKET_NR + 1];
};

struct iotrace_grp {
	struct blkg_policy_data pd;
	struct iotrace_stat __percpu *stat_pcpu;
	uint64_t thresh_ns[LAT_BUCKET_NR];
	struct iotrace_stat stat;
};

/* iotrace_mode */
#define IOTRACE_DISABLE     0  /* iotrace disable */
#define IOTRACE_ENABLE      1  /* iotrace enable without q2c */
#define IOTRACE_ENABLE_ALL  2  /* iotrace enable all */

static int __read_mostly iotrace_mode;

static inline struct blk_iotrace *BLKIOTRACE(struct rq_qos *rqos)
{
	return container_of(rqos, struct blk_iotrace, rqos);
}

static inline struct iotrace_grp *pd_to_iot(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct iotrace_grp, pd) : NULL;
}

static inline struct iotrace_grp *blkg_to_iot(struct blkcg_gq *blkg)
{
	return pd_to_iot(blkg_to_pd(blkg, &blkcg_policy_iotrace));
}

static inline struct blkcg_gq *iot_to_blkg(struct iotrace_grp *iot)
{
	return pd_to_blkg(&iot->pd);
}

static struct blkg_policy_data *iotrace_pd_alloc(gfp_t gfp, struct request_queue *q,
						struct blkcg *blkcg)
{
	struct iotrace_grp *iot;

	iot = kzalloc_node(sizeof(*iot), gfp, q->node);
	if (!iot)
		return NULL;

	iot->stat_pcpu = alloc_percpu_gfp(struct iotrace_stat, gfp);
	if (!iot->stat_pcpu) {
		kfree(iot);
		return NULL;
	}

	return &iot->pd;
}

static void iotrace_pd_init(struct blkg_policy_data *pd)
{
	struct iotrace_grp *iot = pd_to_iot(pd);
	int i, j, cpu;

	for_each_possible_cpu(cpu) {
		struct iotrace_stat *stat;

		stat = per_cpu_ptr(iot->stat_pcpu, cpu);
		blk_rq_stat_init(&stat->rqs);
		for (i = 0; i < IOT_NR; i++) {
			stat->ios[i] = stat->sts[i] = 0;
			stat->tms[i] = stat->dtms[i] = 0;
			for (j = 0; j < LAT_BUCKET_NR + 1; j++)
				stat->hit[i][j] = 0;
		}
	}

	blk_rq_stat_init(&iot->stat.rqs);
	for (i = 0; i < IOT_NR; i++) {
		iot->stat.ios[i] = iot->stat.sts[i] = 0;
		iot->stat.tms[i] = iot->stat.dtms[i] = 0;
		for (j = 0; j < LAT_BUCKET_NR + 1; j++)
			iot->stat.hit[i][j] = 0;
	}

	for (i = 0; i < LAT_BUCKET_NR; i++)
		iot->thresh_ns[i] = def_latb_thresh[i];
}

static void iotrace_pd_free(struct blkg_policy_data *pd)
{
	struct iotrace_grp *iot = pd_to_iot(pd);

	free_percpu(iot->stat_pcpu);
	kfree(iot);
}

static inline u64 iotrace_prfill_formal(struct seq_file *sf, struct blkg_policy_data *pd,
					int off)
{
	struct iotrace_grp *iot = pd_to_iot(pd);
	struct iotrace_stat *stat = &iot->stat;
	const char *dname = blkg_dev_name(pd->blkg);
	int cpu, i;

	if (!dname)
		return 0;
	memset(stat, 0, sizeof(struct iotrace_stat));

	/* collect per cpu data */
	for_each_online_cpu(cpu) {
		struct iotrace_stat *s;

		s = per_cpu_ptr(iot->stat_pcpu, cpu);
		for (i = 0; i < IOT_NR; i++) {
			int j;

			stat->ios[i] += s->ios[i];
			stat->sts[i] += s->sts[i];
			stat->tms[i] += s->tms[i];
			for (j = 0; j < LAT_BUCKET_NR + 1; j++)
				stat->hit[i][j] += s->hit[i][j];
		}
	}

	seq_printf(sf, "%s rios: %llu wios: %llu oios: %llu rsts: %llu wsts: %llu osts: %llu rtms: %llu wtms: %llu otms: %llu ",
		dname,
		stat->ios[IOT_READ], stat->ios[IOT_WRITE], stat->ios[IOT_OTHER],
		stat->sts[IOT_READ], stat->sts[IOT_WRITE], stat->sts[IOT_OTHER],
		stat->tms[IOT_READ], stat->tms[IOT_WRITE], stat->tms[IOT_OTHER]);

	/* read hit */
	seq_puts(sf, " rhit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->hit[IOT_READ][i]);

	/* write hit */
	seq_puts(sf, " whit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->hit[IOT_WRITE][i]);

	/* other hit */
	seq_puts(sf, " ohit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->hit[IOT_OTHER][i]);

	seq_putc(sf, '\n');

	return 0;
}

static inline u64 iotrace_prfill_extend(struct seq_file *sf, struct blkg_policy_data *pd,
					int off)
{
	struct iotrace_grp *iot = pd_to_iot(pd);
	struct iotrace_stat *stat = &iot->stat;
	const char *dname = blkg_dev_name(pd->blkg);
	int cpu, i, j;

	if (!dname)
		return 0;

	memset(stat, 0, sizeof(struct iotrace_stat));

	/* collect per cpu data */
	for_each_online_cpu(cpu) {
		struct iotrace_stat *s;

		s = per_cpu_ptr(iot->stat_pcpu, cpu);
		for (i = 0; i < IOT_NR; i++) {
			stat->ios[i] += s->ios[i];
			stat->sts[i] += s->sts[i];
			stat->tms[i] += s->tms[i];
			stat->dtms[i] += s->dtms[i];
			for (j = 0; j < LAT_BUCKET_NR + 1; j++) {
				stat->hit[i][j] += s->hit[i][j];
				stat->dhit[i][j] += s->dhit[i][j];
			}
		}
	}

	seq_printf(sf, "%s rios: %llu wios: %llu oios: %llu rsts: %llu wsts: %llu osts: %llu rtms: %llu wtms: %llu otms: %llu rdtms: %llu wdtms: %llu odtms: %llu",
		dname,
		stat->ios[IOT_READ], stat->ios[IOT_WRITE], stat->ios[IOT_OTHER],
		stat->sts[IOT_READ], stat->sts[IOT_WRITE], stat->sts[IOT_OTHER],
		stat->tms[IOT_READ], stat->tms[IOT_WRITE], stat->tms[IOT_OTHER],
		stat->dtms[IOT_READ], stat->dtms[IOT_WRITE], stat->dtms[IOT_OTHER]);

	/* read hit */
	seq_puts(sf, " rhit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->hit[IOT_READ][i]);

	/* write hit */
	seq_puts(sf, " whit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->hit[IOT_WRITE][i]);

	/* other hit */
	seq_puts(sf, " ohit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->hit[IOT_OTHER][i]);

	/* read dhit */
	seq_puts(sf, " rdhit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->dhit[IOT_READ][i]);

	/* write dhit */
	seq_puts(sf, " wdhit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->dhit[IOT_WRITE][i]);

	/* other dhit */
	seq_puts(sf, " odhit:");
	for (i = 0; i < LAT_BUCKET_NR + 1; i++)
		seq_printf(sf, " %llu", stat->dhit[IOT_OTHER][i]);

	seq_putc(sf, '\n');

	return 0;
}

static u64 iotrace_prfill_stat(struct seq_file *sf, struct blkg_policy_data *pd,
				int off)
{
	if (iotrace_mode == IOTRACE_ENABLE)
		return iotrace_prfill_formal(sf, pd, off);

	if (iotrace_mode == IOTRACE_ENABLE_ALL)
		return iotrace_prfill_extend(sf, pd, off);

	return 0;
}


static int iotrace_print_stat(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), iotrace_prfill_stat,
			  &blkcg_policy_iotrace, seq_cft(sf)->private, false);
	return 0;
}

static u64 iotrace_prfill_lat_thresh(struct seq_file *sf,
					struct blkg_policy_data *pd, int off)
{
	struct iotrace_grp *iot = pd_to_iot(pd);
	const char *dname = blkg_dev_name(pd->blkg);
	int i;

	if (!dname)
		return 0;

	seq_puts(sf, dname);
	for (i = 0; i < LAT_BUCKET_NR; i++)
		seq_printf(sf, " %llu",  iot->thresh_ns[i]);

	seq_putc(sf, '\n');

	return 0;
}

static int iotrace_print_lat_thresh(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  iotrace_prfill_lat_thresh, &blkcg_policy_iotrace,
			  seq_cft(sf)->private, false);
	return 0;
}

static ssize_t iotrace_set_lat_thresh(struct kernfs_open_file *of, char *buf,
				      size_t nbytes, loff_t off)
{
	struct blkcg *blkcg = css_to_blkcg(of_css(of));
	struct blkg_conf_ctx ctx;
	struct iotrace_grp *iot;
	uint64_t tmp[LAT_BUCKET_NR];
	int i, ret;
	char *p;

	ret = blkg_conf_prep(blkcg, &blkcg_policy_iotrace, buf, &ctx);
	if (ret)
		return ret;

	iot = blkg_to_iot(ctx.blkg);
	p = ctx.body;

	ret = -EINVAL;
	if (sscanf(p, "%llu %llu %llu %llu %llu",
		   &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4]) != LAT_BUCKET_NR)
		goto out;

	/* make sure threshold in order */
	for (i = 0; i < LAT_BUCKET_NR - 1; i++) {
		if (tmp[i] >= tmp[i + 1])
			goto out;
	}

	/* update threshold for each bucket */
	for (i = 0; i < LAT_BUCKET_NR; i++)
		iot->thresh_ns[i] = tmp[i];

	ret = 0;
out:
	blkg_conf_finish(&ctx);
	return ret ? : nbytes;
}

static int iotrace_print_enable(struct seq_file *sf, void *v)
{
	seq_printf(sf, "%d\n", iotrace_mode);
	return 0;
}

static ssize_t iotrace_set_mode(struct kernfs_open_file *of, char *buf,
				size_t nbytes, loff_t off)
{
	int mode;

	if (kstrtoint(buf, 10, &mode))
		return -EINVAL;
	if ((mode < IOTRACE_DISABLE) || (mode > IOTRACE_ENABLE_ALL))
		return -EINVAL;

	iotrace_mode = mode;

	return nbytes;
}

/* cgroup v2: io.iotrace.stat */
static struct cftype iotrace_def_files[] = {
	{
		.name		= "iotrace.stat",
		.seq_show	= iotrace_print_stat,
	},
	{
		.name		= "iotrace.lat_thresh",
		.seq_show	= iotrace_print_lat_thresh,
		.write		= iotrace_set_lat_thresh,
	},
	{
		.name		= "iotrace.enable",
		.flags		= CFTYPE_ONLY_ON_ROOT,
		.seq_show	= iotrace_print_enable,
		.write		= iotrace_set_mode,
	},
	{}
};

static struct blkcg_policy blkcg_policy_iotrace = {
	.dfl_cftypes	= iotrace_def_files,
	.pd_alloc_fn	= iotrace_pd_alloc,
	.pd_init_fn	= iotrace_pd_init,
	.pd_free_fn	= iotrace_pd_free,
};

static void iotrace_account_bio(struct iotrace_grp *iot, struct bio *bio,
				u64 now)
{
	u64 delta, start = bio_issue_time(&bio->bi_issue);
	u64 delta_disk, start_disk = bio_issue_time(&bio->bi_start);
	struct iotrace_stat *stat;
	int i, t;

	now = __bio_issue_time(now);

	if (now <= start)
		return;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
		t = IOT_READ;
		break;
	case REQ_OP_WRITE:
		t = IOT_WRITE;
		break;
	default:
		t = IOT_OTHER;
		break;
	}

	if (start)
		delta = now - start;
	else
		delta = 0;
	stat = get_cpu_ptr(iot->stat_pcpu);
	stat->ios[t]++;
	stat->sts[t] += bio_issue_size(&bio->bi_issue);
	stat->tms[t] += delta;
	if (start_disk && (start_disk > start) && (now > start_disk))
		delta_disk = now - start_disk;
	else
		delta_disk = 0;
	stat->dtms[t] += delta_disk;
	if (delta >= iot->thresh_ns[LAT_BUCKET_NR - 1]) {
		stat->hit[t][LAT_BUCKET_NR]++;
	} else {
		for (i = 0; i < LAT_BUCKET_NR; i++) {
			if (delta < iot->thresh_ns[i]) {
				stat->hit[t][i]++;
				break;
			}
		}
	}

	if (iotrace_mode != IOTRACE_ENABLE_ALL) {
		put_cpu_ptr(stat);
		return;
	}

	if (delta_disk >= iot->thresh_ns[LAT_BUCKET_NR - 1])
		stat->dhit[t][LAT_BUCKET_NR]++;
	else {
		for (i = 0; i < LAT_BUCKET_NR; i++) {
			if (delta_disk < iot->thresh_ns[i]) {
				stat->dhit[t][i]++;
				break;
			}
		}
	}

	put_cpu_ptr(stat);
}

static void blkcg_iotrace_done_bio(struct rq_qos *rqos, struct bio *bio)
{
	struct blkcg_gq *blkg;
	struct iotrace_grp *iot;
	u64 now;

	if (iotrace_mode == IOTRACE_DISABLE)
		return;

	now = ktime_to_ns(ktime_get());
	blkg = bio->bi_blkg;
	/* account io statistics */
	while (blkg) {
		iot = blkg_to_iot(blkg);
		if (!iot) {
			WARN_ONCE(1, "struct iotrace_grp is not sync with blkg");
			blkg = blkg->parent;
			continue;
		}

		iotrace_account_bio(iot, bio, now);
		blkg = blkg->parent;
	}
}

static void blkcg_iotrace_issue(struct rq_qos *rqos, struct request *rq)
{
	struct bio *bio;

	if (iotrace_mode != IOTRACE_ENABLE_ALL)
		return;

	__rq_for_each_bio(bio, rq)
		bio_issue_init_time(&bio->bi_start, rq->io_start_time_ns);
}

static void blkcg_iotrace_exit(struct rq_qos *rqos)
{
	struct blk_iotrace *blkiotrace = BLKIOTRACE(rqos);

	blkcg_deactivate_policy(rqos->q, &blkcg_policy_iotrace);
	kfree(blkiotrace);
}

static struct rq_qos_ops blkcg_iotrace_ops = {
	.issue		= blkcg_iotrace_issue,
	.done_bio	= blkcg_iotrace_done_bio,
	.exit		= blkcg_iotrace_exit,
};

int blk_iotrace_init(struct request_queue *q)
{
	struct blk_iotrace *blkiotrace;
	struct rq_qos *rqos;
	int ret;

	blkiotrace = kzalloc(sizeof(*blkiotrace), GFP_KERNEL);
	if (!blkiotrace)
		return -ENOMEM;

	rqos = &blkiotrace->rqos;
	rqos->id = RQ_QOS_IOTRACE;
	rqos->ops = &blkcg_iotrace_ops;
	rqos->q = q;

	rq_qos_add(q, rqos);

	ret = blkcg_activate_policy(q, &blkcg_policy_iotrace);
	if (ret) {
		rq_qos_del(q, rqos);
		kfree(blkiotrace);
		return ret;
	}

	return 0;
}

static int __init iotrace_init(void)
{
	return blkcg_policy_register(&blkcg_policy_iotrace);
}

static void __exit iotrace_exit(void)
{
	return blkcg_policy_unregister(&blkcg_policy_iotrace);
}

module_init(iotrace_init);
module_exit(iotrace_exit);
MODULE_LICENSE("GPL");
