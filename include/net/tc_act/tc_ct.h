/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_CT_H
#define __NET_TC_CT_H

#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_ct.h>

struct tcf_conntrack_info {
	struct tc_action common;
	struct net *net;
	u16 zone;
	struct nf_conn *tmpl;
	u32 labels[4];
	u32 labels_mask[4];
	u32 mark;
	u32 mark_mask;
	bool commit;
	struct tcf_block *block;
};

#define to_conntrack(a) ((struct tcf_conntrack_info *)a)

static inline bool is_tcf_ct(const struct tc_action *a)
{
#ifdef CONFIG_NET_CLS_ACT
	if (a->ops && a->ops->id == TCA_ID_CONNTRACK)
		return true;
#endif
	return false;
}

static inline struct tcf_conntrack_info *tcf_ct_info(const struct tc_action *a)
{
	return to_conntrack(a);
}

#endif /* __NET_TC_CT_H */
