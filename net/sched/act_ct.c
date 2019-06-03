/*
 * net/sched/act_conntrack.c  connection tracking action
 *
 * Copyright (c) 2018 Yossi Kuperman <yossiku@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/act_api.h>
#include <uapi/linux/tc_act/tc_ct.h>
#include <net/tc_act/tc_ct.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <linux/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat.h>
/* #include <net/netfilter/nf_nat_l3proto.h> */

#include <net/ip.h>
#include <net/pkt_cls.h>

static unsigned int conntrack_net_id;
static struct tc_action_ops act_conntrack_ops;

enum ovs_ct_nat {
	OVS_CT_NAT = 1 << 0,     /* NAT for committed connections only. */
	OVS_CT_SRC_NAT = 1 << 1, /* Source NAT for NEW connections. */
	OVS_CT_DST_NAT = 1 << 2, /* Destination NAT for NEW connections. */
};

static void ct_parse_nat(struct tc_ct_offload *cto,
			 struct tcf_conntrack_info *ca,
			 struct nf_conn *ct,
			 enum ip_conntrack_info ctinfo)
{
	struct nf_conntrack_tuple target;
	unsigned long nat = 0;

	if (!(ct->status & IPS_NAT_MASK) || !ca->nat)
		return;

	if (ca->nat & OVS_CT_SRC_NAT) {
		nat = IPS_SRC_NAT;
	} else if (ca->nat & OVS_CT_DST_NAT) {
		nat = IPS_DST_NAT;
	} else {
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
			nat = ct->status & IPS_SRC_NAT ?
			      IPS_DST_NAT : IPS_SRC_NAT;
		else
			nat = ct->status & IPS_SRC_NAT ?
			      IPS_SRC_NAT : IPS_DST_NAT;
	}

	/* We are aiming to look like inverse of other direction. */
	nf_ct_invert_tuple(&target, nf_ct_tuple(ct, !CTINFO2DIR(ctinfo)));

	if (nat & IPS_SRC_NAT) {
		cto->ipv4 = target.src.u3.ip;
		cto->port = target.src.u.all;
	}

	if (nat & IPS_DST_NAT) {
		cto->ipv4 = target.dst.u3.ip;
		cto->port = target.dst.u.all;
	}

	cto->proto = target.dst.protonum;
	cto->nat = nat;
}

static void ct_notify_underlying_device(struct sk_buff *skb,
					struct tcf_conntrack_info *ca,
					struct nf_conn *ct,
					enum ip_conntrack_info ctinfo,
					struct net *net)
{
	struct tc_ct_offload cto = { skb, net, NULL, NULL };

	if (ct) {
		cto.zone = (struct nf_conntrack_zone *)nf_ct_zone(ct);
		cto.tuple = nf_ct_tuple(ct, CTINFO2DIR(ctinfo));

		ct_parse_nat(&cto, ca, ct, ctinfo);
	}

	tc_setup_cb_call_all(NULL, TC_SETUP_CT, &cto);
}

static bool skb_nfct_cached(struct net *net, struct sk_buff *skb, u16 zone_id)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return false;

	if (!net_eq(net, read_pnet(&ct->ct_net)))
		return false;
	if (nf_ct_zone(ct)->id != zone_id)
		return false;
	return true;
}

/* Trim the skb to the length specified by the IP/IPv6 header,
 * removing any trailing lower-layer padding. This prepares the skb
 * for higher-layer processing that assumes skb->len excludes padding
 * (such as nf_ip_checksum). The caller needs to pull the skb to the
 * network header, and ensure ip_hdr/ipv6_hdr points to valid data.
 */
static int tcf_skb_network_trim(struct sk_buff *skb)
{
	unsigned int len;
	int err;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		len = ntohs(ip_hdr(skb)->tot_len);
		break;
	case htons(ETH_P_IPV6):
		len = sizeof(struct ipv6hdr)
			+ ntohs(ipv6_hdr(skb)->payload_len);
		break;
	default:
		len = skb->len;
	}

	err = pskb_trim_rcsum(skb, len);

	return err;
}

static u_int8_t tcf_skb_family(struct sk_buff *skb)
{
	u_int8_t family = PF_UNSPEC;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		family = PF_INET;
		break;
	case htons(ETH_P_IPV6):
		family = PF_INET6;
		break;
	default:
        break;
	}

	return family;
}

static int tcf_conntrack_nat_execute(struct sk_buff *skb, struct nf_conn *ct,
				     enum ip_conntrack_info ctinfo,
				     const struct nf_nat_range2 *range,
				     enum nf_nat_manip_type maniptype)
{
	int hooknum, err = NF_ACCEPT;

	/* See HOOK2MANIP(). */
	if (maniptype == NF_NAT_MANIP_SRC)
		hooknum = NF_INET_LOCAL_IN; /* Source NAT */
	else
		hooknum = NF_INET_LOCAL_OUT; /* Destination NAT */

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		if (IS_ENABLED(CONFIG_NF_NAT_IPV4) &&
		    skb->protocol == htons(ETH_P_IP) &&
		    ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   hooknum))
				err = NF_DROP;
			goto push;
		} else if (IS_ENABLED(CONFIG_NF_NAT_IPV6) &&
			   skb->protocol == htons(ETH_P_IPV6)) {
			__be16 frag_off;
			u8 nexthdr = ipv6_hdr(skb)->nexthdr;
			int hdrlen = ipv6_skip_exthdr(skb,
						      sizeof(struct ipv6hdr),
						      &nexthdr, &frag_off);

			if (hdrlen >= 0 && nexthdr == IPPROTO_ICMPV6) {
				if (!nf_nat_icmpv6_reply_translation(skb, ct,
								     ctinfo,
								     hooknum,
								     hdrlen))
					err = NF_DROP;
				goto push;
			}
		}
		/* Non-ICMP, fall thru to initialize if needed. */
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {
			/* Initialize according to the NAT action. */
			err = (range && range->flags & NF_NAT_RANGE_MAP_IPS)
				/* Action is set up to establish a new
				 * mapping.
				 */
				? nf_nat_setup_info(ct, range, maniptype)
				: nf_nat_alloc_null_binding(ct, hooknum);
			if (err != NF_ACCEPT)
				goto push;
		}
		break;

	case IP_CT_ESTABLISHED:
	case IP_CT_ESTABLISHED_REPLY:
		break;

	default:
		err = NF_DROP;
		goto push;
	}

	err = nf_nat_packet(ct, ctinfo, hooknum, skb);
push:
	return err;
}

/* Returns NF_DROP if the packet should be dropped, NF_ACCEPT otherwise. */
static int tcf_conntrack_nat(struct net *net,
			     struct tcf_conntrack_info *info,
			     struct sk_buff *skb, struct nf_conn *ct,
			     enum ip_conntrack_info ctinfo)
{
	enum nf_nat_manip_type maniptype;
	int err;

	/* Add NAT extension if not confirmed yet. */
	if (!nf_ct_is_confirmed(ct) && !nf_ct_nat_ext_add(ct))
		return NF_ACCEPT;   /* Can't NAT. */

	/* Determine NAT type.
	 * Check if the NAT type can be deduced from the tracked connection.
	 * Make sure new expected connections (IP_CT_RELATED) are NATted only
	 * when committing.
	 */
	if (info->nat & OVS_CT_NAT && ctinfo != IP_CT_NEW &&
	    ct->status & IPS_NAT_MASK &&
	    (ctinfo != IP_CT_RELATED || info->commit)) {
		/* NAT an established or related connection like before. */
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
			/* This is the REPLY direction for a connection
			 * for which NAT was applied in the forward
			 * direction.  Do the reverse NAT.
			 */
			maniptype = ct->status & IPS_SRC_NAT
				? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC;
		else
			maniptype = ct->status & IPS_SRC_NAT
				? NF_NAT_MANIP_SRC : NF_NAT_MANIP_DST;
	} else if (info->nat & OVS_CT_SRC_NAT) {
		maniptype = NF_NAT_MANIP_SRC;
	} else if (info->nat & OVS_CT_DST_NAT) {
		maniptype = NF_NAT_MANIP_DST;
	} else {
		return NF_ACCEPT; /* Connection is not NATed. */
	}

	err = tcf_conntrack_nat_execute(skb, ct, ctinfo, &info->range,
					maniptype);

	return err;
}

static void tcf_ct_clear(struct sk_buff *skb)
{
	if (skb_nfct(skb)) {
		nf_conntrack_put(skb_nfct(skb));
		nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
	}
}

static int __tcf_conntrack(struct sk_buff *skb,
			   struct tcf_conntrack_info *ca,
			   u_int8_t family,
			   const struct tc_action *a,
			   struct tcf_result *res)
{
	struct net *net = dev_net(skb->dev);
	enum ip_conntrack_info ctinfo;
	struct nf_conn *tmpl = NULL;
	struct nf_conn *ct;
	bool cached;
	struct nf_hook_state state = {
		.hook = NF_INET_PRE_ROUTING,
		.pf = PF_INET,
		.net = net,
	};
	int err;

	tmpl = ca->tmpl;
	cached = skb_nfct_cached(net, skb, ca->zone);

	if (!cached) {
		if (tmpl) {
			if (skb_nfct(skb))
				nf_conntrack_put(skb_nfct(skb));

			nf_ct_set(skb, tmpl, IP_CT_NEW);
		}

		state.pf = family;
		err = nf_conntrack_in(skb, &state);
		if (err != NF_ACCEPT)
			goto drop;
	} else {
		if (tmpl)
			nf_conntrack_put(&tmpl->ct_general);
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto out;

	if (ca->nat && (nf_ct_is_confirmed(ct) || ca->commit)) {
		err = tcf_conntrack_nat(net, ca, skb, ct, ctinfo);
		if (err != NF_ACCEPT)
			goto drop;
	}

	if (ctinfo == IP_CT_ESTABLISHED ||
	    ctinfo == IP_CT_ESTABLISHED_REPLY) {
		/* TODO: I'm not sure if that "cached" thing affects NAT? */
		ct_notify_underlying_device(skb, ca, ct, ctinfo, net);
	}

	/* TODO: must check this code very carefully; move to another function */
	if (ca->commit) {
		u32 *labels = ca->labels;
		u32 *labels_m = ca->labels_mask;

#if IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)
		if (ca->mark_mask) {
			u32 ct_mark = ca->mark;
			u32 mask = ca->mark_mask;
			u32 new_mark;

			new_mark = ct_mark | (ct->mark & ~(mask));
			if (ct->mark != new_mark) {
				ct->mark = new_mark;
				if (nf_ct_is_confirmed(ct))
					nf_conntrack_event_cache(IPCT_MARK, ct);
			}
		}
#endif
		if (!nf_ct_is_confirmed(ct)) {
			struct nf_conn_labels *cl, *master_cl;
			bool have_mask = !!(memchr_inv(ca->labels_mask, 0, sizeof(ca->labels_mask)));

			/* Inherit master's labels to the related connection? */
			master_cl = ct->master ? nf_ct_labels_find(ct->master) : NULL;

			if (!master_cl && !have_mask)
				goto skip; /* Nothing to do. */

			cl = nf_ct_labels_find(ct);
			if (!cl) {
				nf_ct_labels_ext_add(ct);
				cl = nf_ct_labels_find(ct);
			}

			if (!cl)
				goto drop;

			/* Inherit the master's labels, if any.  Must use memcpy for backport
			 * as struct assignment only copies the length field in older
			 * kernels.
	 		*/
			if (master_cl)
				memcpy(cl->bits, master_cl->bits, NF_CT_LABELS_MAX_SIZE);

			if (have_mask) {
				u32 *dst = (u32 *)cl->bits;
				int i;

				for (i = 0; i < 4; i++)
					dst[i] = (dst[i] & ~labels_m[i]) | (labels[i] & labels_m[i]);

				//todo: can we just replace?
			}

			/* Labels are included in the IPCTNL_MSG_CT_NEW event only if the
			 * IPCT_LABEL bit is set in the event cache.
			 */
			nf_conntrack_event_cache(IPCT_LABEL, ct);
		} else if (!!memchr_inv(labels_m, 0, sizeof(ca->labels_mask))) {
			struct nf_conn_labels *cl;

			cl = nf_ct_labels_find(ct);
			if (!cl) {
				nf_ct_labels_ext_add(ct);
				cl = nf_ct_labels_find(ct);
			}

			if (!cl)
				goto drop;

			nf_connlabels_replace(ct, ca->labels, ca->labels_mask, 4);
		}
skip:
		if (nf_conntrack_confirm(skb) != NF_ACCEPT)
			goto drop;
	}

	return ca->tcf_action;

out:
	ct_notify_underlying_device(skb, ca, NULL, IP_CT_UNTRACKED, net);
	return ca->tcf_action;

drop:
	return TC_ACT_SHOT;
}

static int tcf_conntrack(struct sk_buff *skb, const struct tc_action *a,
			 struct tcf_result *res)
{
	struct tcf_conntrack_info *orig_ca = to_conntrack(a);
	struct tcf_conntrack_info tmp_ca;
	u_int8_t family;
	int nh_ofs;
	int err;

	err = tcf_skb_network_trim(skb);
	if (err)
		return TC_ACT_SHOT;

	family = tcf_skb_family(skb);
	if (family == PF_UNSPEC)
		return TC_ACT_SHOT;

	/* TODO: temporary; should be in a different action? */
	if (orig_ca->clear) {
		tcf_ct_clear(skb);
		return orig_ca->tcf_action;
	}

	/* The conntrack module expects to be working at L3. */
	nh_ofs = skb_network_offset(skb);
	skb_pull_rcsum(skb, nh_ofs);

	spin_lock(&orig_ca->tcf_lock);
	tcf_lastuse_update(&orig_ca->tcf_tm);
	bstats_update(&orig_ca->tcf_bstats, skb);
	memcpy(&tmp_ca, orig_ca, sizeof(tmp_ca));

	if (orig_ca->tmpl)
		nf_conntrack_get(&orig_ca->tmpl->ct_general);
	spin_unlock(&orig_ca->tcf_lock);

	err = __tcf_conntrack(skb, &tmp_ca, family, a, res);

	skb_push(skb, nh_ofs);
	skb_postpush_rcsum(skb, skb->data, nh_ofs);

	return err;
}

static const struct nla_policy conntrack_policy[TCA_CONNTRACK_MAX + 1] = {
	[TCA_CONNTRACK_PARMS] = { .len = sizeof(struct tc_conntrack) },
	/* TODO: should be nested */
	/* TODO: support IPv6 */
	[TCA_CONNTRACK_NAT] = { .type = NLA_FLAG },
	[TCA_CONNTRACK_NAT_SRC] = { .type = NLA_FLAG },
	[TCA_CONNTRACK_NAT_DST] = { .type = NLA_FLAG },
	[TCA_CONNTRACK_NAT_IP_MIN] = { .type = NLA_U32 },
	[TCA_CONNTRACK_NAT_IP_MAX] = { .type = NLA_U32 },
	[TCA_CONNTRACK_NAT_PORT_MIN] = { .type = NLA_U16 },
	[TCA_CONNTRACK_NAT_PORT_MAX] = { .type = NLA_U16 },
};

static void tcf_conntrack_nat_parse(struct tcf_conntrack_info *info,
				    struct nlattr *tb[])
{
	bool have_ip_max = false;
	bool have_proto_max = false;

	if (!tb[TCA_CONNTRACK_NAT])
		return;

	info->nat |= OVS_CT_NAT;

	if (tb[TCA_CONNTRACK_NAT_SRC])
		info->nat |= OVS_CT_SRC_NAT;
	if (tb[TCA_CONNTRACK_NAT_DST])
		info->nat |= OVS_CT_DST_NAT;

	if (tb[TCA_CONNTRACK_NAT_IP_MIN]) {
		info->range.min_addr.ip = nla_get_u32(tb[TCA_CONNTRACK_NAT_IP_MIN]);
		info->range.flags |= NF_NAT_RANGE_MAP_IPS;
	}
	if (tb[TCA_CONNTRACK_NAT_IP_MAX]) {
		info->range.max_addr.ip = nla_get_u32(tb[TCA_CONNTRACK_NAT_IP_MAX]);
		info->range.flags |= NF_NAT_RANGE_MAP_IPS;
		have_ip_max = true;
	}

	if (tb[TCA_CONNTRACK_NAT_PORT_MIN]) {
		info->range.min_proto.all = htons(nla_get_u16(tb[TCA_CONNTRACK_NAT_PORT_MIN]));
		info->range.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
	}
	if (tb[TCA_CONNTRACK_NAT_PORT_MAX]) {
		info->range.max_proto.all = htons(nla_get_u16(tb[TCA_CONNTRACK_NAT_PORT_MAX]));
		info->range.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
		have_proto_max = true;
	}

	/* Allow missing IP_MAX. */
	if (info->range.flags & NF_NAT_RANGE_MAP_IPS && !have_ip_max)
		info->range.max_addr.ip = info->range.min_addr.ip;

	/* Allow missing PROTO_MAX. */
	if (info->range.flags & NF_NAT_RANGE_PROTO_SPECIFIED &&
	    !have_proto_max) {
		info->range.max_proto.all = info->range.min_proto.all;
	}
}

static int tcf_conntrack_init(struct net *net, struct nlattr *nla,
			     struct nlattr *est, struct tc_action **a,
			     int ovr, int bind, bool rtnl_held,
			     struct tcf_proto *tp,
			     struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);
	struct tcf_block *block = tp->chain->block;
	struct nlattr *tb[TCA_CONNTRACK_MAX + 1];
	struct tcf_conntrack_info *ci;
	struct tc_conntrack *parm;
	int ret = 0;
	struct nf_conntrack_zone zone;
	struct nf_conn *tmpl = NULL;

	if (!nla)
		return -EINVAL;

	ret = nla_parse_nested(tb, TCA_CONNTRACK_MAX, nla, conntrack_policy,
			       NULL);
	if (ret < 0)
		return ret;

	if (!tb[TCA_CONNTRACK_PARMS])
		return -EINVAL;

	parm = nla_data(tb[TCA_CONNTRACK_PARMS]);

	ret = tcf_idr_check_alloc(tn, &parm->index, a, bind);
	if (!ret) {
		ret = tcf_idr_create(tn, parm->index, est, a,
				     &act_conntrack_ops, bind, false);
		if (ret) {
			tcf_idr_cleanup(tn, parm->index);
			return ret;
		}

		ci = to_conntrack(*a);
		ci->tcf_action = parm->action;
		ci->net = net;
		ci->commit = parm->commit;
		ci->clear = parm->clear;

		tcf_conntrack_nat_parse(ci, tb);

		ci->zone = parm->zone;
		if (parm->zone != NF_CT_DEFAULT_ZONE_ID) {
			nf_ct_zone_init(&zone, parm->zone,
							NF_CT_DEFAULT_ZONE_DIR, 0);

			tmpl = nf_ct_tmpl_alloc(net, &zone, GFP_ATOMIC);
			if (!tmpl) {
				pr_debug("Failed to allocate conntrack template");
				tcf_idr_cleanup(tn, parm->index);
				return -ENOMEM;
			}
			__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
			nf_conntrack_get(&tmpl->ct_general);
		}

		ci->tmpl = tmpl;
		ci->mark = parm->mark;
		ci->mark_mask = parm->mark_mask;
		ci->block = block;
		memcpy(ci->labels, parm->labels, sizeof(parm->labels));
		memcpy(ci->labels_mask, parm->labels_mask, sizeof(parm->labels_mask));

		tcf_idr_insert(tn, *a);
		ret = ACT_P_CREATED;
	} else if (ret > 0) {
		if (bind)
			return 0;

		if (!ovr) {
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}

		if (parm->zone != NF_CT_DEFAULT_ZONE_ID) {
			nf_ct_zone_init(&zone, parm->zone,
							NF_CT_DEFAULT_ZONE_DIR, 0);

			tmpl = nf_ct_tmpl_alloc(net, &zone, GFP_ATOMIC);
			if (!tmpl) {
				pr_debug("Failed to allocate conntrack template");
				return -ENOMEM;
			}
		}

		/* replacing action and zone */
		ci = to_conntrack(*a);
		spin_lock_bh(&ci->tcf_lock);
		ci->tcf_action = parm->action;
		ci->zone = parm->zone;
		swap(ci->tmpl, tmpl);
		spin_unlock_bh(&ci->tcf_lock);

		if (tmpl) {
			nf_conntrack_put(&tmpl->ct_general);
		}

		ret = 0;
	}

	return ret;
}

static void tcf_conntrack_release(struct tc_action *a)
{
	struct tcf_conntrack_info *ci = to_conntrack(a);
	struct nf_conn *tmpl = NULL;

	spin_lock_bh(&ci->tcf_lock);
	if (ci->tmpl) {
		swap(ci->tmpl, tmpl);
	}
	spin_unlock_bh(&ci->tcf_lock);

	if (tmpl) {
		nf_conntrack_put(&tmpl->ct_general);
	}
}

static int tcf_conntrack_dump_nat(struct sk_buff *skb,
				  struct tcf_conntrack_info *info)
{
	int err;

	if (!info->nat)
		return 0;

	err = nla_put_flag(skb, TCA_CONNTRACK_NAT);
	if (err)
		goto nla_put_failure;

	if (info->nat & OVS_CT_SRC_NAT) {
		err = nla_put_flag(skb, TCA_CONNTRACK_NAT_SRC);
		if (err)
			goto nla_put_failure;
	}

	if (info->nat & OVS_CT_DST_NAT) {
		err = nla_put_flag(skb, TCA_CONNTRACK_NAT_DST);
		if (err)
			goto nla_put_failure;
	}

	if (info->range.flags & NF_NAT_RANGE_MAP_IPS) {
		err = nla_put_be32(skb, TCA_CONNTRACK_NAT_IP_MIN,
				   info->range.min_addr.ip);
		if (err)
			goto nla_put_failure;

		err = nla_put_be32(skb, TCA_CONNTRACK_NAT_IP_MAX,
				   info->range.max_addr.ip);
		if (err)
			goto nla_put_failure;
	}

	if (info->range.flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		err = nla_put_be16(skb, TCA_CONNTRACK_NAT_PORT_MIN,
				   info->range.min_proto.all);
		if (err)
			goto nla_put_failure;

		err = nla_put_be16(skb, TCA_CONNTRACK_NAT_PORT_MAX,
				   info->range.max_proto.all);
		if (err)
			goto nla_put_failure;
	}

nla_put_failure:
	return err;
}

static inline int tcf_conntrack_dump(struct sk_buff *skb, struct tc_action *a,
				    int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_conntrack_info *ci = to_conntrack(a);

	struct tc_conntrack opt = {
		.index   = ci->tcf_index,
		.refcnt  = refcount_read(&ci->tcf_refcnt) - ref,
		.bindcnt = atomic_read(&ci->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

 	spin_lock_bh(&ci->tcf_lock);
	opt.action  = ci->tcf_action,
	opt.zone   = ci->zone,
	opt.commit = ci->commit,
	opt.clear = ci->clear,
	opt.mark = ci->mark,
	opt.mark_mask = ci->mark_mask,

 	memcpy(opt.labels, ci->labels, sizeof(opt.labels));
	memcpy(opt.labels_mask, ci->labels_mask, sizeof(opt.labels_mask));

	if (nla_put(skb, TCA_CONNTRACK_PARMS, sizeof(opt), &opt))
		goto nla_put_failure;

	if (tcf_conntrack_dump_nat(skb, ci))
		goto nla_put_failure;

	tcf_tm_dump(&t, &ci->tcf_tm);
	if (nla_put_64bit(skb, TCA_CONNTRACK_TM, sizeof(t), &t,
			  TCA_CONNTRACK_PAD))
		goto nla_put_failure;
	spin_unlock_bh(&ci->tcf_lock);

	return skb->len;
nla_put_failure:
	spin_unlock_bh(&ci->tcf_lock);
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_conntrack_walker(struct net *net, struct sk_buff *skb,
			       struct netlink_callback *cb, int type,
			       const struct tc_action_ops *ops,
			       struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_conntrack_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tcf_idr_search(tn, a, index);
}

static struct tc_action_ops act_conntrack_ops = {
	.kind		=	"ct",
	.id		=	TCA_ACT_CONNTRACK,
	.owner		=	THIS_MODULE,
	.act		=	tcf_conntrack,
	.dump		=	tcf_conntrack_dump,
	.init		=	tcf_conntrack_init,
	.cleanup	=	tcf_conntrack_release,
	.walk		=	tcf_conntrack_walker,
	.lookup		=	tcf_conntrack_search,
	.size		=	sizeof(struct tcf_conntrack_info),
};

static __net_init int conntrack_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, conntrack_net_id);

	return tc_action_net_init(net, tn, &act_conntrack_ops);
}

static void __net_exit conntrack_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, conntrack_net_id);
}

static struct pernet_operations conntrack_net_ops = {
	.init = conntrack_init_net,
	.exit_batch = conntrack_exit_net,
	.id   = &conntrack_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init conntrack_init_module(void)
{
	return tcf_register_action(&act_conntrack_ops, &conntrack_net_ops);
}

static void __exit conntrack_cleanup_module(void)
{
	tcf_unregister_action(&act_conntrack_ops, &conntrack_net_ops);
}

module_init(conntrack_init_module);
module_exit(conntrack_cleanup_module);
MODULE_AUTHOR("Yossi Kuperman <yossiku@mellanox.com>");
MODULE_DESCRIPTION("Connection tracking action");
MODULE_LICENSE("GPL");

