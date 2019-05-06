/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __UAPI_TC_CT_H
#define __UAPI_TC_CT_H

#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

#define TCA_ACT_CONNTRACK 18

struct tc_conntrack {
	tc_gen;
	__u16 zone;
	__u32 labels[4];
	__u32 labels_mask[4];
	__u32 mark;
	__u32 mark_mask;
	bool commit;
	bool clear;
};

enum {
	TCA_CONNTRACK_UNSPEC,
	TCA_CONNTRACK_PARMS,

	TCA_CONNTRACK_NAT,
	TCA_CONNTRACK_NAT_SRC,
	TCA_CONNTRACK_NAT_DST,
	TCA_CONNTRACK_NAT_IP_MIN,
	TCA_CONNTRACK_NAT_IP_MAX,
	TCA_CONNTRACK_NAT_PORT_MIN,
	TCA_CONNTRACK_NAT_PORT_MAX,

	TCA_CONNTRACK_TM,
	TCA_CONNTRACK_PAD,
	__TCA_CONNTRACK_MAX
};
#define TCA_CONNTRACK_MAX (__TCA_CONNTRACK_MAX - 1)

#endif /* __UAPI_TC_CT_H */
