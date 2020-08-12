/* SPDX-License-Identifier: GPL-2.0 */
/* TOT		An implementation of the TCP SKB Trace Option
 *		suite for the LINUX operating system.
 *
 *		Definitions for the TCP SKB Trace Option.
 *
 * Version:	@(#)tcp_skb_trace.h   1.0.0   16/07/2020
 *
 * Author:	YinFeng.Zhu <zhuyinfeng01@bytedance.com>
 *
 *
 * TOT-Format:
 *
 *	Kind           Len
 *	+-------------+-------------+---------------+---------------+
 *	|    fb       |     1c      |       ctx     |      age      |
 *	+-------------+-------------+---------------+---------------+
 *	|   sk_state  |   ca_state  |  icsk_pending |    syscalls   |
 *	+-------------+-------------+---------------+---------------+
 *	|  reordering | retransmits |          send_elapsed         |
 *	+-------------+-------------+---------------+---------------+
 *	|            srtt           |            min_rtt            |
 *	+-------------+-------------+---------------+---------------+
 *	|          snd_cwnd         |          pkts_in_flight       |
 *	+-------------+-------------+---------------+---------------+
 *	|         pacing_rate       |          snd_ssthresh         |
 *	+-------------+-------------+---------------+---------------+
 *	|          icsk_rto         |        write_queue_qlen       |
 *	+-------------+-------------+---------------+---------------+
 *	|<---                   28 bytes                        --->|
 *
 *	*Note
 *
 *	Kind:            fb     # 251, a reserved kind in rfc793, we use it.
 *	Length:          1c     # 28, skb trace option size
 *	ctx:             **     # skb debug info, packet path or logic etc
 *	age:             **     # sk_buff age, init 0, +1 when send/retrans
 *	sk_state:        **     # connection state
 *	ca_state:        **     # congestion control state
 *	icsk_pending:    **     # scheduled timer event
 *	syscalls:        **     # socket send or write syscall count
 *	reordering:      **     # packet reordering metric
 *	retransmits:     **     # number of unrecovered [RTO] timeouts
 *	send_elapsed:    **     # time elapsed in jiffies from socket syscall
 *	srtt:            **     # smoothed round trip time << 3 in msecs
 *	min_rtt:         **     # min rtt
 *	snd_cwnd:        **     # sending congestion window
 *	pkts_in_flight:  **     # determines how many packets are "in network"
 *	pacing rate:     **     # pacing rate in KB/s
 *	snd_ssthresh:    **     # slow start size threshold
 *	icsk_rto:        **     # retransmit timeout
 *	write_queue_qlen:**     # struct sk_buff_head qlen
 *
 */
#ifndef _TCP_SKB_TRACE_H
#define _TCP_SKB_TRACE_H

extern int sysctl_tcp_trace_opt;

enum tcp_trace_opt_ctx {
	TCP_TRACE_OPT_CTX_INIT = 1,
	TCP_TRACE_OPT_CTX_TCP_SENDMSG,
	TCP_TRACE_OPT_CTX_DO_TCP_SENDPAGES,
	TCP_TRACE_OPT_CTX_DO_TCP_SETSOCKOPT_NODELAY,
	TCP_TRACE_OPT_CTX_DO_TCP_SETSOCKOPT_CORK,
	TCP_TRACE_OPT_CTX_TCP_DATA_SND_CHECK,
	TCP_TRACE_OPT_CTX_TCP_PACING_TIMER,
	TCP_TRACE_OPT_CTX_TCP_SIMPLE_RETRANSMIT,
	TCP_TRACE_OPT_CTX_TCP_FASTRETRANS_ALERT,
	TCP_TRACE_OPT_CTX_TCP_PROCESS_LOSS_FRTO,
	TCP_TRACE_OPT_CTX_TCP_REO_TIMEOUT,
	TCP_TRACE_OPT_CTX_TCP_SEND_LOSS_PROBE,
	TCP_TRACE_OPT_CTX_TCP_RETRANSMIT_TIMER,
	TCP_TRACE_OPT_CTX_TCP_PROBE_TIMER,
	TCP_TRACE_OPT_CTX_TCP_KEEPALIVE_TIMER,
	TCP_TRACE_OPT_CTX_TCP_SHUTDOWN,
	TCP_TRACE_OPT_CTX_TCP_CLOSE,
	TCP_TRACE_OPT_CTX_TCP_WFREE,
	TCP_TRACE_OPT_CTX_TCP_TASKLET_FUNC,
	TCP_TRACE_OPT_CTX_TCP_RELEASE_CB,
	TCP_TRACE_OPT_CTX_TCP_DELACK_TIMER_HANDLER,
	TCP_TRACE_OPT_CTX_MAX,
};

struct tcp_trace_opt_info {
	u8	tcp_trace_opt_ctx;
	u8	tcp_trace_opt_retrans;
	u8	tcp_trace_opt_skc_state;
	u8	tcp_trace_opt_icsk_ca_state;
	u8	tcp_trace_opt_icsk_pending;
	u8	tcp_trace_opt_calls;
	u8	tcp_trace_opt_reordering;
	u8	tcp_trace_opt_icsk_retransmits;
	u16	tcp_trace_opt_elapsed;
	u16	tcp_trace_opt_srtt;
	u16	tcp_trace_opt_minrtt;
	u16	tcp_trace_opt_snd_cwnd;
	u16	tcp_trace_opt_pkts_in_flight;
	u16	tcp_trace_opt_pacing_rate;
	u16	tcp_trace_opt_snd_ssthresh;
	u16	tcp_trace_opt_icsk_rto;
	u16	tcp_trace_opt_sk_write_queue_qlen;
};

static inline u8 tcp_set_trace_opt_ctx(struct sock *sk, const u8 ctx)
{
	if (unlikely(sysctl_tcp_trace_opt)) {
		struct tcp_sock *tp = tcp_sk(sk);
		u8 old_ctx = tp->trace_opt.tcp_trace_opt_ctx;

		tp->trace_opt.tcp_trace_opt_ctx = ctx;
		return old_ctx;
	} else {
		return 0;
	}
}

#endif /* _TCP_SKB_TRACE_H */
