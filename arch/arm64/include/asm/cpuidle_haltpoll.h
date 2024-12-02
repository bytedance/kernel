/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ARCH_HALTPOLL_H
#define _ARCH_HALTPOLL_H

static inline void arch_haltpoll_enable(unsigned int cpu) { }
static inline void arch_haltpoll_disable(unsigned int cpu) { }

static inline bool arch_haltpoll_want(bool force)
{
	/*
	 * Enabling haltpoll requires KVM support for arch_haltpoll_enable(),
	 * arch_haltpoll_disable().
	 *
	 * Given that that's missing right now, only allow force loading for
	 * haltpoll.
	 */
	return force;
}
#endif
