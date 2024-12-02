/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_DELAY_CONST_H
#define _ASM_DELAY_CONST_H

#include <asm/param.h>	/* For HZ */

/* 2**32 / 1000000000 (rounded up) */
#define __nsecs_to_xloops_mult	0x5UL

extern unsigned long loops_per_jiffy;

#define NSECS_TO_CYCLES(time_nsecs) \
	((((time_nsecs) * __nsecs_to_xloops_mult) * loops_per_jiffy * HZ) >> 32)

#endif	/* _ASM_DELAY_CONST_H */
