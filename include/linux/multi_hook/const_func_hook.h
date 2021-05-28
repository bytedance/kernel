/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Bytedance, Inc. All rights reserved.
 *
 * Authors: Qianyu Zhang <zhangqianyu.sys@bytedance.com>
 *
 * the const_func_hook provide the ability to change a const function pointer.
 */

#ifndef CONST_FUNC_HOOK_H
#define CONST_FUNC_HOOK_H


int const_func_hook(unsigned long func_addr, unsigned long new_func,
		unsigned long *old_func_p,
		unsigned long *mapped_func_addr_p);

void const_func_unhook(unsigned long mapped_func_addr, unsigned long old_func);

#endif /* CONST_FUNC_HOOK_H */
