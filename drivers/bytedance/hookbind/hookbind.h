/* SPDX-License-Identifier: GPL-2.0 */
int register_hookbind(void);
void unregister_hookbind(void);
ssize_t dump_dmesg(void);
ssize_t add_new_rule(const char __user *, size_t );
