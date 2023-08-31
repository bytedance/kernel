/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_SEAMLDR_H
#define _X86_VIRT_SEAMLDR_H

#define SEAMLDR_MAX_NR_MODULE_PAGES	496

#define SEAMLDR_SIGSTRUCT_SIZE		2048

/* Load Intel TDX module */
#define SEAMLDR_SCENARIO_LOAD		0
/* Update previously loaded Intel TDX module to the same or another one */
#define SEAMLDR_SCENARIO_UPDATE		1

/* Passed to P-SEAMLDR to describe information about the TDX module to install */
struct seamldr_params {
	u32	version;
	u32	scenario; /* SEAMLDR_SCENARIO_LOAD/UPDATE */
	u64	sigstruct_pa;
	u8	reserved[104];
	u64	num_module_pages;
	u64	mod_pages_pa_list[SEAMLDR_MAX_NR_MODULE_PAGES];
} __packed;

#endif
