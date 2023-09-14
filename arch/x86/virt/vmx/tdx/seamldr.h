/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _X86_VIRT_SEAMLDR_H
#define _X86_VIRT_SEAMLDR_H

/*
 * SEAMLDR SEAMCALL error codes
 */
#define SEAMLDR_BADCALL			0x8000000000000003ULL
#define SEAMLDR_RND_NO_ENTROPY		0x8000000000030001ULL

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

/*
 * TDX module's signature structure, which provides metadata
 * information about the module.
 */
struct seam_sigstruct {
	u32		header_type;
	u32		header_length;
	u32		header_version;
	u32		module_type;
	u32		module_vendor;
	u32		date;
	u32		size;
	u32		key_size;
	u32		module_size;
	u32		exponent_size;
	u8		reserved[88];
	u8		modulus[384];
	u32		exponent;
	u8		signature[384];
	u8		seamhash[48];
	u16		seamsvn;
	u64		attributes;
	u32		rip_offset;
	u8		num_stack_pages;
	u8		num_tls_pages;
	u16		num_keyhole_pgs;
	u16		min_glb_data_pages;
	u16		max_tdmrs;
	u16		max_reserved_per_tdmr;
	u16		pamt_entry_size_4K;
	u16		pamt_entry_size_2M;
	u16		pamt_entry_size_1G;
	u8		reserved2[6];
	u16		module_hv;
	u16		min_update_hv;
	u8		no_downgrade;
	u8		reserved3;
	u16		num_handoff_pages;
	u8		reserved4[32];
	u32		cpuid_table_size;
	u8		cpuid_table[1020];
} __packed;

struct tee_tcb_svn {
	u16	seamsvn;
	u8	reserved[14];
} __packed;

struct __tee_tcb_info {
	u64			valid;
	struct tee_tcb_svn	tcb_svn;
	u8			mrseam[48];
	u8			mrsignerseam[48];
	u64			attributes;
} __packed;

#define P_SEAMLDR_INFO_ALIGNMENT	256

struct p_seamldr_info {
	u32	version;
	u32	attributes;
	u32	vendor_id;
	u32	build_date;
	u16	build_num;
	u16	minor;
	u16	major;
	u8	reserved0[2];
	u32	acm_x2apicid;
	u32	num_remaining_updates;
	struct __tee_tcb_info tcb_info;
	u8	seam_ready;
	u8	seam_debug;
	u8	p_seamldr_ready;
	u8	reserved2[88];
} __packed __aligned(P_SEAMLDR_INFO_ALIGNMENT);

/* P-SEAMLDR SEAMCALL leaf function */
#define P_SEAMLDR_SEAMCALL_BASE		BIT_ULL(63)
#define P_SEAMLDR_INFO			(P_SEAMLDR_SEAMCALL_BASE | 0x0)
#define P_SEAMLDR_INSTALL		(P_SEAMLDR_SEAMCALL_BASE | 0x1)

/* FIXME: Update the leaf number */
#define P_SEAMLDR_OFFLINE		(P_SEAMLDR_SEAMCALL_BASE | 0xF0)

#ifdef CONFIG_INTEL_TDX_MODULE_UPDATE
int seamldr_flush_vmcs(void);
int tdx_module_update(void);
#else  /* !CONFIG_INTEL_TDX_MODULE_UPDATE */
static inline int seamldr_flush_vmcs(void) { return 0; }
static inline int tdx_module_update(void) { return 0; }
int tdx_module_update(void);
#endif /* CONFIG_INTEL_TDX_MODULE_UPDATE */
#endif
