/* SPDX-License-Identifier: GPL-2.0-only */
/* CPU virtualization extensions handling */
#ifndef _ASM_X86_VIRTEX_H
#define _ASM_X86_VIRTEX_H

#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/vmx.h>

/*
 * cpu_vmxon() - Enable VMX on the current CPU
 *
 * Set CR4.VMXE and enable VMX
 */
static inline int cpu_vmxon(u64 vmxon_pointer)
{
	u64 msr;

	cr4_set_bits(X86_CR4_VMXE);

	asm goto("1: vmxon %[vmxon_pointer]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : : [vmxon_pointer] "m"(vmxon_pointer)
			  : : fault);
	return 0;

fault:
	WARN_ONCE(1, "VMXON faulted, MSR_IA32_FEAT_CTL (0x3a) = 0x%llx\n",
		  rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ? 0xdeadbeef : msr);
	cr4_clear_bits(X86_CR4_VMXE);

	return -EFAULT;
}

/*
 * Disable VMX and clear CR4.VMXE (even if VMXOFF faults)
 *
 * Note, VMXOFF causes a #UD if the CPU is !post-VMXON, but it's impossible to
 * atomically track post-VMXON state, e.g. this may be called in NMI context.
 * Eat all faults as all other faults on VMXOFF faults are mode related, i.e.
 * faults are guaranteed to be due to the !post-VMXON check unless the CPU is
 * magically in RM, VM86, compat mode, or at CPL>0.
 */
static inline int cpu_vmxoff(void)
{
	asm goto("1: vmxoff\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  ::: "cc", "memory" : fault);

	cr4_clear_bits(X86_CR4_VMXE);
	return 0;

fault:
	cr4_clear_bits(X86_CR4_VMXE);
	return -EIO;
}

static inline int cpu_vmcs_load(u64 vmcs_pa)
{
	asm goto("1: vmptrld %0\n\t"
			  ".byte 0x2e\n\t" /* branch not taken hint */
			  "jna %l[error]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : : "m" (vmcs_pa) : "cc" : error, fault);
	return 0;

error:
	pr_err("vmptrld failed: %llx\n", vmcs_pa);
	return -EIO;
fault:
	pr_err("vmptrld faulted\n");
	return -EIO;
}

static inline int cpu_vmcs_store(u64 *vmcs_pa)
{
	int ret = -EIO;

	asm volatile("1: vmptrst %0\n\t"
		     "mov $0, %1\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE(1b, 2b)
		     : "=m" (*vmcs_pa), "+r" (ret) : :);

	if (ret)
		pr_err("vmptrst faulted\n");

	return ret;
}

#endif /* _ASM_X86_VIRTEX_H */
