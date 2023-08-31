// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Intel Corporation.
 *
 * Generic VMX support.
 */
#undef pr_fmt
#define pr_fmt(fmt) "x86/virt/vmx: " fmt

#include <linux/cpumask.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <asm/cpufeatures.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/perf_event.h>
#include <asm/tlbflush.h>
#include <asm/tdx.h>

DEFINE_PER_CPU(u64, vmx_basic);
EXPORT_PER_CPU_SYMBOL_GPL(vmx_basic);

static DEFINE_PER_CPU(struct vmcs *, vmxon_region);
static DEFINE_PER_CPU(int, vmxop_count);

static bool vmx_basic_valid(u64 _vmx_basic)
{
	/* ia-32 sdm vol 3b: vmcs size is never greater than 4kb. */
	if (vmx_basic_vmcs_size(_vmx_basic) > PAGE_SIZE)
		return false;

#ifdef CONFIG_X86_64
	/* ia-32 sdm vol 3b: 64-bit cpus always have vmx_basic_msr[48]==0. */
	if (_vmx_basic & VMX_BASIC_64)
		return false;
#endif

	/*
	 * KVM requires write-back (wb) memory type for vmcs accesses.
	 * no reason not to make it unversial.
	 */
	if (((_vmx_basic & VMX_BASIC_MEM_TYPE_MASK) >> VMX_BASIC_MEM_TYPE_SHIFT)
			!= VMX_BASIC_MEM_TYPE_WB)
		return false;

	return true;
}

static void prepare_vmxon_region(struct cpuinfo_x86 *c)
{
	struct vmcs *_vmxon_region;
	struct page *page;
	u64 _vmx_basic;
	int cpu;

	cpu = smp_processor_id();
	WARN_ON_ONCE(cpu != c->cpu_index);

	/*
	 * Need to clear both per-cpu @vmx_basic and @vmxon_region when
	 * VMX is not supported.  This is done when the cpu goes offline.
	 * Just need to return here.
	 */
	if (!cpu_has(c, X86_FEATURE_VMX))
		return;

	rdmsrl(MSR_IA32_VMX_BASIC, _vmx_basic);

	if (!vmx_basic_valid(_vmx_basic)) {
		pr_err("CPU %d: invalid MSR_IA32_VMX_BASIC: 0x%llx\n", cpu,
				_vmx_basic);
		return;
	}

	page = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL | __GFP_ZERO, 0);
	if (!page) {
		pr_err("CPU %d: failed to allocate VMXON region.\n", cpu);
		return;
	}

	_vmxon_region = page_address(page);

	/* VMXON requires 'revision_id' being set to the VMXON region */
	_vmxon_region->hdr.revision_id = vmx_basic_vmcs_revision_id(_vmx_basic);

	/*
	 * Only set per-cpu @vmx_basic when VMXON region is ready, so
	 * that user of VMX (i.e. KVM) can just use it (exposed as
	 * symbol) to see whether VMXON region is ready, but doesn't
	 * need to check @vmxon_region.
	 */
	this_cpu_write(vmx_basic, _vmx_basic);
	this_cpu_write(vmxon_region, _vmxon_region);
}

static int vmx_cpu_startup(unsigned int cpu)
{
	struct cpuinfo_x86 *c = &cpu_data(cpu);

	prepare_vmxon_region(c);

	return 0;
}

static int vmx_cpu_teardown(unsigned int cpu)
{
	struct vmcs *_vmxon_region = this_cpu_read(vmxon_region);

	if (_vmxon_region) {
		free_page((unsigned long)_vmxon_region);
		this_cpu_write(vmxon_region, NULL);
	}

	this_cpu_write(vmx_basic, 0);

	return 0;
}

static int __init vmx_early_init(void)
{
	prepare_vmxon_region(&boot_cpu_data);

	if (cpuhp_setup_state_nocalls(CPUHP_AP_X86_INTEL_VMX_ONLINE,
			"x86/vmx:online", vmx_cpu_startup, vmx_cpu_teardown))
		pr_err("failed to register CPU hotplug callback.\n");

	tdx_init();
	return 0;
}
early_initcall(vmx_early_init);

/*
 * Enable VMX and enter VMX operation on local cpu if it is not in VMX
 * operation using a reference count.
 *
 * This function must be called when preemption is not possible on
 * local cpu.  It is IRQ safe and can be called from remote cpu via IPI.
 */
int cpu_vmxop_get(void)
{
	struct vmcs *_vmxon_region;
	unsigned long rflags;
	int count, ret = 0;

	/*
	 * Use __this_cpu_read() to catch error in case the caller
	 * didn't call it when preemption is impossible.
	 */
	_vmxon_region = __this_cpu_read(vmxon_region);
	if (!_vmxon_region)
		return -EOPNOTSUPP;

	/* Disable IRQ to prevent race against @vmxop_count */
	local_irq_save(rflags);

	count = this_cpu_read(vmxop_count) + 1;

	/* Overflow */
	if (WARN_ON_ONCE(count < 0)) {
		ret = -EINVAL;
		goto out;
	}

	/* Already done */
	if (count > 1)
		goto update;

	/* No other code should set X86_CR4_VMXE bit */
	if (WARN_ON_ONCE(cr4_read_shadow() & X86_CR4_VMXE)) {
		ret = -EBUSY;
		goto out;
	}

	/* On some processor PT may not play nice with VMX */
	intel_pt_handle_vmx(1);

	ret = cpu_vmxon(__pa(_vmxon_region));
	if (ret)  {
		intel_pt_handle_vmx(0);
		goto out;
	}

update:
	/* Successfully done.  Increase the count. */
	this_cpu_write(vmxop_count, count);
out:
	local_irq_restore(rflags);
	return ret;
}
EXPORT_SYMBOL_GPL(cpu_vmxop_get);

/*
 * Leave VMX operation and disable VMX on local cpu when the reference
 * count reaches 0.
 *
 * This function must be called when preemption is not possible on
 * local cpu.  It is IRQ safe and can be called from remote cpu via IPI.
 */
int cpu_vmxop_put(void)
{
	unsigned long rflags;
	int count, ret = 0;

	/*
	 * cpu_vmxop_put() shouldn't be called w/o having
	 * successfully called cpu_vmxop_get().
	 */
	if (WARN_ON_ONCE(!__this_cpu_read(vmxon_region)))
		return -ENODEV;

	local_irq_save(rflags);

	count = this_cpu_read(vmxop_count) - 1;

	/* No matching cpu_vmxop_get() is called */
	if (WARN_ON_ONCE(count < 0)) {
		ret = -EINVAL;
		goto out;
	}

	/* Still has user */
	if (count > 0)
		goto update;

	ret = cpu_vmxoff();

	intel_pt_handle_vmx(0);

update:
	this_cpu_write(vmxop_count, count);
out:
	local_irq_restore(rflags);
	return ret;
}
EXPORT_SYMBOL_GPL(cpu_vmxop_put);

static void __cpu_vmxop_get(void *cpus)
{
	if (!cpu_vmxop_get())
		cpumask_set_cpu(smp_processor_id(), cpus);
}

static void __cpu_vmxop_put(void *cpus)
{
	if (!cpu_vmxop_put())
		cpumask_clear_cpu(smp_processor_id(), cpus);
}

/*
 * Enable VMX and enter VMX operation on all online CPUs
 *
 * Cpu hotplug must have been disabled. This requirement is to ensure the
 * cpu_vmxop_get_all() and cpu_vmxop_put_all() are called on the same set of
 * CPUs to keep the ref-counting balanced.
 *
 * Return 0 on success, otherwise an error.
 */
int cpu_vmxop_get_all(void)
{
	cpumask_var_t cpus;
	int ret = 0;

	lockdep_assert_cpus_held();

	if (!zalloc_cpumask_var(&cpus, GFP_KERNEL))
		return -ENOMEM;

	on_each_cpu(__cpu_vmxop_get, cpus, 1);

	if (!cpumask_equal(cpus, cpu_online_mask)) {
		on_each_cpu_mask(cpus, __cpu_vmxop_put, cpus, 1);
		/*
		 * Cannot revert what has been done. There is no way out.
		 * Just emit an error message.
		 */
		if (unlikely(!cpumask_empty(cpus)))
			pr_err_once("CPUs failed to put VMX: %*pbl\n",
				    cpumask_pr_args(cpus));
		ret = -EIO;
	}
	free_cpumask_var(cpus);

	return ret;
}
EXPORT_SYMBOL_GPL(cpu_vmxop_get_all);

/*
 * Leave VMX operation and disable VMX on all online CPUs
 *
 * Like cpu_vmxop_get_all(), this function must be called with cpu hotplug
 * disabled.
 *
 * Return 0 on success, otherwise an error.
 */
int cpu_vmxop_put_all(void)
{
	int ret = 0;
	cpumask_var_t cpus;

	lockdep_assert_cpus_held();

	if (!zalloc_cpumask_var(&cpus, GFP_KERNEL))
		return -ENOMEM;

	cpumask_copy(cpus, cpu_online_mask);
	on_each_cpu(__cpu_vmxop_put, cpus, 1);

	if (unlikely(!cpumask_empty(cpus)))
		ret = -EIO;
	free_cpumask_var(cpus);

	return ret;
}
EXPORT_SYMBOL_GPL(cpu_vmxop_put_all);
