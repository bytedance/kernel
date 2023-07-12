// SPDX-License-Identifier: GPL-2.0+
/*
 * Driver for ACPI NMI device
 */
#define pr_fmt(fmt) "ACPI NMI: " fmt

#include <linux/nmi.h>
#include <linux/arm_sdei.h>
#include <linux/platform_device.h>
#include <asm/irq_regs.h>
#include <linux/sched/debug.h>
#include <linux/irq_work.h>
#include <linux/workqueue.h>
#include <linux/mm.h>

#define INVALID_SDEI_NUM 0x80000000
/* The _DSM for SDEI signaling uses a GUID of:
 * e83a4698-e3a0-11eb-ba80-0242ac130004
 */
#define SDEI_DSM_GUID						\
	GUID_INIT(0xe83a4698, 0xe3a0, 0x11eb, 0xba, 0x80, 0x02, 0x42,	\
		  0xac, 0x13, 0x00, 0x04)

static int panic_on_acpi_nmi;
static int showmem_on_acpi_nmi = 1;
static int showcpus_on_acpi_nmi = 1;

static const int revision_id;
static const int function_index = 1;
static u32 registered_event_num;
static struct irq_work dump_irq_work;
/* Fallback when NMI is not supported */
struct work_struct show_cpus_work;

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
static struct ctl_table acpi_nmi_table[] = {
	{
		.procname	= "panic_enable",
		.data		= &panic_on_acpi_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "show_mem_usage_enable",
		.data		= &showmem_on_acpi_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "show_allcpus_backtrace_enable",
		.data		= &showcpus_on_acpi_nmi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{ }
};

static struct ctl_table_header *hdr;
static int register_nmi_sysctls(void)
{
	if (!hdr) {
		hdr = register_sysctl("fs/acpi_nmi", acpi_nmi_table);
		if (!hdr)
			return -ENOMEM;
	}
	return 0;
}

static void unregister_nmi_sysctls(void)
{
	if (hdr)
		unregister_sysctl_table(hdr);
	hdr = NULL;
}

#else
static int register_nmi_sysctls(void) { return 0; }
static void unregister_nmi_sysctls(void) {}
#endif

static int sdei_callback(u32 event_num, struct pt_regs *regs,
				      void *arg)
{
	pr_debug("SDEI callback\n");
	irq_work_queue(&dump_irq_work);
	return 0;
}

static int register_sdei_event(int event_num)
{
	int err;

	if (event_num == 0) {
		/*
		 * Event 0 is reserved by the specification for
		 * SDEI_EVENT_SIGNAL.
		 */
		return -EINVAL;
	}

	err = sdei_event_register(event_num, sdei_callback, NULL);
	if (!err)
		err = sdei_event_enable(event_num);

	return err;

}

static void show_all_cpus(void)
{
	/*
	 * Fall back to the workqueue based printing if the
	 * backtrace printing did not succeed or the
	 * architecture has no support for it:
	 */
	if (!trigger_all_cpu_backtrace()) {
		struct pt_regs *regs = NULL;
		int cpu;

		preempt_disable();
		cpu = smp_processor_id();
		preempt_enable();

		if (idle_cpu(cpu)) {
			pr_info("CPU%d: backtrace skipped as idling\n", cpu);
			return;
		}

		if (in_irq())
			regs = get_irq_regs();

		pr_info("CPU%d:\n", cpu);
		if (regs)
			show_regs(regs);
		else
			show_stack(NULL, NULL, KERN_DEFAULT);

		queue_work(system_highpri_wq, &show_cpus_work);
	}
}

static void show_memory(void)
{
	show_mem();
}

static void dump_in_irq(struct irq_work *irq_work)
{
	pr_info("Start dumping, triggered by BMC");
	if (showmem_on_acpi_nmi)
		show_memory();

	if (showcpus_on_acpi_nmi)
		show_all_cpus();

	if (panic_on_acpi_nmi) {
		pr_info("Panic triggered by BMC");
		panic("ACPI NMI");
	}
}

static DEFINE_RAW_SPINLOCK(show_lock);

static void showacpu(void *dummy)
{
	unsigned long flags;

	/* Idle CPUs have no interesting backtrace. */
	if (idle_cpu(smp_processor_id())) {
		pr_info("CPU%d: backtrace skipped as idling\n", smp_processor_id());
		return;
	}

	raw_spin_lock_irqsave(&show_lock, flags);
	pr_info("CPU%d:\n", smp_processor_id());
	show_stack(NULL, NULL, KERN_DEFAULT);
	raw_spin_unlock_irqrestore(&show_lock, flags);
}

static void showcpus_fb(struct work_struct *work)
{
	smp_call_function(showacpu, NULL, 0);
}

static void init_work_queue(void)
{
	init_irq_work(&dump_irq_work, dump_in_irq);
	INIT_WORK(&show_cpus_work, showcpus_fb);

}

static int acpi_nmi_probe(struct platform_device *pdev)
{
	union acpi_object *obj;
	int err;
	unsigned char i;
	union acpi_object obj_arg;
	union acpi_object argv4 = ACPI_INIT_DSM_ARGV4(1, &obj_arg);

	obj_arg.type = ACPI_TYPE_INTEGER;
	obj_arg.integer.value = 0;

	/*
	 * Evaluate _DSM Function.
	 */
	obj = acpi_evaluate_dsm_typed(ACPI_HANDLE(&pdev->dev), &SDEI_DSM_GUID, revision_id,
				function_index, &argv4, ACPI_TYPE_INTEGER);

	pr_debug("dsm_uuid_array: ");
	for (i = 0; i < UUID_SIZE; i++)
		pr_debug(" %02x", SDEI_DSM_GUID.b[i]);

	pr_debug("\ndsm_args: rev %d, func %d\n", revision_id, function_index);

	if (obj && obj->integer.value != INVALID_SDEI_NUM)
		err = register_sdei_event(obj->integer.value);
	else {
		pr_info("failed get sdei num\n");
		return -EINVAL;
	}

	init_work_queue();

	if (!err) {
		registered_event_num = obj->integer.value;
		pr_debug("registered sdei num: %d\n", registered_event_num);
		err = register_nmi_sysctls();
		if (err) {
			pr_err("failed to register sysctl interface, err %d\n", err);
			sdei_event_unregister(registered_event_num);
			registered_event_num = 0;
		}
	} else {
		pr_info("failed register sdei num, err %d\n", err);
	}
	ACPI_FREE(obj);

	return err;

}

static int acpi_nmi_remove(struct platform_device *pdev)
{
	unregister_nmi_sysctls();
	return sdei_event_unregister(registered_event_num);
}

static const struct acpi_device_id acpi_nmi_match[] = {
	{ "NMI0001", 0 },
	{},
};

static struct platform_driver acpi_nmi_platform_driver = {
	.probe		= acpi_nmi_probe,
	.remove		= acpi_nmi_remove,
	.driver	= {
		.name	= "acpi_nmi",
		.acpi_match_table = ACPI_PTR(acpi_nmi_match),
	},
};
builtin_platform_driver(acpi_nmi_platform_driver);
