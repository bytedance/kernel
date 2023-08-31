// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Intel TDX module runtime update support
 */

#define pr_fmt(fmt)	"seamldr: " fmt

#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/firmware.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#include <asm/archrandom.h>
#include <asm/tdx.h>
#include <asm/virtext.h>
#include <asm/vmx.h>

#include "tdx.h"
#include "seamldr.h"

static RAW_NOTIFIER_HEAD(update_chain_head);
static DEFINE_MUTEX(update_chain_lock);

/* Fake device for request_firmware */
struct platform_device *tdx_pdev;

static bool is_seamldr_func_leaf(u64 func_leaf)
{
	return func_leaf & BIT_ULL(63);
}

static int seamldr_call(u64 func_leaf, u64 rcx, u64 *sret)
{
	struct tdx_module_args args = { .rcx = rcx, };
	int retry = RDRAND_RETRY_LOOPS;
	unsigned long flags;
	u64 seamcall_ret;
	u64 vmcs;
	int ret;

	if (!is_seamldr_func_leaf(func_leaf))
		return -EINVAL;

	/*
	 * SEAMRET from P-SEAMLDR invalidates the current-VMCS pointer.
	 * Save/restore current-VMCS pointer across P-SEAMLDR SEAMCALLs so
	 * that other VMX instructions won't fail due to an invalid
	 * current-VMCS.
	 *
	 * Disable interrupt to prevent SMP call functions from seeing the
	 * invalid current-VMCS.
	 */
	local_irq_save(flags);
	ret = cpu_vmcs_store(&vmcs);
	if (ret) {
		local_irq_restore(flags);
		return ret;
	}

	/*
	 * Certain P-SEAMLDR SEAMCALLs may run out of entropy like TDX
	 * SEAMCALLs. But P-SEAMLDR uses a different error code.
	 */
	do {
		seamcall_ret = __seamcall_ret(func_leaf, &args);
	} while ((seamcall_ret == SEAMLDR_RND_NO_ENTROPY) && --retry);

	/* Restore current-VMCS pointer */
#define INVALID_VMCS	-1ULL
	if (vmcs != INVALID_VMCS)
		WARN_ON_ONCE(cpu_vmcs_load(vmcs));
	local_irq_restore(flags);

	if (sret)
		*sret = seamcall_ret;

	switch (seamcall_ret) {
	case TDX_SUCCESS:
		return 0;
	case TDX_SEAMCALL_VMFAILINVALID:
		pr_err_once("module is not loaded.\n");
		return -ENODEV;
	case TDX_SEAMCALL_GP:
		pr_err_once("not enabled by BIOS.\n");
		return -ENODEV;
	case TDX_SEAMCALL_UD:
		pr_err_once("not in VMX operation.\n");
		return -EINVAL;
	default:
		pr_err_once("SEAMCALL failed: leaf 0x%llx, rcx 0x%llx, error 0x%llx.\n",
			    func_leaf, rcx, seamcall_ret);
		return -EIO;
	}
}

int register_tdx_update_notifier(struct notifier_block *nb)
{
	int ret;

	mutex_lock(&update_chain_lock);
	ret = raw_notifier_chain_register(&update_chain_head, nb);
	mutex_unlock(&update_chain_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(register_tdx_update_notifier);

int unregister_tdx_update_notifier(struct notifier_block *nb)
{
	int ret;

	mutex_lock(&update_chain_lock);
	ret = raw_notifier_chain_unregister(&update_chain_head, nb);
	mutex_unlock(&update_chain_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(unregister_tdx_update_notifier);

static int tdx_module_update_start(void)
{
	int ret;

	lockdep_assert_held(&update_chain_lock);
	ret = raw_notifier_call_chain_robust(&update_chain_head,
					     TDX_UPDATE_START,
					     TDX_UPDATE_ABORT,
					     NULL);

	return notifier_to_errno(ret);
}

static int tdx_module_update_end(int val)
{
	int ret;

	lockdep_assert_held(&update_chain_lock);
	ret = raw_notifier_call_chain(&update_chain_head, val, NULL);

	return notifier_to_errno(ret);
}

static void free_seamldr_params(struct seamldr_params *params)
{
	int i;

	for (i = 0; i < params->num_module_pages; i++)
		free_page((unsigned long)__va(params->mod_pages_pa_list[i]));
	free_page((unsigned long)__va(params->sigstruct_pa));
	free_page((unsigned long)params);
}

/* Allocate and populate a seamldr_params */
static struct seamldr_params *alloc_seamldr_params(const void *module, int module_size,
						   const void *sig, int sig_size)
{
	struct seamldr_params *params;
	unsigned long page;
	int i;

	BUILD_BUG_ON(sizeof(struct seamldr_params) != PAGE_SIZE);
	if ((module_size >> PAGE_SHIFT) > SEAMLDR_MAX_NR_MODULE_PAGES ||
	    sig_size != SEAMLDR_SIGSTRUCT_SIZE)
		return ERR_PTR(-EINVAL);

	params = (struct seamldr_params *)get_zeroed_page(GFP_KERNEL);
	if (!params)
		return ERR_PTR(-ENOMEM);

	params->scenario = SEAMLDR_SCENARIO_LOAD;
	params->num_module_pages = module_size >> PAGE_SHIFT;

	/*
	 * Module binary can take up to 496 pages. These pages needn't be
	 * contiguous. Allocate pages one-by-one to reduce the possibility
	 * of failure. Note that this allocation is very rare and so
	 * performance isn't critical.
	 */
	for (i = 0; i < params->num_module_pages; i++) {
		page = __get_free_page(GFP_KERNEL);
		if (!page)
			goto free;
		memcpy((void *)page, module + (i << PAGE_SHIFT),
		       min((int)PAGE_SIZE, module_size - (i << PAGE_SHIFT)));
		params->mod_pages_pa_list[i] = __pa(page);
	}

	page = __get_free_page(GFP_KERNEL);
	if (!page)
		goto free;
	memcpy((void *)page, sig, sig_size);
	params->sigstruct_pa = __pa(page);

	return params;
free:
	free_seamldr_params(params);
	return ERR_PTR(-ENOMEM);
}

static int sigstruct_pamt_entry_size(const struct seam_sigstruct *sig)
{
	/*
	 * For backward compatibility, 0 indicates that PAMT entry size is 16
	 * bytes.
	 */
	return sig->pamt_entry_size_4K ? : 16;
}

static bool pamt_can_reuse(const struct seam_sigstruct *sig)
{
	if (!sysinfo.tdmr_info.tdmr_pamt_size)
		return true;

	return sysinfo.tdmr_info.pamt_entry_size[TDX_PS_4K] == sigstruct_pamt_entry_size(sig);
}

struct update_ctx {
	struct seamldr_params *params;
	const struct firmware *module, *sig;
};

static void free_update_ctx(struct update_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->sig)
		release_firmware(ctx->sig);
	if (ctx->module)
		release_firmware(ctx->module);
	if (ctx->params)
		free_seamldr_params(ctx->params);
	kfree(ctx);
}

static struct update_ctx *init_update_ctx(void)
{
	struct update_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	struct seamldr_params *params;
	const struct firmware *module, *sig;
	int ret;

	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ret = request_firmware_direct(&module, "intel-seam/libtdx.bin",
				      &tdx_pdev->dev);
	if (ret)
		goto free;
	ctx->module = module;

	ret = request_firmware_direct(&sig, "intel-seam/libtdx.bin.sigstruct",
				      &tdx_pdev->dev);
	if (ret)
		goto free;
	ctx->sig = sig;

	/*
	 * Don't install the new TDX module if PAMT cannot be reused.
	 * Re-allocating PAMTs are not desired because PAMTs need large
	 * contiguous memory, if they are free'd, there is a risk that they
	 * cannot be allocated again.
	 */
	if (!pamt_can_reuse((const struct seam_sigstruct *)sig->data)) {
		ret = -EIO;
		goto free;
	}

	params = alloc_seamldr_params(module->data, module->size,
				      sig->data, sig->size);
	if (IS_ERR(params)) {
		ret = PTR_ERR(params);
		goto free;
	}
	ctx->params = params;

	return ctx;

free:
	free_update_ctx(ctx);
	return ERR_PTR(ret);
}

struct install_args {
	const struct seamldr_params *params;
	u64 sret;
};

static void do_seamldr_install(void *data)
{
	struct install_args *args = data;

	seamldr_call(P_SEAMLDR_INSTALL, __pa(args->params), &(args->sret));
}

static int seamldr_install(const struct seamldr_params *params)
{
	struct install_args args = { .params = params };
	int cpu;

	/*
	 * Don't use on_each_cpu() because P-SEAMLDR SEAMCALLs can be invoked
	 * by only one CPU at a time.
	 */
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, do_seamldr_install, &args, true);

		/* Skip CPUs that have called SEAMLDR.INSTALL */
		if (args.sret == SEAMLDR_BADCALL)
			continue;
		else if (args.sret)
			break;
	}

	if (args.sret) {
		pr_err("SEAMLDR.INSTALL failed. Error %llx\n", args.sret);
		return -EIO;
	}

	return 0;
}

static int do_tdx_module_update(struct update_ctx *ctx)
{
	struct seamldr_params *params = ctx->params;
	int ret;

	/*
	 * Prevent tdx_cpu_enable(), which is called when onlining CPUs. This
	 * also couples with the following cpu_vmxop_get_all() to ensure all
	 * online CPUs entering VMX operation, which is a requirement of later
	 * TDMR initialization (this thread may be scheduled to any online
	 * CPUs, i.e., TDX SEAMCALLs may be made on any online CPUs).
	 */
	cpus_read_lock();
	ret = cpu_vmxop_get_all();
	if (ret)
		goto unlock;

	ret = seamldr_install(params);
	if (!ret) {
		ret = tdx_enable_after_update();
		if (ret)
			pr_err("Failed to initialize new TDX module %d\n", ret);
	} else {
		pr_err("Failed to install new TDX module %d\n", ret);
	}

	cpu_vmxop_put_all();
unlock:
	cpus_read_unlock();
	return ret;
}

static int tdx_module_update(void)
{
	int update_status = -1;
	struct update_ctx *ctx;
	int ret;

	/*
	 * Hold update_chain_lock to ensure no new registration during updates.
	 * Otherwise, new subscribers may receive a completion notification
	 * without a preceding start notification, which is undesired.
	 */
	mutex_lock(&update_chain_lock);

	/* Prevent concurrent calls of tdx kernel APIs during the update */
	tdx_module_lock();

	ctx = init_update_ctx();
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		goto unlock;
	}

	ret = tdx_module_update_start();
	if (ret)
		goto free;

	ret = do_tdx_module_update(ctx);

	if (ret)
		update_status = TDX_UPDATE_FAIL;
	else
		update_status = TDX_UPDATE_SUCCESS;

free:
	free_update_ctx(ctx);
unlock:
	/*
	 * Release the lock before sending the completion notification so
	 * that subscribers can call APIs which may acquire the lock, e.g.,
	 * tdx_enable(), when handling the completion notification.
	 */
	tdx_module_unlock();
	if (update_status >= 0)
		WARN_ON_ONCE(tdx_module_update_end(update_status));
	mutex_unlock(&update_chain_lock);
	return ret;
}

static ssize_t reload_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t size)
{
	int ret;

	if (!sysfs_streq(buf, "update"))
		return -EINVAL;

	ret = tdx_module_update();

	return ret ? : size;
}
static DEVICE_ATTR_WO(reload);

static struct attribute *cpu_root_tdx_attrs[] = {
	&dev_attr_reload.attr,
	NULL,
};

static const struct attribute_group cpu_root_tdx_group = {
	.name  = "tdx",
	.attrs = cpu_root_tdx_attrs,
};

static __init int tdx_module_update_init(void)
{
	struct device *dev_root;
	int ret;

	if (!platform_tdx_enabled())
		return 0;

	tdx_pdev = platform_device_register_simple("tdx", -1, NULL, 0);
	if (IS_ERR(tdx_pdev))
		return PTR_ERR(tdx_pdev);

	dev_root = bus_get_dev_root(&cpu_subsys);
	if (dev_root) {
		ret = sysfs_create_group(&dev_root->kobj, &cpu_root_tdx_group);
		put_device(dev_root);
		if (ret) {
			pr_err("Fail to create tdx group: %d\n", ret);
			return ret;
		}
	}

	return 0;
}
late_initcall(tdx_module_update_init)
