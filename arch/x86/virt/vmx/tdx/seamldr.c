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

#include <asm/tdx.h>

#include "tdx.h"
#include "seamldr.h"

static RAW_NOTIFIER_HEAD(update_chain_head);
static DEFINE_MUTEX(update_chain_lock);

/* Fake device for request_firmware */
struct platform_device *tdx_pdev;

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

	/* TODO: Install and re-initialize the new TDX module */

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
