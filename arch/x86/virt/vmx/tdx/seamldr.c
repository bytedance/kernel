// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Intel TDX module runtime update support
 */

#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/notifier.h>

#include <asm/tdx.h>

#include "tdx.h"

static RAW_NOTIFIER_HEAD(update_chain_head);
static DEFINE_MUTEX(update_chain_lock);

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

static int tdx_module_update(void)
{
	int update_status = -1;
	int ret;

	/*
	 * Hold update_chain_lock to ensure no new registration during updates.
	 * Otherwise, new subscribers may receive a completion notification
	 * without a preceding start notification, which is undesired.
	 */
	mutex_lock(&update_chain_lock);

	/* Prevent concurrent calls of tdx kernel APIs during the update */
	tdx_module_lock();

	ret = tdx_module_update_start();
	if (ret)
		goto unlock;

	/* TODO: Install and re-initialize the new TDX module */

	if (ret)
		update_status = TDX_UPDATE_FAIL;
	else
		update_status = TDX_UPDATE_SUCCESS;

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
