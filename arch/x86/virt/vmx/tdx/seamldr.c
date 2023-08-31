// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2023 Intel Corporation.
 *
 * Intel TDX module runtime update support
 */

#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/sysfs.h>

#include <asm/tdx.h>

static int tdx_module_update(void)
{
	return 0;
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
