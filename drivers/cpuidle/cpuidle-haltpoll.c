// SPDX-License-Identifier: GPL-2.0
/*
 * cpuidle driver for haltpoll governor.
 *
 * Copyright 2019 Red Hat, Inc. and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Authors: Marcelo Tosatti <mtosatti@redhat.com>
 */

#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/module.h>
#include <linux/sched/idle.h>
#include <linux/cpuidle_haltpoll.h>

static bool force;
MODULE_PARM_DESC(force, "Load unconditionally");
static int enable_haltpoll_driver(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops enable_haltpoll_ops = {
	.set = enable_haltpoll_driver,
	.get = param_get_bool,
};
module_param_cb(force, &enable_haltpoll_ops, &force, 0644);


static struct cpuidle_device __percpu *haltpoll_cpuidle_devices;
static enum cpuhp_state haltpoll_hp_state;

static __cpuidle int default_enter_idle(struct cpuidle_device *dev,
					struct cpuidle_driver *drv, int index)
{
	if (current_clr_polling_and_test())
		return index;

	arch_cpu_idle();
	return index;
}

static struct cpuidle_driver haltpoll_driver = {
	.name = "haltpoll",
	.governor = "haltpoll",
	.states = {
		{ /* entry 0 is for polling */ },
		{
			.enter			= default_enter_idle,
			.exit_latency		= 1,
			.target_residency	= 1,
			.power_usage		= -1,
			.name			= "haltpoll idle",
			.desc			= "default architecture idle",
		},
	},
	.safe_state_index = 0,
	.state_count = 2,
};

static int haltpoll_cpu_online(unsigned int cpu)
{
	struct cpuidle_device *dev;

	dev = per_cpu_ptr(haltpoll_cpuidle_devices, cpu);
	if (!dev->registered) {
		dev->cpu = cpu;
		if (cpuidle_register_device(dev)) {
			pr_notice("cpuidle_register_device %d failed!\n", cpu);
			return -EIO;
		}
		arch_haltpoll_enable(cpu);
	}

	return 0;
}

static int haltpoll_cpu_offline(unsigned int cpu)
{
	struct cpuidle_device *dev;

	dev = per_cpu_ptr(haltpoll_cpuidle_devices, cpu);
	if (dev->registered) {
		arch_haltpoll_disable(cpu);
		cpuidle_unregister_device(dev);
	}

	return 0;
}

static void haltpoll_uninit(void)
{
	if (haltpoll_hp_state)
		cpuhp_remove_state(haltpoll_hp_state);
	cpuidle_unregister_driver(&haltpoll_driver);

	free_percpu(haltpoll_cpuidle_devices);
	haltpoll_cpuidle_devices = NULL;
}

static int __init haltpoll_init(void)
{
	int ret;
	struct cpuidle_driver *drv = &haltpoll_driver;

	if (!arch_haltpoll_want(force))
		return -ENODEV;

	cpuidle_poll_state_init(drv);

	ret = cpuidle_register_driver(drv);
	if (ret < 0)
		return ret;

	haltpoll_cpuidle_devices = alloc_percpu(struct cpuidle_device);
	if (haltpoll_cpuidle_devices == NULL) {
		cpuidle_unregister_driver(drv);
		return -ENOMEM;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "cpuidle/haltpoll:online",
				haltpoll_cpu_online, haltpoll_cpu_offline);
	if (ret < 0) {
		haltpoll_uninit();
	} else {
		haltpoll_hp_state = ret;
		ret = 0;
	}

	return ret;
}

static void __exit haltpoll_exit(void)
{
	haltpoll_uninit();
}

#ifdef CONFIG_ARM64
static int register_haltpoll_driver(void)
{
	int ret;
	struct cpuidle_driver *drv = &haltpoll_driver;

	cpuidle_poll_state_init(drv);

	ret = cpuidle_register_driver(drv);
	if (ret < 0)
		return ret;

	haltpoll_cpuidle_devices = alloc_percpu(struct cpuidle_device);
	if (haltpoll_cpuidle_devices == NULL) {
		cpuidle_unregister_driver(drv);
		return -ENOMEM;
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "cpuidle/haltpoll:online",
			haltpoll_cpu_online, haltpoll_cpu_offline);
	if (ret < 0) {
		haltpoll_uninit();
	} else {
		haltpoll_hp_state = ret;
		ret = 0;
	}

	return ret;
}

static void unregister_haltpoll_driver(void)
{
	if (haltpoll_hp_state)
		cpuhp_remove_state(haltpoll_hp_state);
	cpuidle_unregister_driver(&haltpoll_driver);

	free_percpu(haltpoll_cpuidle_devices);
	haltpoll_cpuidle_devices = NULL;

}

static int enable_haltpoll_driver(const char *val, const struct kernel_param *kp)
{
	int ret;
	bool do_enable;

	if (!val)
		return 0;

	ret = strtobool(val, &do_enable);

	if (ret || force == do_enable)
		return ret;

	if (do_enable) {
		ret = register_haltpoll_driver();

		if (!ret) {
			pr_info("Enable haltpoll driver.\n");
			force = 1;
		} else {
			pr_err("Fail to enable haltpoll driver.\n");
		}
	} else {
		unregister_haltpoll_driver();
		force = 0;
		pr_info("Unregister haltpoll driver.\n");
	}

	return ret;
}
#else
static int enable_haltpoll_driver(const char *val, const struct kernel_param *kp)
{
	return -1;
}
#endif

module_init(haltpoll_init);
module_exit(haltpoll_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcelo Tosatti <mtosatti@redhat.com>");
