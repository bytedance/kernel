/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ETHTOOL_COMMON_H
#define _ETHTOOL_COMMON_H

#include <linux/netdevice.h>
#include <linux/ethtool.h>

extern int ethtool_get_module_info_call(struct net_device *dev,
				 struct ethtool_modinfo *modinfo);
extern int ethtool_get_module_eeprom_call(struct net_device *dev,
				   struct ethtool_eeprom *ee, u8 *data);

#endif /* _ETHTOOL_COMMON_H */
