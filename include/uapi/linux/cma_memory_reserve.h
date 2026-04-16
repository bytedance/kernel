/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Userspace ABI for ByteDance CMA memory reserve driver.
 *
 * Copyright (c) 2026, ByteDance, Inc.
 */

#ifndef _UAPI_LINUX_CMA_MEMORY_RESERVE_H
#define _UAPI_LINUX_CMA_MEMORY_RESERVE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define CMR_IOC_MAGIC	0xC1

/**
 * struct cmr_user_mem_info - Userspace-visible CMA memory metadata
 * @dma_addr: DMA address in the address space of the corresponding
 *	/dev/cmr_char<N> device. This is not a generic CPU physical
 *	address. Another device may be able to use this value only when
 *	the relevant IOMMU translation is configured in passthrough/PT
 *	mode; otherwise it is meaningless and unusable for other devices.
 *	For non-coherent allocations, this ABI does not provide cache
 *	maintenance; userspace must ensure the current platform has no
 *	cache coherency issue for this use case, or handle coherency by
 *	other external means before sharing or using this DMA address.
 * @size: Size in bytes of the reserved DMA buffer.
 */
struct cmr_user_mem_info {
	__u64 dma_addr;
	__u64 size;
};

#define CMR_IOC_GET_MEM_INFO	_IOR(CMR_IOC_MAGIC, 0x0, struct cmr_user_mem_info)

#endif /* _UAPI_LINUX_CMA_MEMORY_RESERVE_H */
