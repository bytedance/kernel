// SPDX-License-Identifier: GPL-2.0-only
/*
 * CMA Memory Reserve Driver - Per NUMA Node
 *
 * Copyright (c) 2026, ByteDance, Inc.
 * Authors: Shen yicong shenyicong.1023@bytedance.com
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/nodemask.h>
#include <linux/gfp.h>
#include <linux/mutex.h>
#include <linux/cma_memory_reserve.h>

#define CMR_NAME "cmr_char"
#define CMR_CLASS_NAME "cmr_class"

/*
 * Module parameter for allocation size in MB.
 *
 * Default is 0, meaning do not allocate any memory and do not create devices.
 * This is useful for built-in mode where parameters are often passed via
 * kernel cmdline (e.g. cma_memory_reserve.alloc_size_mb=256).
 */
static unsigned long alloc_size_mb; /* Default 0MB */
module_param(alloc_size_mb, ulong, 0444);
MODULE_PARM_DESC(alloc_size_mb, "Size of memory to reserve per node in MB");

/*
 * Default 0: non-coherent. When disabled, userspace must ensure that
 * the current platform has no cache coherency issue for this use case,
 * or handle cache coherency by other external means.
 */
static int need_coherent;
module_param(need_coherent, int, 0444);
MODULE_PARM_DESC(need_coherent,
		 "Use coherent DMA memory; false means userspace handles coherency");

struct cmr_node_ctx {
	int node_id;
	dev_t dev_num;
	struct device *dev;	/* Private DMA device, never published to sysfs */
	struct device *class_dev;	/* Published /dev and sysfs device */

	/* Memory resources */
	dma_addr_t dma_handle;	/* DMA address in ctx->dev DMA address space */
	size_t size;		/* Actual size in bytes */
	void *kvaddr;		/* Kernel virtual address (Uncached) */

	struct list_head list;	/* To keep track of all contexts */
};

static struct class *cmr_class;
static LIST_HEAD(ctx_list);  /* Linked list to manage our devices */
static DEFINE_MUTEX(ctx_lock);

static dev_t cmr_devt_base;
static unsigned int cmr_devt_count;
static struct cdev cmr_cdev;
static bool cmr_cdev_added;
static bool cmr_ready;

static char *cmr_devnode(const struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0600;

	/* Use default node name created by devtmpfs/udev. */
	return NULL;
}

/*
 * Helper to find context based on inode.
 * Used in open() to bind file->private_data
 */
static struct cmr_node_ctx *get_ctx_from_inode(struct inode *inode)
{
	struct cmr_node_ctx *ctx;
	unsigned int minor = iminor(inode);
	unsigned int base_minor = MINOR(cmr_devt_base);
	int node;

	if (minor < base_minor)
		return NULL;

	node = minor - base_minor;
	list_for_each_entry(ctx, &ctx_list, list) {
		if (ctx->node_id == node)
			return ctx;
	}

	return NULL;
}

static void cmr_destroy_class_device(struct cmr_node_ctx *ctx)
{
	if (!ctx->class_dev)
		return;

	dev_set_drvdata(ctx->class_dev, NULL);
	device_unregister(ctx->class_dev);
	ctx->class_dev = NULL;
}

static void cmr_put_dma_device(struct cmr_node_ctx *ctx)
{
	if (!ctx->dev)
		return;

	root_device_unregister(ctx->dev);
	ctx->dev = NULL;
}

/*
 * READ: Read from the CMA memory to user buffer
 */
static ssize_t cmr_read(struct file *filp, char __user *buf, size_t count,
			loff_t *pos)
{
	struct cmr_node_ctx *ctx = filp->private_data;
	size_t available;
	u8 *base;

	if (!ctx || !ctx->kvaddr)
		return -EFAULT;

	base = (u8 *)ctx->kvaddr;

	if (*pos >= ctx->size)
		return 0;

	available = ctx->size - *pos;
	if (count > available)
		count = available;

	/*
	 * Note: Since kvaddr can be coherent (uncached), this copy might be slower
	 * than copying from standard RAM, but it guarantees data freshness.
	 */
	if (copy_to_user(buf, base + *pos, count))
		return -EFAULT;

	*pos += count;
	return count;
}

/*
 * WRITE: Write from user buffer to CMA memory
 */
static ssize_t cmr_write(struct file *filp, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct cmr_node_ctx *ctx = filp->private_data;
	size_t available;
	u8 *base;

	if (!ctx || !ctx->kvaddr)
		return -EFAULT;

	base = (u8 *)ctx->kvaddr;

	if (*pos >= ctx->size)
		return -ENOSPC;

	available = ctx->size - *pos;
	if (count > available)
		count = available;

	if (copy_from_user(base + *pos, buf, count))
		return -EFAULT;

	*pos += count;

	pr_debug("%s: node %d wrote %zu bytes at offset %lld\n",
		 CMR_NAME, ctx->node_id, count, *pos - count);

	return count;
}

/*
 * MMAP: Map DMA memory to user space
 *
 * - Coherent: dma_mmap_coherent()
 * - Non-coherent: dma_mmap_pages() for dma_alloc_noncoherent()
 */
static int cmr_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct cmr_node_ctx *ctx = filp->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	int ret;

	if (!ctx || !ctx->kvaddr)
		return -EFAULT;

	/*
	 * Support mapping from an offset (vma->vm_pgoff) as long as the mapping
	 * stays within the allocated buffer.
	 */
	if (offset >= ctx->size)
		return -ENXIO;

	if (size > ctx->size - offset)
		return -EINVAL;

	if (!ctx->dev)
		return -ENODEV;

	/*
	 * dma_mmap_coherent is the correct partner for dma_alloc_coherent.
	 * It maps the underlying DMA allocation into userspace while preserving
	 * the cache attributes that were set up during allocation.
	 */
	if (need_coherent)
		ret = dma_mmap_coherent(ctx->dev, vma, ctx->kvaddr, ctx->dma_handle,
					ctx->size);
	else
		ret = dma_mmap_pages(ctx->dev, vma, ctx->size, virt_to_page(ctx->kvaddr));

	if (ret < 0) {
		pr_err("%s: %s failed: %d\n", CMR_NAME, __func__, ret);
		return ret;
	}

	return 0;
}

static int cmr_open(struct inode *inode, struct file *filp)
{
	struct cmr_node_ctx *ctx;
	int ret = -ENODEV;

	/*
	 * Paired with the release-store after all contexts have been initialized
	 * and before cdev/device nodes are published.
	 */
	if (!smp_load_acquire(&cmr_ready))
		return -ENODEV;

	mutex_lock(&ctx_lock);
	ctx = get_ctx_from_inode(inode);
	if (ctx) {
		filp->private_data = ctx;
		ret = 0;
	}
	mutex_unlock(&ctx_lock);

	return ret;
}

static int cmr_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long cmr_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct cmr_node_ctx *ctx = filp->private_data;
	struct cmr_user_mem_info info;

	if (!ctx || !ctx->kvaddr)
		return -ENODEV;

	switch (cmd) {
	case CMR_IOC_GET_MEM_INFO:
		/*
		 * Expose the DMA address only in the DMA domain of this cmr device.
		 * It must not be treated as a generic CPU physical address. Another
		 * device may be able to use it only when the relevant IOMMU
		 * translation is configured in passthrough/PT mode; otherwise it is
		 * meaningless and unusable for other devices. For non-coherent
		 * allocations, this ioctl does not provide cache maintenance;
		 * userspace must ensure cache coherency is not an issue on the
		 * current platform, or handle it by other external means.
		 */
		info.dma_addr = ctx->dma_handle;
		info.size = ctx->size;
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations cmr_fops = {
	.owner		= THIS_MODULE,
	.open		= cmr_open,
	.release	= cmr_release,
	.unlocked_ioctl	= cmr_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
	.read		= cmr_read,
	.write		= cmr_write,
	.mmap		= cmr_mmap,
	.llseek		= default_llseek,
};

/*
 * Cleanup a single context (free memory, drop/unregister device)
 */
static void cleanup_node_context(struct cmr_node_ctx *ctx)
{
	mutex_lock(&ctx_lock);
	list_del(&ctx->list);
	mutex_unlock(&ctx_lock);

	cmr_destroy_class_device(ctx);

	if (ctx->kvaddr) {
		if (need_coherent)
			dma_free_coherent(ctx->dev, ctx->size, ctx->kvaddr,
					  ctx->dma_handle);
		else
			dma_free_noncoherent(ctx->dev, ctx->size, ctx->kvaddr,
					     ctx->dma_handle,
					     DMA_BIDIRECTIONAL);
		pr_info("%s: node %d freed %zu bytes\n",
			CMR_NAME, ctx->node_id, ctx->size);
	}

	cmr_put_dma_device(ctx);

	kfree(ctx);
}

static int __init cmr_init(void)
{
	int ret = 0;
	int node;
	size_t alloc_size_bytes;
	struct cmr_node_ctx *ctx, *tmp;

	if (!alloc_size_mb) {
		pr_info("%s: alloc_size_mb=0, skip allocation and device creation\n",
			CMR_NAME);
		return 0;
	}

	/* Calculate size */
	alloc_size_bytes = alloc_size_mb * 1024 * 1024;
	alloc_size_bytes = PAGE_ALIGN(alloc_size_bytes);

	pr_info("%s: initializing, alloc_size=%lu MB per node (%s Mode)\n",
		CMR_NAME, alloc_size_mb,
		need_coherent ? "Coherent" : "Non-Coherent");

	/* Create the device class */
	cmr_class = class_create(CMR_CLASS_NAME);
	if (IS_ERR(cmr_class)) {
		pr_err("%s: failed to create class\n", CMR_NAME);
		return PTR_ERR(cmr_class);
	}

	/* Restrict /dev/cmr_char* to root-only by default. */
	cmr_class->devnode = cmr_devnode;

	/*
	 * Allocate a single major number for the driver, and use the NUMA node id
	 * as the minor number.
	 */
	cmr_devt_count = nr_node_ids;
	ret = alloc_chrdev_region(&cmr_devt_base, 0, cmr_devt_count, CMR_NAME);
	if (ret < 0) {
		pr_err("%s: alloc_chrdev_region failed: %d\n", CMR_NAME, ret);
		class_destroy(cmr_class);
		cmr_class = NULL;
		cmr_devt_count = 0;
		return ret;
	}

	/* Prepare all per-node contexts and DMA buffers without publishing /dev nodes. */
	for_each_node_state(node, N_MEMORY) {
		char dma_dev_name[32];
		dev_t devno;

		ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
		if (!ctx) {
			ret = -ENOMEM;
			goto err_cleanup;
		}

		ctx->node_id = node;
		ctx->size = alloc_size_bytes;
		INIT_LIST_HEAD(&ctx->list);

		/* Use node id as minor number under a single allocated major. */
		devno = MKDEV(MAJOR(cmr_devt_base), MINOR(cmr_devt_base) + node);
		ctx->dev_num = devno;

		snprintf(dma_dev_name, sizeof(dma_dev_name), "%s_dma%d",
			 CMR_NAME, node);
		ctx->dev = root_device_register(dma_dev_name);
		if (IS_ERR(ctx->dev)) {
			ret = PTR_ERR(ctx->dev);
			ctx->dev = NULL;
			pr_err("%s: root_device_register failed for node %d: %d\n",
			       CMR_NAME, node, ret);
			kfree(ctx);
			goto err_cleanup;
		}

		/*
		 * root_device_register() provides a core-owned release callback, so
		 * delayed kobject release cannot call back into unloaded module text.
		 */
		ctx->dev->dma_mask = &ctx->dev->coherent_dma_mask;
		ctx->dev->coherent_dma_mask = DMA_BIT_MASK(64);
		set_dev_node(ctx->dev, node);

		/* Initialize DMA masks before allocating DMA memory. */
		ret = dma_set_mask_and_coherent(ctx->dev, DMA_BIT_MASK(64));
		if (ret)
			ret = dma_set_mask_and_coherent(ctx->dev, DMA_BIT_MASK(32));
		if (ret) {
			pr_err("%s: dma_set_mask_and_coherent failed for node %d: %d\n",
			       CMR_NAME, node, ret);
			cmr_put_dma_device(ctx);
			kfree(ctx);
			goto err_cleanup;
		}

		/* Allocate Memory using dma_alloc_coherent/dma_alloc_noncoherent. */
		if (need_coherent)
			ctx->kvaddr = dma_alloc_coherent(ctx->dev, ctx->size,
							 &ctx->dma_handle, GFP_KERNEL);
		else
			ctx->kvaddr = dma_alloc_noncoherent(ctx->dev, ctx->size,
							    &ctx->dma_handle,
							    DMA_BIDIRECTIONAL,
							    GFP_KERNEL);

		if (!ctx->kvaddr) {
			pr_err("%s: dma_alloc failed for node %d (size=%zu)\n",
			       CMR_NAME, node, ctx->size);
			ret = -ENOMEM;
			cmr_put_dma_device(ctx);
			kfree(ctx);
			goto err_cleanup;
		}

		/* Add to global list (fully initialized contexts only). */
		list_add_tail(&ctx->list, &ctx_list);

		pr_info("%s: node %d setup done. Virt: %p, DMA Addr: %llx\n",
			CMR_NAME, node, ctx->kvaddr,
			(unsigned long long)ctx->dma_handle);
	}

	/* Make initialized contexts visible before publishing cdev/devices. */
	smp_store_release(&cmr_ready, true);

	cdev_init(&cmr_cdev, &cmr_fops);
	cmr_cdev.owner = THIS_MODULE;
	ret = cdev_add(&cmr_cdev, cmr_devt_base, cmr_devt_count);
	if (ret) {
		pr_err("%s: cdev_add failed: %d\n", CMR_NAME, ret);
		goto err_cleanup;
	}
	cmr_cdev_added = true;

	/* Publish /dev nodes only after chrdev range is registered. */
	list_for_each_entry(ctx, &ctx_list, list) {
		ctx->class_dev = device_create(cmr_class, ctx->dev,
					       ctx->dev_num, ctx, "%s%d",
					       CMR_NAME, ctx->node_id);
		if (IS_ERR(ctx->class_dev)) {
			ret = PTR_ERR(ctx->class_dev);
			ctx->class_dev = NULL;
			pr_err("%s: device_create failed for node %d: %d\n",
			       CMR_NAME, ctx->node_id, ret);
			continue;
		}
	}

	return 0;

err_cleanup:
	/* Keep cmr_ready updates ordered consistently with the publish path. */
	smp_store_release(&cmr_ready, false);

	if (cmr_cdev_added) {
		cdev_del(&cmr_cdev);
		cmr_cdev_added = false;
	}

	/* Iterate list and clean up everything */
	list_for_each_entry_safe(ctx, tmp, &ctx_list, list)
		cleanup_node_context(ctx);

	if (cmr_devt_count)
		unregister_chrdev_region(cmr_devt_base, cmr_devt_count);
	cmr_devt_count = 0;
	if (cmr_class) {
		class_destroy(cmr_class);
		cmr_class = NULL;
	}
	return ret;
}

static void __exit cmr_exit(void)
{
	struct cmr_node_ctx *ctx, *tmp;

	pr_info("%s: unloading module\n", CMR_NAME);

	/* Keep cmr_ready updates ordered consistently with the publish path. */
	smp_store_release(&cmr_ready, false);

	if (cmr_cdev_added) {
		cdev_del(&cmr_cdev);
		cmr_cdev_added = false;
	}

	list_for_each_entry_safe(ctx, tmp, &ctx_list, list)
		cleanup_node_context(ctx);

	if (cmr_devt_count)
		unregister_chrdev_region(cmr_devt_base, cmr_devt_count);
	cmr_devt_count = 0;

	if (cmr_class) {
		class_destroy(cmr_class);
		cmr_class = NULL;
	}
}

module_init(cmr_init);
module_exit(cmr_exit);

MODULE_AUTHOR("Shen yicong <shenyicong.1023@bytedance.com>");
MODULE_DESCRIPTION("Per-NUMA CMA Memory Reserve Driver");
MODULE_LICENSE("GPL");
