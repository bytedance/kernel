// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/mm/flush.c
 *
 * Copyright (C) 1995-2002 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/pagemap.h>

#include <asm/cacheflush.h>
#include <asm/cache.h>
#include <asm/tlbflush.h>

void sync_icache_aliases(void *kaddr, unsigned long len)
{
	unsigned long addr = (unsigned long)kaddr;

	if (icache_is_aliasing()) {
		__clean_dcache_area_pou(kaddr, len);
		__flush_icache_all();
	} else {
		/*
		 * Don't issue kick_all_cpus_sync() after I-cache invalidation
		 * for user mappings.
		 */
		__flush_icache_range(addr, addr + len);
	}
}

static void flush_ptrace_access(struct vm_area_struct *vma, struct page *page,
				unsigned long uaddr, void *kaddr,
				unsigned long len)
{
	if (vma->vm_flags & VM_EXEC)
		sync_icache_aliases(kaddr, len);
}

/*
 * Copy user data from/to a page which is mapped into a different processes
 * address space.  Really, we want to allow our "user space" model to handle
 * this.
 */
void copy_to_user_page(struct vm_area_struct *vma, struct page *page,
		       unsigned long uaddr, void *dst, const void *src,
		       unsigned long len)
{
	memcpy(dst, src, len);
	flush_ptrace_access(vma, page, uaddr, dst, len);
}

void __sync_icache_dcache(pte_t pte)
{
	struct page *page = pte_page(pte);

	/*
	 * HugeTLB pages are always fully mapped, so only setting head page's
	 * PG_dcache_clean flag is enough.
	 */
	if (PageHuge(page))
		page = compound_head(page);

	if (!test_and_set_bit(PG_dcache_clean, &page->flags))
		sync_icache_aliases(page_address(page), page_size(page));
}
EXPORT_SYMBOL_GPL(__sync_icache_dcache);

/*
 * This function is called when a page has been modified by the kernel. Mark
 * it as dirty for later flushing when mapped in user space (if executable,
 * see __sync_icache_dcache).
 */
void flush_dcache_page(struct page *page)
{
	/*
	 * Only the head page's flags of HugeTLB can be cleared since the tail
	 * vmemmap pages associated with each HugeTLB page are mapped with
	 * read-only when CONFIG_HUGETLB_PAGE_FREE_VMEMMAP is enabled (more
	 * details can refer to vmemmap_remap_pte()).  Although
	 * __sync_icache_dcache() only set PG_dcache_clean flag on the head
	 * page struct, there is more than one page struct with PG_dcache_clean
	 * associated with the HugeTLB page since the head vmemmap page frame
	 * is reused (more details can refer to the comments above
	 * page_fixed_fake_head()).
	 */
	if (hugetlb_free_vmemmap_enabled() && PageHuge(page))
		page = compound_head(page);

	if (test_bit(PG_dcache_clean, &page->flags))
		clear_bit(PG_dcache_clean, &page->flags);
}
EXPORT_SYMBOL(flush_dcache_page);

/*
 * Additional functions defined in assembly.
 */
EXPORT_SYMBOL(__flush_icache_range);

#ifdef CONFIG_ARCH_HAS_PMEM_API
void arch_wb_cache_pmem(void *addr, size_t size)
{
	/* Ensure order against any prior non-cacheable writes */
	dmb(osh);
	__clean_dcache_area_pop(addr, size);
}
EXPORT_SYMBOL_GPL(arch_wb_cache_pmem);

void arch_invalidate_pmem(void *addr, size_t size)
{
	__inval_dcache_area(addr, size);
}
EXPORT_SYMBOL_GPL(arch_invalidate_pmem);
#endif
