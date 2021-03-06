// SPDX-License-Identifier: GPL-2.0
/*
 * Virtual Memory Map support
 *
 * (C) 2007 sgi. Christoph Lameter.
 *
 * Virtual memory maps allow VM primitives pfn_to_page, page_to_pfn,
 * virt_to_page, page_address() to be implemented as a base offset
 * calculation without memory access.
 *
 * However, virtual mappings need a page table and TLBs. Many Linux
 * architectures already map their physical space using 1-1 mappings
 * via TLBs. For those arches the virtual memory map is essentially
 * for free if we use the same page size as the 1-1 mappings. In that
 * case the overhead consists of a few additional pages that are
 * allocated to create a view of memory for vmemmap.
 *
 * The architecture is expected to provide a vmemmap_populate() function
 * to instantiate the mapping.
 */
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/memblock.h>
#include <linux/memremap.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/bootmem_info.h>
#include <linux/delay.h>

#include <asm/dma.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

/**
 * vmemmap_remap_walk - walk vmemmap page table
 *
 * @remap_pte:		called for each non-empty PTE (lowest-level) entry.
 * @reuse_page:		the page which is reused for the tail vmemmap pages.
 * @reuse_addr:		the virtual address of the @reuse_page page.
 * @vmemmap_pages:	the list head of the vmemmap pages that can be freed
 *			or is mapped from.
 * @pgtables:		the list of page tables which is used for splitting huge
 *			PMD page tables.
 */
struct vmemmap_remap_walk {
	void (*remap_pte)(pte_t *pte, unsigned long addr,
			  struct vmemmap_remap_walk *walk);
	struct page *reuse_page;
	unsigned long reuse_addr;
	struct list_head *vmemmap_pages;
	struct list_head *pgtables;
};

/*
 * How many struct page structs need to be reset. When we reuse the head
 * struct page, the special metadata (e.g. page->flags or page->mapping)
 * cannot copy to the tail struct page structs. The invalid value can be
 * checked in the free_tail_pages_check(). In order to avoid the message
 * of "corrupted mapping in tail page". We should reset at least 3 (one
 * head struct page struct and two tail struct page structs) struct page
 * structs.
 */
#define NR_RESET_STRUCT_PAGE		3
#define STRUCT_PAGE_PER_PAGE		(PAGE_SIZE / sizeof(struct page))

/* The gfp mask of allocating vmemmap page */
#define GFP_VMEMMAP_PAGE		\
	(GFP_KERNEL | __GFP_RETRY_MAYFAIL | __GFP_NOWARN | __GFP_THISNODE)

#define VMEMMAP_HPMD_ORDER		(PMD_SHIFT - PAGE_SHIFT)
#define VMEMMAP_HPMD_NR			(1 << VMEMMAP_HPMD_ORDER)

static pgtable_t pgtable_withdraw(struct vmemmap_remap_walk *walk)
{
	pgtable_t pgtable;

	pgtable = list_first_entry(walk->pgtables, struct page, lru);
	list_del(&pgtable->lru);

	return pgtable;
}

static void __split_vmemmap_huge_pmd(pmd_t *pmd, pte_t *pgtable,
				     unsigned long addr)
{
	int i;
	pmd_t __pmd;
	struct page *page = pmd_page(*pmd);

	pmd_populate_kernel(&init_mm, &__pmd, pgtable);
	for (i = 0; i < VMEMMAP_HPMD_NR; i++, addr += PAGE_SIZE) {
		pte_t entry, *pte;
		pgprot_t pgprot = PAGE_KERNEL;

		entry = mk_pte(page + i, pgprot);
		pte = pte_offset_kernel(&__pmd, addr);
		set_pte_at(&init_mm, addr, pte, entry);
	}

	/* make pte visible before pmd */
	smp_wmb();
	pmd_populate_kernel(&init_mm, pmd, pgtable);
}

static void split_vmemmap_huge_pmd(pmd_t *pmd, unsigned long addr,
				   struct vmemmap_remap_walk *walk)
{
	spinlock_t *ptl;

	if (!walk->pgtables)
		return;

	addr &= PMD_MASK;
	ptl = pmd_lock(&init_mm, pmd);
	if (!pmd_leaf(*pmd))
		goto out;
	__split_vmemmap_huge_pmd(pmd, page_to_virt(pgtable_withdraw(walk)),
				 addr);
	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
out:
	spin_unlock(ptl);
}

static void vmemmap_pte_range(pmd_t *pmd, unsigned long addr,
			      unsigned long end,
			      struct vmemmap_remap_walk *walk)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);

	/*
	 * The routine of vmemmap page table walking has the following rules:
	 *
	 * - reuse address is part of the range that we are walking.
	 * - reuse_page is found 'first' in table walk before we start
	 *   remapping (which is calling @walk->remap_pte).
	 */
	if (walk->reuse_addr == addr) {
		BUG_ON(pte_none(*pte));

		walk->reuse_page = pte_page(*pte++);
		addr += PAGE_SIZE;
	}

	for (; addr != end; addr += PAGE_SIZE, pte++) {
		BUG_ON(pte_none(*pte));

		walk->remap_pte(pte, addr, walk);
	}
}

static void vmemmap_pmd_range(pud_t *pud, unsigned long addr,
			      unsigned long end,
			      struct vmemmap_remap_walk *walk)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		BUG_ON(pmd_none(*pmd));

		split_vmemmap_huge_pmd(pmd, addr, walk);
		next = pmd_addr_end(addr, end);
		vmemmap_pte_range(pmd, addr, next, walk);
	} while (pmd++, addr = next, addr != end);
}

static void vmemmap_pud_range(p4d_t *p4d, unsigned long addr,
			      unsigned long end,
			      struct vmemmap_remap_walk *walk)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(p4d, addr);
	do {
		BUG_ON(pud_none(*pud));

		next = pud_addr_end(addr, end);
		vmemmap_pmd_range(pud, addr, next, walk);
	} while (pud++, addr = next, addr != end);
}

static void vmemmap_p4d_range(pgd_t *pgd, unsigned long addr,
			      unsigned long end,
			      struct vmemmap_remap_walk *walk)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		BUG_ON(p4d_none(*p4d));

		next = p4d_addr_end(addr, end);
		vmemmap_pud_range(p4d, addr, next, walk);
	} while (p4d++, addr = next, addr != end);
}

static void vmemmap_remap_range(unsigned long start, unsigned long end,
				struct vmemmap_remap_walk *walk)
{
	unsigned long addr = start;
	unsigned long next;
	pgd_t *pgd;

	VM_BUG_ON(!IS_ALIGNED(start, PAGE_SIZE));
	VM_BUG_ON(!IS_ALIGNED(end, PAGE_SIZE));

	pgd = pgd_offset_k(addr);
	do {
		BUG_ON(pgd_none(*pgd));

		next = pgd_addr_end(addr, end);
		vmemmap_p4d_range(pgd, addr, next, walk);
	} while (pgd++, addr = next, addr != end);

	flush_tlb_kernel_range(start, end);
}

/*
 * Free a vmemmap page. A vmemmap page can be allocated from the memblock
 * allocator or buddy allocator. If the PG_reserved flag is set, it means
 * that it allocated from the memblock allocator, just free it via the
 * free_bootmem_page(). Otherwise, use __free_page().
 */
static inline void free_vmemmap_page(struct page *page)
{
	if (PageReserved(page))
		free_bootmem_page(page);
	else
		__free_page(page);
}

/* Free a list of the vmemmap pages */
static void free_vmemmap_page_list(struct list_head *list)
{
	struct page *page, *next;

	list_for_each_entry_safe(page, next, list, lru) {
		list_del(&page->lru);
		free_vmemmap_page(page);
	}
}

static void vmemmap_remap_pte(pte_t *pte, unsigned long addr,
			      struct vmemmap_remap_walk *walk)
{
	/*
	 * Remap the tail pages as read-only to catch illegal write operation
	 * to the tail pages.
	 */
	pgprot_t pgprot = PAGE_KERNEL_RO;
	pte_t entry = mk_pte(walk->reuse_page, pgprot);
	struct page *page = pte_page(*pte);

	list_add(&page->lru, walk->vmemmap_pages);
	set_pte_at(&init_mm, addr, pte, entry);
}

/**
 * vmemmap_remap_free - remap the vmemmap virtual address range [@start, @end)
 *			to the page which @reuse is mapped, then free vmemmap
 *			pages.
 * @start:	start address of the vmemmap virtual address range.
 * @end:	end address of the vmemmap virtual address range.
 * @reuse:	reuse address.
 * @pgtables:	the list of page tables which is used for splitting huge PMD
 *		page tables.
 */
void vmemmap_remap_free(unsigned long start, unsigned long end,
			unsigned long reuse, struct list_head *pgtables)
{
	LIST_HEAD(vmemmap_pages);
	struct vmemmap_remap_walk walk = {
		.remap_pte	= vmemmap_remap_pte,
		.reuse_addr	= reuse,
		.vmemmap_pages	= &vmemmap_pages,
		.pgtables	= pgtables,
	};

	BUG_ON(start != reuse + PAGE_SIZE);

	vmemmap_remap_range(reuse, end, &walk);
	free_vmemmap_page_list(&vmemmap_pages);
}

static inline void reset_struct_pages(struct page *start)
{
	int i;
	struct page *end = start + STRUCT_PAGE_PER_PAGE - 1;

	for (i = 0; i < NR_RESET_STRUCT_PAGE; i++)
		memcpy(start + i, end, sizeof(struct page));
}

static void vmemmap_restore_pte(pte_t *pte, unsigned long addr,
				struct vmemmap_remap_walk *walk)
{
	pgprot_t pgprot = PAGE_KERNEL;
	struct page *page;
	void *to;

	BUG_ON(pte_page(*pte) != walk->reuse_page);

	page = list_first_entry(walk->vmemmap_pages, struct page, lru);
	list_del(&page->lru);
	to = page_to_virt(page);
	copy_page(to, (void *)walk->reuse_addr);
	reset_struct_pages(to);

	set_pte_at(&init_mm, addr, pte, mk_pte(page, pgprot));
}

static void alloc_vmemmap_page_list(struct list_head *list,
				    unsigned long start, unsigned long end)
{
	unsigned long addr;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		struct page *page;
		int nid = page_to_nid((const void *)addr);

retry:
		page = alloc_pages_node(nid, GFP_VMEMMAP_PAGE, 0);
		if (unlikely(!page)) {
			msleep(100);
			/*
			 * We should retry infinitely, because we cannot
			 * handle allocation failures. Once we allocate
			 * vmemmap pages successfully, then we can free
			 * a HugeTLB page.
			 */
			goto retry;
		}
		list_add_tail(&page->lru, list);
	}
}

/**
 * vmemmap_remap_alloc - remap the vmemmap virtual address range [@start, end)
 *			 to the page which is from the @vmemmap_pages
 *			 respectively.
 * @start:	start address of the vmemmap virtual address range.
 * @end:	end address of the vmemmap virtual address range.
 * @reuse:	reuse address.
 */
void vmemmap_remap_alloc(unsigned long start, unsigned long end,
			 unsigned long reuse)
{
	LIST_HEAD(vmemmap_pages);
	struct vmemmap_remap_walk walk = {
		.remap_pte	= vmemmap_restore_pte,
		.reuse_addr	= reuse,
		.vmemmap_pages	= &vmemmap_pages,
	};

	might_sleep();

	BUG_ON(start != reuse + PAGE_SIZE);

	alloc_vmemmap_page_list(&vmemmap_pages, start, end);
	vmemmap_remap_range(reuse, end, &walk);
}

/*
 * Allocate a block of memory to be used to back the virtual memory map
 * or to back the page tables that are used to create the mapping.
 * Uses the main allocators if they are available, else bootmem.
 */

static void * __ref __earlyonly_bootmem_alloc(int node,
				unsigned long size,
				unsigned long align,
				unsigned long goal)
{
	return memblock_alloc_try_nid_raw(size, align, goal,
					       MEMBLOCK_ALLOC_ACCESSIBLE, node);
}

void * __meminit vmemmap_alloc_block(unsigned long size, int node)
{
	/* If the main allocator is up use that, fallback to bootmem. */
	if (slab_is_available()) {
		gfp_t gfp_mask = GFP_KERNEL|__GFP_RETRY_MAYFAIL|__GFP_NOWARN;
		int order = get_order(size);
		static bool warned;
		struct page *page;

		page = alloc_pages_node(node, gfp_mask, order);
		if (page)
			return page_address(page);

		if (!warned) {
			warn_alloc(gfp_mask & ~__GFP_NOWARN, NULL,
				   "vmemmap alloc failure: order:%u", order);
			warned = true;
		}
		return NULL;
	} else
		return __earlyonly_bootmem_alloc(node, size, size,
				__pa(MAX_DMA_ADDRESS));
}

/* need to make sure size is all the same during early stage */
void * __meminit vmemmap_alloc_block_buf(unsigned long size, int node)
{
	void *ptr = sparse_buffer_alloc(size);

	if (!ptr)
		ptr = vmemmap_alloc_block(size, node);
	return ptr;
}

static unsigned long __meminit vmem_altmap_next_pfn(struct vmem_altmap *altmap)
{
	return altmap->base_pfn + altmap->reserve + altmap->alloc
		+ altmap->align;
}

static unsigned long __meminit vmem_altmap_nr_free(struct vmem_altmap *altmap)
{
	unsigned long allocated = altmap->alloc + altmap->align;

	if (altmap->free > allocated)
		return altmap->free - allocated;
	return 0;
}

/**
 * altmap_alloc_block_buf - allocate pages from the device page map
 * @altmap:	device page map
 * @size:	size (in bytes) of the allocation
 *
 * Allocations are aligned to the size of the request.
 */
void * __meminit altmap_alloc_block_buf(unsigned long size,
		struct vmem_altmap *altmap)
{
	unsigned long pfn, nr_pfns, nr_align;

	if (size & ~PAGE_MASK) {
		pr_warn_once("%s: allocations must be multiple of PAGE_SIZE (%ld)\n",
				__func__, size);
		return NULL;
	}

	pfn = vmem_altmap_next_pfn(altmap);
	nr_pfns = size >> PAGE_SHIFT;
	nr_align = 1UL << find_first_bit(&nr_pfns, BITS_PER_LONG);
	nr_align = ALIGN(pfn, nr_align) - pfn;
	if (nr_pfns + nr_align > vmem_altmap_nr_free(altmap))
		return NULL;

	altmap->alloc += nr_pfns;
	altmap->align += nr_align;
	pfn += nr_align;

	pr_debug("%s: pfn: %#lx alloc: %ld align: %ld nr: %#lx\n",
			__func__, pfn, altmap->alloc, altmap->align, nr_pfns);
	return __va(__pfn_to_phys(pfn));
}

void __meminit vmemmap_verify(pte_t *pte, int node,
				unsigned long start, unsigned long end)
{
	unsigned long pfn = pte_pfn(*pte);
	int actual_node = early_pfn_to_nid(pfn);

	if (node_distance(actual_node, node) > LOCAL_DISTANCE)
		pr_warn("[%lx-%lx] potential offnode page_structs\n",
			start, end - 1);
}

pte_t * __meminit vmemmap_pte_populate(pmd_t *pmd, unsigned long addr, int node)
{
	pte_t *pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte)) {
		pte_t entry;
		void *p = vmemmap_alloc_block_buf(PAGE_SIZE, node);
		if (!p)
			return NULL;
		entry = pfn_pte(__pa(p) >> PAGE_SHIFT, PAGE_KERNEL);
		set_pte_at(&init_mm, addr, pte, entry);
	}
	return pte;
}

static void * __meminit vmemmap_alloc_block_zero(unsigned long size, int node)
{
	void *p = vmemmap_alloc_block(size, node);

	if (!p)
		return NULL;
	memset(p, 0, size);

	return p;
}

pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node)
{
	pmd_t *pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd)) {
		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
		if (!p)
			return NULL;
		pmd_populate_kernel(&init_mm, pmd, p);
	}
	return pmd;
}

pud_t * __meminit vmemmap_pud_populate(p4d_t *p4d, unsigned long addr, int node)
{
	pud_t *pud = pud_offset(p4d, addr);
	if (pud_none(*pud)) {
		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
		if (!p)
			return NULL;
		pud_populate(&init_mm, pud, p);
	}
	return pud;
}

p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
{
	p4d_t *p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d)) {
		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
		if (!p)
			return NULL;
		p4d_populate(&init_mm, p4d, p);
	}
	return p4d;
}

pgd_t * __meminit vmemmap_pgd_populate(unsigned long addr, int node)
{
	pgd_t *pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd)) {
		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
		if (!p)
			return NULL;
		pgd_populate(&init_mm, pgd, p);
	}
	return pgd;
}

int __meminit vmemmap_populate_basepages(unsigned long start,
					 unsigned long end, int node)
{
	unsigned long addr = start;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	for (; addr < end; addr += PAGE_SIZE) {
		pgd = vmemmap_pgd_populate(addr, node);
		if (!pgd)
			return -ENOMEM;
		p4d = vmemmap_p4d_populate(pgd, addr, node);
		if (!p4d)
			return -ENOMEM;
		pud = vmemmap_pud_populate(p4d, addr, node);
		if (!pud)
			return -ENOMEM;
		pmd = vmemmap_pmd_populate(pud, addr, node);
		if (!pmd)
			return -ENOMEM;
		pte = vmemmap_pte_populate(pmd, addr, node);
		if (!pte)
			return -ENOMEM;
		vmemmap_verify(pte, node, addr, addr + PAGE_SIZE);
	}

	return 0;
}

struct page * __meminit __populate_section_memmap(unsigned long pfn,
		unsigned long nr_pages, int nid, struct vmem_altmap *altmap)
{
	unsigned long start;
	unsigned long end;

	/*
	 * The minimum granularity of memmap extensions is
	 * PAGES_PER_SUBSECTION as allocations are tracked in the
	 * 'subsection_map' bitmap of the section.
	 */
	end = ALIGN(pfn + nr_pages, PAGES_PER_SUBSECTION);
	pfn &= PAGE_SUBSECTION_MASK;
	nr_pages = end - pfn;

	start = (unsigned long) pfn_to_page(pfn);
	end = start + nr_pages * sizeof(struct page);

	if (vmemmap_populate(start, end, nid, altmap))
		return NULL;

	return pfn_to_page(pfn);
}
