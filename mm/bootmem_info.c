// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/mm/bootmem_info.c
 *
 *  Copyright (C)
 */
#include <linux/mm.h>
#include <linux/compiler.h>
#include <linux/memblock.h>
#include <linux/bootmem_info.h>
#include <linux/memory_hotplug.h>
#include <linux/pagewalk.h>

void get_page_bootmem(unsigned long info, struct page *page, unsigned long type)
{
	page->freelist = (void *)type;
	SetPagePrivate(page);
	set_page_private(page, info);
	page_ref_inc(page);
}

void put_page_bootmem(struct page *page)
{
	unsigned long type;

	type = (unsigned long) page->freelist;
	BUG_ON(type < MEMORY_HOTPLUG_MIN_BOOTMEM_TYPE ||
	       type > MEMORY_HOTPLUG_MAX_BOOTMEM_TYPE);

	if (page_ref_dec_return(page) == 1) {
		page->freelist = NULL;
		ClearPagePrivate(page);
		set_page_private(page, 0);
		INIT_LIST_HEAD(&page->lru);
		free_reserved_page(page);
	}
}

#ifndef CONFIG_SPARSEMEM_VMEMMAP
static void __init register_page_bootmem_info_section(unsigned long start_pfn)
{
	unsigned long mapsize, section_nr, i;
	struct mem_section *ms;
	struct page *page, *memmap;
	struct mem_section_usage *usage;

	section_nr = pfn_to_section_nr(start_pfn);
	ms = __nr_to_section(section_nr);

	/* Get section's memmap address */
	memmap = sparse_decode_mem_map(ms->section_mem_map, section_nr);

	/*
	 * Get page for the memmap's phys address
	 * XXX: need more consideration for sparse_vmemmap...
	 */
	page = virt_to_page(memmap);
	mapsize = sizeof(struct page) * PAGES_PER_SECTION;
	mapsize = PAGE_ALIGN(mapsize) >> PAGE_SHIFT;

	/* remember memmap's page */
	for (i = 0; i < mapsize; i++, page++)
		get_page_bootmem(section_nr, page, SECTION_INFO);

	usage = ms->usage;
	page = virt_to_page(usage);

	mapsize = PAGE_ALIGN(mem_section_usage_size()) >> PAGE_SHIFT;

	for (i = 0; i < mapsize; i++, page++)
		get_page_bootmem(section_nr, page, MIX_SECTION_INFO);

}
#else /* CONFIG_SPARSEMEM_VMEMMAP */
static int __init bootmem_pte_entry(pte_t *pte, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct page *page = pte_page(*pte);
	unsigned long *section_nr = walk->private;

	get_page_bootmem(*section_nr, page, SECTION_INFO);

	return 0;
}

static int __init bootmem_pmd_entry(pmd_t *pmd, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct page *page = pmd_page(*pmd);
	unsigned long *section_nr = walk->private;

	if (pmd_leaf(*pmd)) {
		unsigned int nr_pages = 1 << (PMD_SHIFT - PAGE_SHIFT);

		while (nr_pages--)
			get_page_bootmem(*section_nr, page++, SECTION_INFO);
	} else {
		get_page_bootmem(*section_nr, page, MIX_SECTION_INFO);
	}

	return 0;
}

static int __init bootmem_pud_entry(pud_t *pud, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct page *page = pud_page(*pud);
	unsigned long *section_nr = walk->private;

	get_page_bootmem(*section_nr, page, MIX_SECTION_INFO);

	return 0;
}

static int __init bootmem_p4d_entry(p4d_t *p4d, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct page *page = p4d_page(*p4d);
	unsigned long *section_nr = walk->private;

	get_page_bootmem(*section_nr, page, MIX_SECTION_INFO);

	return 0;
}

static int __init bootmem_pgd_entry(pgd_t *pgd, unsigned long addr,
				    unsigned long next, struct mm_walk *walk)
{
	struct page *page = pgd_page(*pgd);
	unsigned long *section_nr = walk->private;

	get_page_bootmem(*section_nr, page, MIX_SECTION_INFO);

	return 0;
}

static int __init register_page_bootmem_memmap(unsigned long section_nr,
					       struct page *memmap)
{
	struct mm_struct *mm = &init_mm;
	struct page *memmap_end = memmap + PAGES_PER_SECTION;

	static const struct mm_walk_ops ops __initconst = {
		.pgd_entry = bootmem_pgd_entry,
		.p4d_entry = bootmem_p4d_entry,
		.pud_entry = bootmem_pud_entry,
		.pmd_entry = bootmem_pmd_entry,
		.pte_entry = bootmem_pte_entry,
	};

	down_read(&mm->mmap_sem);
	BUG_ON(walk_page_range_novma(mm, (unsigned long)memmap,
				     (unsigned long)memmap_end,
				     &ops, &section_nr));
	up_read(&mm->mmap_sem);

	return 0;
}

static void __init register_page_bootmem_info_section(unsigned long start_pfn)
{
	unsigned long mapsize, section_nr, i;
	struct mem_section *ms;
	struct page *page, *memmap;
	struct mem_section_usage *usage;

	section_nr = pfn_to_section_nr(start_pfn);
	ms = __nr_to_section(section_nr);

	memmap = sparse_decode_mem_map(ms->section_mem_map, section_nr);

	register_page_bootmem_memmap(section_nr, memmap);

	usage = ms->usage;
	page = virt_to_page(usage);

	mapsize = PAGE_ALIGN(mem_section_usage_size()) >> PAGE_SHIFT;

	for (i = 0; i < mapsize; i++, page++)
		get_page_bootmem(section_nr, page, MIX_SECTION_INFO);
}
#endif /* !CONFIG_SPARSEMEM_VMEMMAP */

static void __init register_page_bootmem_info_node(struct pglist_data *pgdat)
{
	unsigned long i, pfn, end_pfn, nr_pages;
	int node = pgdat->node_id;
	struct page *page;

	nr_pages = PAGE_ALIGN(sizeof(struct pglist_data)) >> PAGE_SHIFT;
	page = virt_to_page(pgdat);

	for (i = 0; i < nr_pages; i++, page++)
		get_page_bootmem(node, page, NODE_INFO);

	pfn = pgdat->node_start_pfn;
	end_pfn = pgdat_end_pfn(pgdat);

	/* register section info */
	for (; pfn < end_pfn; pfn += PAGES_PER_SECTION) {
		/*
		 * Some platforms can assign the same pfn to multiple nodes - on
		 * node0 as well as nodeN.  To avoid registering a pfn against
		 * multiple nodes we check that this pfn does not already
		 * reside in some other nodes.
		 */
		if (pfn_valid(pfn) && (early_pfn_to_nid(pfn) == node))
			register_page_bootmem_info_section(pfn);
	}
}

void __init register_page_bootmem_info(void)
{
	int i;

	for_each_online_node(i)
		register_page_bootmem_info_node(NODE_DATA(i));
}
