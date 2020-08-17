// SPDX-License-Identifier: GPL-2.0
/*
 * Free some vmemmap pages of HugeTLB
 *
 * Copyright (c) 2020, Bytedance. All rights reserved.
 *
 *     Author: Muchun Song <songmuchun@bytedance.com>
 */
#ifndef _LINUX_HUGETLB_VMEMMAP_H
#define _LINUX_HUGETLB_VMEMMAP_H
#include <linux/hugetlb.h>

#ifdef CONFIG_HUGETLB_PAGE_FREE_VMEMMAP
void alloc_huge_page_vmemmap(struct hstate *h, struct page *head);
void free_huge_page_vmemmap(struct hstate *h, struct page *head);
void hugetlb_vmemmap_init(struct hstate *h);

int vmemmap_pgtable_prealloc(struct hstate *h, struct list_head *pgtables);
void vmemmap_pgtable_free(struct list_head *pgtables);

unsigned long gigantic_vmemmap_pgtable_prealloc(void);
void gigantic_vmemmap_pgtable_init(struct huge_bootmem_page *m,
				   struct page *head);

/*
 * How many vmemmap pages associated with a HugeTLB page that can be freed
 * to the buddy allocator. The checking of the is_power_of_2() aims to let
 * the compiler help us optimize the code as much as possible.
 */
static inline unsigned int free_vmemmap_pages_per_hpage(struct hstate *h)
{
	return is_power_of_2(sizeof(struct page)) ? h->nr_free_vmemmap_pages : 0;
}
#else
static inline void alloc_huge_page_vmemmap(struct hstate *h, struct page *head)
{
}

static inline void free_huge_page_vmemmap(struct hstate *h, struct page *head)
{
}

static inline int vmemmap_pgtable_prealloc(struct hstate *h,
					   struct list_head *pgtables)
{
	return 0;
}

static inline void vmemmap_pgtable_free(struct list_head *pgtables)
{
}

static inline unsigned long gigantic_vmemmap_pgtable_prealloc(void)
{
	return 0;
}

static inline void gigantic_vmemmap_pgtable_init(struct huge_bootmem_page *m,
						 struct page *head)
{
}

static inline unsigned int free_vmemmap_pages_per_hpage(struct hstate *h)
{
	return 0;
}

static inline void hugetlb_vmemmap_init(struct hstate *h)
{
}
#endif /* CONFIG_HUGETLB_PAGE_FREE_VMEMMAP */
#endif /* _LINUX_HUGETLB_VMEMMAP_H */
