// SPDX-License-Identifier: GPL-2.0-only

#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/shrinker.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/text-patching.h>
#include <linux/memory.h>

#define DIRECTMAP_PROTECTED	0
#define DIRECTMAP_UNPROTECTED	1

static LIST_HEAD(pages);
static int page_cnt;
static DEFINE_SPINLOCK(pages_lock);
static DEFINE_MUTEX(pages_mutex);

#define DEFINE_RANGE_CALC(x) struct range_calc x = {.min = ULONG_MAX, .max = 0}

struct range_calc {
	unsigned long min;
	unsigned long max;
};

static inline void grow_range(struct range_calc *grower, unsigned long addr, unsigned long size)
{
	if (addr < grower->min)
		grower->min = addr;
	if (addr + size > grower->max)
		grower->max = addr;
}

static inline void grow_range_page(struct range_calc *grower, struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);

	if (!addr)
		return;

	grow_range(grower, addr, PAGE_SIZE);
}

static inline bool has_range(struct range_calc *grower)
{
	return grower->min != ULONG_MAX && grower->max != 0;
}

static unsigned long perm_shrink_count(struct shrinker *shrinker, struct shrink_control *sc)
{
	unsigned long ret;

	spin_lock(&pages_lock);
	ret = page_cnt;
	spin_unlock(&pages_lock);

	return ret;
}

static struct page *__get_perm_page(void)
{
	struct page *page;

	spin_lock(&pages_lock);
	page = list_first_entry(&pages, struct page, lru);
	list_del(&page->lru);
	spin_unlock(&pages_lock);

	return page;
}

static unsigned long perm_shrink_scan(struct shrinker *shrinker, struct shrink_control *sc)
{
	DEFINE_RANGE_CALC(range);
	static LIST_HEAD(to_free_list);
	struct page *page, *tmp;
	unsigned int i, cnt = 0;

	for (i = 0; i < sc->nr_to_scan; i++) {
		page = __get_perm_page();
		if (!page)
			continue;

		grow_range_page(&range, page);
		set_direct_map_default_noflush(page);
		list_add(&page->lru, &to_free_list);
		cnt++;
	}

	if (has_range(&range))
		flush_tlb_kernel_range(range.min, range.max);

	list_for_each_entry_safe(page, tmp, &to_free_list, lru)
		__free_pages(page, 0);

	return cnt;
}

static struct shrinker perm_shrinker = {
	.count_objects = perm_shrink_count,
	.scan_objects = perm_shrink_scan,
	.seeks = DEFAULT_SEEKS
};

static bool replenish_pages_one(void)
{
	struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);

	if (!page)
		return false;

	spin_lock(&pages_lock);
	list_add(&page->lru, &pages);
	page->private = DIRECTMAP_UNPROTECTED;
	page_cnt++;
	spin_unlock(&pages_lock);

	return true;
}

static bool replenish_pages(void)
{
	struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 9); /* 2MB */
	DEFINE_RANGE_CALC(range);
	int convert_ret = 0;
	int i;

	if (!page)
		return replenish_pages_one();

	for (i = 0; i < 512; i++)
		convert_ret |= set_direct_map_invalid_noflush(&page[i]);

	if (convert_ret)
		goto convert_fail;

	spin_lock(&pages_lock);
	for (i = 0; i < 512; i++) {
		list_add(&page[i].lru, &pages);
		page[i].private = DIRECTMAP_PROTECTED;
		grow_range_page(&range, page);
	}
	page_cnt += 512;
	spin_unlock(&pages_lock);

	flush_tlb_kernel_range(range.min, range.max);

	vm_unmap_aliases();

	return true;

convert_fail:
	for (i = 0; i < 512; i++) {
		set_direct_map_default_noflush(&page[i]);
		__free_pages(&page[i], 0);
	}

	return false;
}

static struct page *get_perm_page(void)
{
	struct page *page;

	if (!page_cnt && !replenish_pages())
		return NULL;

	spin_lock(&pages_lock);
	page = list_first_entry(&pages, struct page, lru);
	page_cnt--;
	list_del(&page->lru);
	spin_unlock(&pages_lock);

	return page;
}

static void __perm_free_page(struct page *page)
{
	spin_lock(&pages_lock);
	list_add(&page->lru, &pages);
	page_cnt++;
	spin_unlock(&pages_lock);
}

static void __perm_free_pages(struct page **page, int count)
{
	int i;

	spin_lock(&pages_lock);
	for (i = 0; i < count; i++)
		list_add(&page[i]->lru, &pages);
	page_cnt += count;
	spin_unlock(&pages_lock);
}


static inline pgprot_t perms_to_prot(virtual_perm perms)
{
	switch (perms) {
	case PERM_RX:
		return PAGE_KERNEL_ROX;
	case PERM_RWX:
		return PAGE_KERNEL_EXEC;
	case PERM_RW:
		return PAGE_KERNEL;
	case PERM_R:
		return PAGE_KERNEL_RO;
	default:
		return __pgprot(0);
	}
}

static bool map_alloc(struct perm_allocation *alloc)
{
	alloc->mapped = true;
	return !map_kernel_range(perm_alloc_address(alloc), get_vm_area_size(alloc->area),
			     perms_to_prot(alloc->cur_perm), alloc->pages);
}

struct perm_allocation *perm_alloc(unsigned long vstart, unsigned long vend, unsigned long page_cnt,
				   virtual_perm perms)
{
	struct perm_allocation *alloc;
	DEFINE_RANGE_CALC(range);
	int i, j;

	if (!page_cnt)
		return NULL;

	alloc = kmalloc(sizeof(struct perm_allocation), GFP_KERNEL | __GFP_ZERO);

	if (!alloc)
		return NULL;

	alloc->area = __get_vm_area_caller(page_cnt << PAGE_SHIFT, VM_MAP, vstart, vend,
					   __builtin_return_address(0));

	if (!alloc->area)
		goto free_alloc;

	alloc->pages = kvmalloc(page_cnt * sizeof(struct page *), __GFP_RECLAIM|GFP_KERNEL);
	if (!alloc->pages)
		goto free_area;

	alloc->size = (unsigned long)get_vm_area_size(alloc->area);
	alloc->offset = 0;
	alloc->writable = 0;
	alloc->mapped = false;
	alloc->cur_perm = perms;

	/* TODO if this will be RW, we don't need unmapped pages, better to conserve those */
	for (i = 0; i < page_cnt; i++) {
		alloc->pages[i] = get_perm_page();
		if (alloc->pages[i]->private != DIRECTMAP_PROTECTED)
			continue;

		grow_range_page(&range, alloc->pages[i]);
		if (set_direct_map_invalid_noflush(alloc->pages[i]))
			goto convert_fail;
		alloc->pages[i]->private = DIRECTMAP_PROTECTED;
	}

	/*
	 * Flush any pages that were removed in the loop above. In the event of no pages in the
	 * cache, these may be scattered about single pages, so flush here to only have a single
	 * flush instead of one for each replenish_pages_one() call.
	 */
	if (has_range(&range)) {
		flush_tlb_kernel_range(range.min, range.max);
		vm_unmap_aliases();
	}

	if (i != page_cnt)
		goto free_pages;

	/* TODO: Need to zero these pages */
	if (!map_alloc(alloc))
		goto free_pages;

	return alloc;

free_pages:
	__perm_free_pages(alloc->pages, i);
	kvfree(alloc->pages);
free_area:
	remove_vm_area(alloc->area->addr);
free_alloc:
	kfree(alloc);

	return NULL;

convert_fail:
	for (j = 0; j < i - 1; j++)
		__perm_free_page(alloc->pages[j]);

	return NULL;
}

unsigned long perm_writable_addr(struct perm_allocation *alloc, unsigned long addr)
{
	/* If this is already mapped and writable, just write to the actual kva */
	if (alloc->mapped && (alloc->cur_perm & PERM_W))
		return addr;

	/* TODO lock or callers need to synchronize? */
	if (!alloc->writable)
		alloc->writable = vmalloc(alloc->size);

	return (unsigned long)alloc->writable + (addr - perm_alloc_address(alloc));
}

bool perm_writable_finish(struct perm_allocation *alloc)
{
	unsigned long addr;
	void *writable;
	int i;

	if (!alloc)
		return false;
	if (!alloc->writable)
		return true;

	addr = perm_alloc_address(alloc);

	writable = (void *)perm_writable_addr(alloc, addr);

	mutex_lock(&text_mutex);
	for (i = 0; i < perm_alloc_size(alloc); i += PAGE_SIZE)
		text_poke((void *)(addr + i), writable + i, PAGE_SIZE);
	mutex_unlock(&text_mutex);

	vfree(alloc->writable);

	alloc->writable = 0;

	return true;
}

static inline pgprot_t get_set(virtual_perm perms)
{
	pteval_t ret = 0;

	if (perms)
		ret = _PAGE_PRESENT;

	if (perms & PERM_W)
		ret |= _PAGE_RW;

	if (~perms & PERM_X)
		ret |= _PAGE_NX;

	return __pgprot(ret);
}

static inline pgprot_t get_unset(virtual_perm perms)
{
	pteval_t ret = 0;

	if (!perms)
		ret = _PAGE_PRESENT;

	if (~perms & PERM_W)
		ret |= _PAGE_RW;

	if (perms & PERM_X)
		ret |= _PAGE_NX;

	return __pgprot(ret);
}

bool perm_change(struct perm_allocation *alloc, virtual_perm perms)
{
	pgprot_t set = get_set(perms);
	pgprot_t clr = get_unset(perms);
	unsigned long start;

	if (!alloc)
		return false;

	if (!(alloc->cur_perm ^ perms))
		return true;

	start = perm_alloc_address(alloc);

	set_memory_noalias_noflush(start, perm_alloc_size(alloc) >> PAGE_SHIFT, set, clr);

	flush_tlb_kernel_range(start, start + perm_alloc_size(alloc));

	return true;
}

static inline bool perms_need_flush(struct perm_allocation *alloc)
{
	return alloc->cur_perm & PERM_X;
}

void perm_free(struct perm_allocation *alloc)
{
	unsigned long size, addr;
	int page_cnt;

	if (!alloc)
		return;

	if (alloc->writable)
		vfree(alloc->writable);

	size = get_vm_area_size(alloc->area);
	addr = perm_alloc_address(alloc);
	page_cnt = size >> PAGE_SHIFT;

	vunmap((void *)addr);

	if (perms_need_flush(alloc))
		flush_tlb_kernel_range(addr, addr + size);

	__perm_free_pages(alloc->pages, page_cnt);

	kfree(alloc->pages);
}

void perm_memset(struct perm_allocation *alloc, char val)
{
	if (!alloc)
		return;

	memset((void *)perm_writable_base(alloc), val, perm_alloc_size(alloc));
}

static int __init perm_alloc_init(void)
{
	return register_shrinker(&perm_shrinker);
}
device_initcall(perm_alloc_init);
