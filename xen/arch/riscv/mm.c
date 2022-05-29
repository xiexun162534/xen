/*
 * xen/arch/riscv/mm.c
 *
 * MMU code for a RISC-V RV32/64 with hypervisor extensions.
 *
 * Copyright (c) 2019 Bobby Eshleman <bobbyeshleman@gmail.com>
 *
 * Based on code that is Copyright (c) 2018 Anup Patel.
 * Based on code that is Copyright (c) 2011 Tim Deegan <tim@xen.org>
 * Based on code that is Copyright (c) 2011 Citrix Systems.
 *
 * Parts of this code are based on:
 *     ARM/Xen: xen/arch/arm/mm.c.
 *     Xvisor: arch/riscv/cpu/generic/cpu_mmu_initial_pgtbl.c
 *         (https://github.com/xvisor/xvisor/tree/v0.2.11)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/compile.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <asm/p2m.h>
#include <public/domctl.h>
#include <asm/page.h>
#include <xen/preempt.h>
#include <xen/errno.h>
#include <xen/grant_table.h>
#include <xen/softirq.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <public/memory.h>
#include <xen/sched.h>
#include <xen/vmap.h>
#include <xsm/xsm.h>
#include <xen/pfn.h>
#include <xen/sizes.h>
#include <asm/setup.h>
#include <xen/libfdt/libfdt.h>

#define XEN_TABLE_MAP_FAILED 0
#define XEN_TABLE_SUPER_PAGE 1
#define XEN_TABLE_NORMAL_PAGE 2

enum pt_level {
    pt_level_zero,
    pt_level_one,
#if CONFIG_PAGING_LEVELS == 3
    pt_level_two,
#endif
};

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))
#undef mfn_to_virt
#define mfn_to_virt(mfn) __mfn_to_virt(mfn_x(mfn))

/* Limits of the Xen heap */
mfn_t xenheap_mfn_start __read_mostly = INVALID_MFN_INITIALIZER;
mfn_t xenheap_mfn_end __read_mostly;
vaddr_t xenheap_virt_end __read_mostly;
vaddr_t xenheap_virt_start __read_mostly;
unsigned long xenheap_base_pdx __read_mostly;

/* Limits of frametable */
unsigned long frametable_virt_end __read_mostly;
unsigned long frametable_base_pdx;

static pte_t xen_fixmap[PAGE_ENTRIES] __attribute__((__aligned__(4096)));

#define THIS_CPU_PGTABLE xen_second_pagetable

/* Used by _setup_initial_pagetables() and initialized by head.S */
extern unsigned long _text_start;
extern unsigned long _text_end;
extern unsigned long _cpuinit_start;
extern unsigned long _cpuinit_end;
extern unsigned long _spinlock_start;
extern unsigned long _spinlock_end;
extern unsigned long _init_start;
extern unsigned long _init_end;
extern unsigned long _rodata_start;
extern unsigned long _rodata_end;

paddr_t phys_offset;
unsigned long max_page;

static inline pte_t mfn_to_pte(mfn_t mfn)
{
    unsigned long pte = mfn_x(mfn) << PTE_SHIFT;
    return (pte_t){ .pte = pte };
}

void *__init arch_vmap_virt_end(void)
{
    return (void *)VMAP_VIRT_END;
}

static inline pte_t mfn_to_xen_entry(mfn_t mfn)
{
    return mfn_to_pte(mfn);
}

/* Map a 4k page in a fixmap entry */
void set_fixmap(unsigned map, mfn_t mfn, unsigned int flags)
{
    pte_t pte;

    pte = mfn_to_xen_entry(mfn);
    pte.pte |= PTE_LEAF_DEFAULT;
    write_pte(&xen_fixmap[pagetable_zeroeth_index(FIXMAP_ADDR(map))], pte);
}

/* Remove a mapping from a fixmap entry */
void clear_fixmap(unsigned map)
{
    pte_t pte = {0};
    write_pte(&xen_fixmap[pagetable_zeroeth_index(FIXMAP_ADDR(map))], pte);
}

#ifdef CONFIG_DOMAIN_PAGE
void *map_domain_page_global(mfn_t mfn)
{
    return vmap(&mfn, 1);
}

void unmap_domain_page_global(const void *va)
{
    vunmap(va);
}
#endif

void flush_page_to_ram(unsigned long mfn, bool sync_icache)
{
    void *va = map_domain_page(_mfn(mfn));
    unmap_domain_page(va);

    /* TODO */

    if ( sync_icache )
        invalidate_icache();
}

enum xenmap_operation { INSERT, REMOVE, MODIFY, RESERVE };

int map_pages_to_xen(unsigned long virt, mfn_t mfn, unsigned long nr_mfns,
                     unsigned int flags)
{
    return -ENOSYS;
}

int populate_pt_range(unsigned long virt, unsigned long nr_mfns)
{
    (void) virt;
    (void) nr_mfns;

    /* TODO */

    return  0;
}

int destroy_xen_mappings(unsigned long v, unsigned long e)
{
    (void) v;
    (void) e;

    /* TODO */

    return 0;
}

int modify_xen_mappings(unsigned long s, unsigned long e, unsigned int flags)
{
    (void) s;
    (void) e;
    (void) flags;

    /* TODO */

    return 0;
}

void arch_dump_shared_mem_info(void)
{
    /* TODO */
}

int donate_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    ASSERT_UNREACHABLE();
    return -ENOSYS;
}

int steal_page(struct domain *d, struct page_info *page, unsigned int memflags)
{
    return -EOPNOTSUPP;
}

int page_is_ram_type(unsigned long mfn, unsigned long mem_type)
{
    ASSERT_UNREACHABLE();
    return 0;
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    BUG();
    return 0;
}

void share_xen_page_with_guest(struct page_info *page, struct domain *d,
                               enum XENSHARE_flags flags)
{
    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

    /* TODO */

    spin_unlock(&d->page_alloc_lock);
}

int xenmem_add_to_physmap_one(struct domain *d, unsigned int space,
                              union add_to_physmap_extra extra,
                              unsigned long idx, gfn_t gfn)
{
    /* TODO */

    return 0;
}

long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    /* TODO */
    return 0;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{
    unsigned long x, y = page->count_info;
    struct domain *owner;

    do
    {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid.
         */
        if ( unlikely(((x + 1) & PGC_count_mask) <= 1) )
            return NULL;
    } while ( (y = cmpxchg(&page->count_info, x, x + 1)) != x );

    owner = page_get_owner(page);
    ASSERT(owner);

    return owner;
}

void put_page(struct page_info *page)
{
    unsigned long nx, x, y = page->count_info;

    do
    {
        ASSERT((y & PGC_count_mask) != 0);
        x = y;
        nx = x - 1;
    } while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    if ( unlikely((nx & PGC_count_mask) == 0) )
    {
        free_domheap_page(page);
    }
}

bool get_page(struct page_info *page, const struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return true;

    if ( owner != NULL )
        put_page(page);

    return false;
}

/* Common code requires get_page_type and put_page_type.
 * We don't care about typecounts so we just do the minimum to make it
 * happy. */
int get_page_type(struct page_info *page, unsigned long type)
{
    return 1;
}

void put_page_type(struct page_info *page)
{
    return;
}

/*
 * This function should only be used to remap device address ranges
 * TODO: add a check to verify this assumption
 */
void __iomem *ioremap_attr(paddr_t pa, size_t len, unsigned int attributes)
{
    mfn_t mfn = _mfn(PFN_DOWN(pa));
    unsigned int offs = pa & (PAGE_SIZE - 1);
    unsigned int nr = PFN_UP(offs + len);

    void *ptr = __vmap(&mfn, nr, 1, 1, attributes, VMAP_DEFAULT);

    if ( ptr == NULL )
        return NULL;

    return ptr + offs;
}

void *ioremap(paddr_t pa, size_t len)
{
    return ioremap_attr(pa, len, PAGE_HYPERVISOR_NOCACHE);
}

#ifdef CONFIG_GRANT_TABLE
void gnttab_clear_flags(struct domain *d, unsigned long nr, uint16_t *addr)
{
	/* TODO */
}

void gnttab_mark_dirty(struct domain *d, mfn_t mfn)
{
	/* TODO */
}

int create_grant_host_mapping(unsigned long addr, mfn_t frame,
                              unsigned int flags, unsigned int cache_flags)
{
	/* TODO */
}

int replace_grant_host_mapping(unsigned long addr, mfn_t mfn,
                               unsigned long new_addr, unsigned int flags)
{
	/* TODO */
}
#endif

bool is_iomem_page(mfn_t mfn)
{
    return !mfn_valid(mfn);
}

unsigned long get_upper_mfn_bound(void)
{
    /* No memory hotplug yet, so current memory limit is the final one. */
    return max_page - 1;
}

/*
 * Map the table that pte points to.
 */
void *map_domain_table(pte_t *pte)
{
    return map_domain_page(maddr_to_mfn((paddr_t)pte_to_paddr(pte)));
}

void unmap_domain_table(pte_t *table)
{
    return unmap_domain_page(table);
}

paddr_t __virt_to_maddr(vaddr_t va)
{
    /* TODO */
    return 0;
}

int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order)
{
    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
