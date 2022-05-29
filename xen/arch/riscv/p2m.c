#include <xen/cpu.h>
#include <xen/domain_page.h>
#include <xen/iocap.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <asm/event.h>
#include <asm/flushtlb.h>
#include <asm/page.h>

void memory_type_changed(struct domain *d)
{
}

mfn_t gfn_to_mfn(struct domain *d, gfn_t gfn)
{
    /* TODO */
    return INVALID_MFN;
}

int map_regions_p2mt(struct domain *d,
                     gfn_t gfn,
                     unsigned long nr,
                     mfn_t mfn,
                     p2m_type_t p2mt)
{
    return -ENOSYS;
}

int unmap_regions_p2mt(struct domain *d,
                       gfn_t gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    return -ENOSYS;
}

int map_mmio_regions(struct domain *d,
                     gfn_t start_gfn,
                     unsigned long nr,
                     mfn_t mfn)
{
    return -ENOSYS;
}

int unmap_mmio_regions(struct domain *d,
                       gfn_t start_gfn,
                       unsigned long nr,
                       mfn_t mfn)
{
    return -ENOSYS;
}

int guest_physmap_add_entry(struct domain *d,
                            gfn_t gfn,
                            mfn_t mfn,
                            unsigned long page_order,
                            p2m_type_t t)
{
    return -ENOSYS;
}

int guest_physmap_remove_page(struct domain *d, gfn_t gfn, mfn_t mfn,
                              unsigned int page_order)
{
    return -ENOSYS;
}


void vcpu_mark_events_pending(struct vcpu *v)
{
    /* TODO */
}

void vcpu_update_evtchn_irq(struct vcpu *v)
{
    /* TODO */
}

struct page_info *get_page_from_gfn(struct domain *d, unsigned long gfn,
                                    p2m_type_t *t, p2m_query_t q)
{
    /* TODO */
    return NULL;
}

int set_foreign_p2m_entry(struct domain *d, const struct domain *fd,
                          unsigned long gfn, mfn_t mfn)
{
    return -EOPNOTSUPP;
}

unsigned long p2m_pod_decrease_reservation(struct domain *d, gfn_t gfn,
                                           unsigned int order)
{
    return 0;
}
