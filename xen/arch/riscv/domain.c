#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/softirq.h>
#include <asm/traps.h>
#include <public/domctl.h>
#include <public/xen.h>

DEFINE_PER_CPU(struct vcpu *, curr_vcpu);

struct vcpu *alloc_dom0_vcpu0(struct domain *dom0)
{
    return vcpu_create(dom0, 0);
}

void context_switch(struct vcpu *prev, struct vcpu *next)
{
    /* TODO */
}

void idle_loop(void)
{
    /* TODO */
}

void noreturn startup_cpu_idle_loop(void)
{
    struct vcpu *v = current;

    ASSERT(is_idle_vcpu(v));

    reset_stack_and_jump(idle_loop);

    /* This function is noreturn */
    BUG();
}

void continue_running(struct vcpu *same)
{
    /* TODO */
}

void sync_local_execstate(void)
{
    /* TODO */
}

void sync_vcpu_execstate(struct vcpu *v)
{
    /* TODO */
}

unsigned long hypercall_create_continuation(
    unsigned int op, const char *format, ...)
{
	/* TODO */

	return 0;
}

struct domain *alloc_domain_struct(void)
{
    return NULL;
}

void free_domain_struct(struct domain *d)
{
    /* TODO */
}

void dump_pageframe_info(struct domain *d)
{
    /* TODO */
}

int arch_sanitise_domain_config(struct xen_domctl_createdomain *config)
{
    return 0;
}


int arch_domain_create(struct domain *d,
                       struct xen_domctl_createdomain *config,
                        unsigned int flags)
{
    return -ENOSYS;
}

void arch_domain_destroy(struct domain *d)
{
    /* TODO */
}

void arch_domain_shutdown(struct domain *d)
{
    /* TODO */
}

void arch_domain_pause(struct domain *d)
{
    /* TODO */
}

void arch_domain_unpause(struct domain *d)
{
    /* TODO */
}

int arch_domain_soft_reset(struct domain *d)
{
    /* TODO */
    return -ENOSYS;
}

void arch_domain_creation_finished(struct domain *d)
{
    /* TODO */
}

int domain_relinquish_resources(struct domain *d)
{
    /* TODO */
    return -ENOSYS;
}

void arch_dump_domain_info(struct domain *d)
{
    /* TODO */
}

long arch_do_vcpu_op(int cmd, struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    /* TODO */
    return -ENOSYS;
}

void arch_dump_vcpu_info(struct vcpu *v)
{
    /* TODO */
}

int arch_set_info_guest(
    struct vcpu *v, vcpu_guest_context_u c)
{
    /* TODO */
    return -ENOSYS;
}

/* taken from arm/domain.c */
struct vcpu *alloc_vcpu_struct(const struct domain *d)
{
    return NULL;
}

void free_vcpu_struct(struct vcpu *v)
{
    /* TODO */
}

int arch_initialise_vcpu(struct vcpu *v, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    /* TODO */
    return -ENOSYS;
}

int arch_vcpu_reset(struct vcpu *v)
{
    /* TODO */
    return -ENOSYS;
}

int arch_vcpu_create(struct vcpu *v)
{
    return -ENOSYS;
}

void arch_vcpu_destroy(struct vcpu *v)
{
    /* TODO */
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
