/*
 * RISC-V Trap handlers
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

#include <xen/domain_page.h>
#include <xen/const.h>
#include <xen/errno.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/livepatch.h>
#include <xen/mem_access.h>
#include <xen/mm.h>
#include <xen/perfc.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/string.h>
#include <xen/symbols.h>
#include <xen/version.h>
#include <xen/virtual_region.h>

#include <asm/sbi.h>
#include <asm/traps.h>
#include <asm/guest_access.h>

/* Included just for hardcoded values during development */
#include <asm/setup.h>

#include <public/sched.h>
#include <public/xen.h>

void __handle_exception(void)
{
    /* TODO */
    BUG();
}

void show_stack(const struct cpu_user_regs *regs)
{
    /* TODO */
    BUG();
}

void show_execution_state(const struct cpu_user_regs *regs)
{
    /* TODO */
    BUG();
}

void vcpu_show_execution_state(struct vcpu *v)
{
    /* TODO */
    BUG();
}

void arch_hypercall_tasklet_result(struct vcpu *v, long res)
{
	/* TODO */
    BUG();
}

enum mc_disposition arch_do_multicall_call(struct mc_state *state)
{
    /* TODO */
    BUG();
    return mc_continue;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
