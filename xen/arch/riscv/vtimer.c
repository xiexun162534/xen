/*
 * xen/arch/riscv/vtimer.c
 *
 * RISC-V Virtual Timer emulation support
 * 
 * Copyright (c) 2022 Xie Xun <xiexun162534@gmail.com>
 *
 * Based on xen/arch/arm/vtimer.c
 * Ian Campbell <ian.campbell@citrix.com>
 * Copyright (c) 2011 Citrix Systems.
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

#include <xen/timer.h>
#include <xen/sched.h>
#include <asm/domain.h>
#include <asm/time.h>
#include <asm/sbi.h>

int domain_vtimer_init(struct domain *d, struct xen_arch_domainconfig *config)
{
    /* TODO Set time_offset */
    return 0;
}

static void vtimer_expired(void *data)
{
    struct vtimer *t = data;
    send_timer_event(t->v);
}

int vcpu_vtimer_init(struct vcpu *v)
{
    struct vtimer *t = &v->arch.vtimer;

    t->v = v;
    init_timer(&t->timer, vtimer_expired, t, v->processor);

    v->arch.vtimer_initialized = true;

    return 0;
}

void vcpu_timer_destroy(struct vcpu *v)
{
    if ( !v->arch.vtimer_initialized )
        return;

    kill_timer(&v->arch.vtimer.timer);
}

void vtimer_save(struct vcpu *v)
{
    /* Do nothing */
}

void vtimer_restore(struct vcpu *v)
{
    stop_timer(&v->arch.vtimer.timer);
    migrate_timer(&v->arch.vtimer.timer, v->processor);
}

void vtimer_set_timer(struct vtimer *t, uint64_t ticks)
{
    s_time_t expires = ticks_to_ns(ticks - boot_count);
    /* clear pending timer interrupt */
    t->v->arch.hvip &= ~MIP_VSTIP;
    set_timer(&t->timer, expires);
}
