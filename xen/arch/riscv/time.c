/*
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

#include <xen/console.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/sched.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/cpu.h>
#include <xen/notifier.h>
#include <asm/acpi.h>
#include <asm/system.h>
#include <asm/time.h>

unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

uint64_t __read_mostly boot_count;


s_time_t get_s_time(void)
{
    uint64_t ticks = get_cycles() - boot_count;
    return ticks_to_ns(ticks);
}


/* VCPU PV timers. */
void send_timer_event(struct vcpu *v)
{
    /* TODO */
}

/* VCPU PV clock. */
void update_vcpu_system_time(struct vcpu *v)
{
    /* TODO */
    BUG();
}

void force_update_vcpu_system_time(struct vcpu *v)
{
    update_vcpu_system_time(v);
}

void domain_set_time_offset(struct domain *d, int64_t time_offset_seconds)
{
    /* TODO */
    BUG();
}

int reprogram_timer(s_time_t timeout)
{
    /* TODO */
    return -ENOSYS;
}
