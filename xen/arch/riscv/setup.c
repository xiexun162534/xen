/*
 * xen/arch/riscv/setup.c
 *
 *
 * Early bringup code for a RISC-V RV32/64 with hypervisor
 * extensions (code H).
 *
 * Based off the ARM setup code with copyright Tim Deegan <tim@xen.org>
 *
 * Copyright (c) 2019 Bobby Eshleman <bobbyeshleman@gmail.com>
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

#include <xen/lib.h>
#include <xen/init.h>
#include <asm/sbi.h>
#include <asm/atomic.h>
#include <public/version.h>

domid_t max_init_domid = 0;

struct domain *xen_dom;

bool acpi_disabled = true;

/* The lucky hart to first increment this variable will boot the other cores */
atomic_t hart_lottery;
unsigned long boot_cpu_hartid;
unsigned long total_pages;

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

    snprintf(s, sizeof(s), "xen-%d.%d-riscv ", major, minor);
    safe_strcat(*info, s);
}

/** start_xen - The C entry point
 *
 * The real entry point is in head.S.
 */
void __init start_xen(paddr_t fdt_paddr, paddr_t boot_phys_offset)
{
    sbi_console_putchar('X');
    sbi_console_putchar('e');
    sbi_console_putchar('n');
    sbi_console_putchar('\n');
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
