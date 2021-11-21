/*
 * Based on arch/arm/include/asm/system.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2013 Regents of the University of California
 * Copyright (C) 2017 SiFive
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _ASM_RISCV_BARRIER_H
#define _ASM_RISCV_BARRIER_H

#include <asm/csr.h>
#include <xen/lib.h>

#ifndef __ASSEMBLY__

#define nop()		__asm__ __volatile__ ("nop")

#define RISCV_FENCE(p, s) \
	__asm__ __volatile__ ("fence " #p "," #s : : : "memory")

/* These barriers need to enforce ordering on both devices or memory. */
#define mb()		RISCV_FENCE(iorw,iorw)
#define rmb()		RISCV_FENCE(ir,ir)
#define wmb()		RISCV_FENCE(ow,ow)

/* These barriers do not need to enforce ordering on devices, just memory. */
#define smp_mb()	RISCV_FENCE(rw,rw)
#define smp_rmb()	RISCV_FENCE(r,r)
#define smp_wmb()	RISCV_FENCE(w,w)
#define smp_mb__before_atomic()    smp_mb()
#define smp_mb__after_atomic()     smp_mb()

#define __smp_store_release(p, v)					\
do {									\
	compiletime_assert_atomic_type(*p);				\
	RISCV_FENCE(rw,w);						\
	WRITE_ONCE(*p, v);						\
} while (0)

#define __smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	RISCV_FENCE(r,rw);						\
	___p1;								\
})

static inline unsigned long local_save_flags(void)
{
	return csr_read(sstatus);
}

static inline void local_irq_enable(void)
{
	csr_set(sstatus, SR_SIE);
}

static inline void local_irq_disable(void)
{
	csr_clear(sstatus, SR_SIE);
}

#define local_irq_save(x)                     \
({                                            \
    x = csr_read_clear(CSR_SSTATUS, SR_SIE);      \
    local_irq_disable();                      \
})

static inline void local_irq_restore(unsigned long flags)
{
	csr_set(CSR_SSTATUS, flags & SR_SIE);
}

static inline int local_irq_is_enabled(void)
{
    unsigned long flags = local_save_flags();

    return flags & SR_SIE;
}

#define arch_fetch_and_add(x, v) __sync_fetch_and_add(x, v)

extern struct vcpu *__context_switch(struct vcpu *prev, struct vcpu *next);
extern void __riscv_unpriv_trap(void);

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_BARRIER_H */
