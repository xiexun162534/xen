#include <asm/guest_access.h>
#include <asm/traps.h>
#include <xen/domain_page.h>

unsigned long raw_copy_to_guest(void *to, const void *from, unsigned len)
{
    return -ENOSYS;
}

unsigned long raw_copy_to_guest_flush_dcache(void *to, const void *from,
                                             unsigned len)
{
    return -ENOSYS;
}

unsigned long raw_clear_guest(void *to, unsigned len)
{
    return -ENOSYS;
}

unsigned long raw_copy_from_guest(void *to, const void __user *from, unsigned len)
{
    return -ENOSYS;
}

unsigned long copy_to_guest_phys(struct domain *d,
                                 paddr_t gpa,
                                 void *buf,
                                 unsigned int len)
{
    return -ENOSYS;
}


/**
 * riscv_vcpu_unpriv_read -- Read machine word from Guest memory
 *
 * @vcpu: The VCPU pointer
 * @read_insn: Flag representing whether we are reading instruction
 * @guest_addr: Guest address to read
 * @trap: Output pointer to trap details
 */
unsigned long riscv_vcpu_unpriv_read(struct vcpu *vcpu,
					 bool read_insn,
					 unsigned long guest_addr,
					 struct riscv_trap *trap)
{
    /* TODO */
    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
