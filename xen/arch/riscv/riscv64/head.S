#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/init.h>
#include <asm/csr.h>
#include <asm/config.h>
#include <asm/processor.h>

	.section .text.header, "ax", %progbits
ENTRY(start)
_start_hang:
	wfi
	j	_start_hang
ENDPROC(start)
