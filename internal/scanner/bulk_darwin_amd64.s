// Trampoline to libSystem's getattrlistbulk, in the style of
// golang.org/x/sys/unix (zsyscall_darwin_*.s).

#include "textflag.h"

TEXT libc_getattrlistbulk_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_getattrlistbulk(SB)

GLOBL	·libc_getattrlistbulk_trampoline_addr(SB), RODATA, $8
DATA	·libc_getattrlistbulk_trampoline_addr(SB)/8, $libc_getattrlistbulk_trampoline<>(SB)
