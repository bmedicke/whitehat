#!/usr/bin/env python3

from pwn import *

elf = ELF("bin")
libc = elf.libc
rop = ROP(elf)

puts_got = hex(elf.got["puts"])
puts_plt = hex(elf.plt["puts"])
pop_rdi_ret = hex(rop.find_gadget(["pop rdi", "ret"])[0])
system_call = hex(libc.sym["system"])
exit_call = hex(libc.sym["exit"])
bin_sh = hex(next(libc.search(b"/bin/sh")))

print("puts@got\t\t", puts_got)
print("puts@plt\t\t", puts_plt)
print("pop rdi;ret;\t", pop_rdi_ret)
print("pop rdi;ret;\t", pop_rdi_ret)
print("exit call\t\t", exit_call)
print("system call\t", system_call)
print("/bin/sh\t\t", bin_sh)

x = rop.find_gadget(["pop rsi"])

print(x)
