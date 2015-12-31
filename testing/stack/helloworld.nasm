; SLAE - Stack (Linux/x86)
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; SLAE-721

BITS 32

global _start
section .text

; syscalls kernel
SYS_WRITE equ 0x04
SYS_EXIT  equ 0x01

; arguments
STDOUT equ 0x01

_start:

	; ssize_t write(int fd, const void *buf, size_t count);
	xor eax, eax
	mov al, SYS_WRITE ; syscall write

	; file descriptor - int fd
	; 0 stdin, 1 stdout, 2 stderr
	xor ebx, ebx
	mov bl, STDOUT    ; fd: 0x01

	; push the string "Hello World!\n"
	; in reverse order to the stack!
	push 0x0a21646c   ; '\n!dl'
	push 0x726f5720   ; 'roW '
	push 0x6f6c6c65   ; 'olle'
	push 0x48         ; 'H'

	; save the stack address
	; into the ecx register as
	; parameter for the write()
	; function.
	mov ecx, esp

	; size_t count
	; 0x10 (16) is the size of the
	; string: "Hello World!\n"
	xor edx, edx
	mov dl, 0x10
	int 0x80

	; void _exit(int status);
	xor eax, eax
	mov al, SYS_EXIT  ; syscall exit
	xor ebx, ebx      ; exit status (0)
	int 0x80
