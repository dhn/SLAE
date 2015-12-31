; SLAE - JMP-CALL-POP (Linux/x86)
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; SLAE-721
;
; void main(void) {
;	char* str = "Hello World!";
;	write(0, str, strlen(str);
;	exit(0);
; } 

BITS 32

global _start
section .text

; syscalls kernel
SYS_WRITE equ 0x04
SYS_EXIT  equ 0x01

; arguments
STDOUT equ 0x01

_start:

	; jump to msg label
	jmp short msg

shellcode:

	; ssize_t write(int fd, const void *buf, size_t count);
	xor eax, eax
	mov al, SYS_WRITE ; syscall write

	; file descriptor (0 stdin, 1 stdout, 2 stderr)
	xor ebx, ebx
	mov bl, STDOUT    ; fd: 0x01

	; call shellcode: save the return address
	; of the next instruction into the stack.
	pop ecx

	; size_t count
	; 0x0d is the size of the
	; string: "Hello World!\n"
	xor edx, edx
	mov dl, 0x0d
	int 0x80

	; void _exit(int status);
	xor eax, eax
	mov al, SYS_EXIT  ; syscall exit
	xor ebx, ebx      ; exit status (0)
	int 0x80

msg:

	call shellcode
	message: db "Hello World!", 0xA	
