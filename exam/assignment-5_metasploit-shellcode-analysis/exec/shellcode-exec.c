/*
 * Title: msfvenom - exec "ifconfig wlan0"  PoC
 * Platform: linux/x86
 * Date: 2015-01-15
 * Author: Dennis 'dhn' Herrmann
 * Website: https://zer0-day.pw
 * Github: https://github.com/dhn/SLAE/
 * SLAE-721
 */
#include <stdio.h>

unsigned char shellcode[] =
	"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
	"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x0f\x00\x00\x00\x69"
	"\x66\x63\x6f\x6e\x66\x69\x67\x20\x77\x6c\x61\x6e\x30\x00\x57"
	"\x53\x89\xe1\xcd\x80";

void
main(void)
{
	int (*ret)() = (int(*)())shellcode;
	ret();
}
