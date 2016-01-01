#!/usr/bin/env bash
# $Id: build.sh,v 1.3 2016/01/01 22:18:38 dhn Exp $

# Title: assembles, links and extracts
#        shellcode from binary
# File: build.sh
# Author: Dennis 'dhn' Herrmann
# SLAE-721

create_shellcode_file() {
cat << EOF > shellcode.c
#include <stdio.h>
#include "shellcode.h"

void main()
{
	printf("Shellcode Length:  %d\n", code_len);
	int (*ret)() = (int(*)())code;
	ret();
}
EOF
}

build() {
	local ARGV=${1}

	printf '[+] Assembling ...\n'
	nasm -f elf32 -o ${ARGV}.o ${ARGV}.nasm
	nasm ${ARGV}.nasm -o ${ARGV}.bin
}

link() {
	local ARGV=${1}

	printf '[+] Linking ...\n'
	ld -o ${ARGV} ${ARGV}.o
}

extract_shellcode() {
	local ARGV=${1}

	printf '[+] Extract Shellcode from binary ...\n\n'
	objdump -d ${ARGV}       \
		| grep '[0-9a-f]:'   \
		| grep -v 'file'     \
		| cut -f2 -d:        \
		| cut -f1-6 -d' '    \
		| tr -s ' '          \
		| tr '\t' ' '        \
		| sed 's/ $//g'      \
		| sed 's/ /\\x/g'    \
		| paste -d '' -s     \
		| grep -oE '.{1,32}' \
		| sed 's/^/"/'       \
		| sed 's/$/"/g'
	printf '\n'
}

create_header() {
	local ARGV=${1}

	printf '[+] Create C-Header file ...\n'
	xxd -i ${ARGV}.bin \
		| sed "s/${ARGV}_bin/code/g" > shellcode.h
}

build_c() {
	local ARGV=${1}

	# create shellcode.c
	if [ ! -f ./shellcode.c ]; then
		create_shellcode_file
	fi

	printf '[+] Compile PoC ...\n'
	gcc -Wl,-z,execstack \
		-fno-stack-protector shellcode.c -o shellcode
}

run_shellcode() {
	printf '[+] Run PoC ...\n\n'
	./shellcode
}

clean() {
	local ARGV=${1}

	printf '[+] Clean ...\n'
	rm -f *.o *.bin shellcode* ${ARGV}
}

build $1
link $1
extract_shellcode $1
create_header $1
build_c $1
run_shellcode
clean $1
echo '[+] Done!'
