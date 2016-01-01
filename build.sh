#!/usr/bin/env bash

# Title: assembles, links and extracts shellcode from binary
# File: build.sh
# Author: Dennis 'dhn' Herrmann
# SLAE-721

build() {
	local ARGV=${1}

	echo '[+] Assembling ... '
	nasm -f elf32 -o ${ARGV}.o ${ARGV}.nasm
}

link() {
	echo '[+] Linking ...'
	ld -o $1 $1.o
}

extract_shellcode() {
	local ARGV=${1}

	echo '[+] Extract Shellcode from binary ...'
	echo ''
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
	echo ''
}

build $1
link $1
extract_shellcode $1
echo '[+] Done!'
