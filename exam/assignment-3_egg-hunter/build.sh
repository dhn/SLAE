#!/usr/bin/env bash
# $Id: build.sh,v 1.5 2016/01/07 22:58:33 dhn Exp $

# Title: assembles, links and extracts
#        shellcode from binary
# File: build.sh
# Author: Dennis 'dhn' Herrmann
# SLAE-721

export PATH=/sbin:/usr/sbin:/bin:/usr/bin
export LC_ALL="C"

OBJDUMP=${OBJDUMP:-objdump}
NASM=${NASM:-nasm}
XXD=${XXD:-xxd}
GCC=${GCC:-gcc}
LD=${LD:-ld}

# DEBUG
DEBUG="false"

# Activate debugging
if [ "${DEBUG}" == "true" ]; then
	printf '[!] DEBUG is activated ...\n'
	set -x
fi

die() {
	printf "ERROR: $*\n" >&2;
	exit 1;
}

build() {
	local ARGV=${1}

	printf '[+] Assembling ...\n'
	${NASM} -f elf32 -o ${ARGV}.o ${ARGV}.nasm > /dev/null 2>&1

	if [ ! ${?} -eq 0 ]; then
		die "Unable to compile: ${ARGV}"
	fi
}

link() {
	local ARGV=${1}

	printf '[+] Linking ...\n'
	${LD} -o ${ARGV} ${ARGV}.o

	if [ ! ${?} -eq 0 ]; then
		die "Unable to link: ${ARGV}"
	fi
}

extract_shellcode() {
	local ARGV=${1}

	printf '[+] Extract Shellcode from binary ...\n\n'
	${OBJDUMP} -d ${ARGV}        \
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

build_c() {
	local ARGV=${1}

	# create PoC
	printf '[+] Compile PoC ...\n'
	${GCC} -Wl,-z,execstack -fno-stack-protector \
		PoC.c -o PoC > /dev/null 2>&1

	if [ ! ${?} -eq 0 ]; then
		die "Unable to compile: PoC.c"
	fi
}

run_shellcode() {
	if [ -z ${RUN} ]; then
		printf '[+] Run PoC ...\n'
		./PoC
	fi
}

clean() {
	local ARGV=${1}

	if [ -z ${CLEAN} ]; then
		printf '[+] Clean ...\n'
		rm -f *.o *.bin ${ARGV}
	fi
}

main() {
	local ARG=${1}

	build ${ARG}
	link ${ARG}
	extract_shellcode ${ARG}
	build_c ${ARG}
	run_shellcode
	clean ${ARG}
	printf '[+] Done!\n'
}

usage() {
cat << EOF
Usage: $(basename $0) [OPTIONS] file
Options:
  -b file  Assembles, links and extracts
           shellcode from binary.
  -c       Disable cleaning
  -r       Disable run PoC
  -h       Display usage
Example:
  $(basename $0) -b <*.nasm>
EOF
}

# getopts
while getopts "b:crh" opt; do
	case $opt in
		b)
			main ${OPTARG}
			;;
		c)
			CLEAN="false"
			;;
		r)
			RUN="false"
			;;
		h)
			usage
			;;
	esac
done
shift $((OPTIND -1))

# Default - usage
if [ ${OPTIND} -eq 1 ]; then
	usage
	exit 0
fi
