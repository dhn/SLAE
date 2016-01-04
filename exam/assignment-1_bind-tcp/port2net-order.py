#!/usr/bin/env python
# Title: Convert Integer to network byte order
# Date: 2015-01-04
# Author: Dennis 'dhn' Herrmann
# Website: https://zer0-day.pw
# Github: https://github.com/dhn/SLAE/
# SLAE-721

# This piece of code  help to  convert an
# integer to the network byte order. This
# is necessary  for  the PORT variable in
# the  bindtcp shellcode. If you  want to
# change it.

import sys
import socket

def convert(port):
    if port <= 65535:
        network_order = socket.htons(port)
        network_hex = hex(network_order)
        return network_order, network_hex
    else:
        print("[!] port range is over 65535")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("usage: %s number" % __file__)
    else:
        port = int(sys.argv[1])
        network, inhex = convert(port)
        print(" port      network order     in hex")
        print("-----------------------------------")
        print('{:>5} {:>18} {:>10}'.format(port, network, inhex))
