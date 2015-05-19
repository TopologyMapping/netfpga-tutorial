#
# $Id: Makefile 6042 2010-04-01 05:59:23Z grg $
#

CFLAGS = -g
CC = gcc
LDFLAGS = -lncurses

all : nffw

registers:
	$(NF_ROOT)/bin/nf_register_gen.pl --project firewall

clean :
	rm -f nffw

nffw : nffw.c
	gcc -Wall nffw.c -std=gnu99 -I/usr/include/ -o nffw /root/netfpga/lib/C/common/libnf2.so

install:

.PHONY: all clean install
