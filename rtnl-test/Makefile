# SPDX-License-Identifier: GPL-2.0
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
CPPFLAGS += -I../include

canbind: canbind.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<

clean:
	rm -f canbind .load.* .raw.err .isotp.err .bcm.err

.PHONY: clean
