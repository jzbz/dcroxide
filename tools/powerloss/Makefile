# SPDX-License-Identifier: ISC
#
# Linux-only: the shim interposes glibc's write/sync entry points, and the
# undo log it produces is replayed by replay.py. Not built by CI or by any
# cargo target -- it is an instrument, invoked by hand when a durability
# claim needs checking.

CFLAGS ?= -O2 -Wall -Wextra -fPIC
libpowerloss.so: shim.c
	$(CC) -shared $(CFLAGS) -o $@ $< -ldl

.PHONY: clean
clean:
	rm -f libpowerloss.so
