# SPDX-License-Identifier: ISC
#
# Linux-only: the shim interposes glibc's write/sync entry points, and the
# undo log it produces is replayed by replay.py. Not a build product -- it is
# an instrument, invoked by hand when a durability claim needs checking. The
# one automated use is dcroxide-testutil's review_powerloss_shim test, which
# compiles shim.c itself and checks a replay end to end.

CFLAGS ?= -O2 -Wall -Wextra -fPIC
libpowerloss.so: shim.c
	$(CC) -shared $(CFLAGS) -o $@ $< -ldl

.PHONY: clean
clean:
	rm -f libpowerloss.so
