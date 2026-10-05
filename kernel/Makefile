CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -fcf-protection=none

.PHONY: all clean

all: ktrigger

ktrigger: ktrigger.c helper_lkm/gds_helper_lkm.h
	$(CC) $(CFLAGS) -mavx2 -Ihelper_lkm -o $@ ktrigger.c

clean:
	rm -f ktrigger
