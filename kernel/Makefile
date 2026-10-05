CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -fcf-protection=none

.PHONY: all clean

all: ktrigger kaslr-sidt kaslr-prefetch

ktrigger: ktrigger.c helper_lkm/gds_helper_lkm.h
	$(CC) $(CFLAGS) -mavx2 -Ihelper_lkm -o $@ ktrigger.c

kaslr-sidt: kaslr-sidt.c
	$(CC) $(CFLAGS) -o $@ kaslr-sidt.c

kaslr-prefetch: kaslr-prefetch.c
	$(CC) $(CFLAGS) -o $@ kaslr-prefetch.c

clean:
	rm -f ktrigger kaslr-sidt kaslr-prefetch
