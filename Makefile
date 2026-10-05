CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -fcf-protection=none -fno-tree-vectorize
LDFLAGS ?=

.PHONY: all clean

all: downfall-oneshot

downfall-oneshot: downfall-oneshot.o downfall.o
	$(CC) -fcf-protection=none -o $@ downfall-oneshot.o downfall.o $(LDFLAGS)

downfall-oneshot.o: downfall-oneshot.c
	$(CC) $(CFLAGS) -mno-avx -c -o $@ $<

downfall.o: downfall.S
	$(CC) -c -o $@ $<

clean:
	rm -f downfall-oneshot downfall-oneshot.o downfall.o
