CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -fcf-protection=none -fno-tree-vectorize -mno-avx -mno-avx2
LDFLAGS ?=

.PHONY: all clean

all: spy spy-victim devmem-probe

spy: spy.o sampler.o
	$(CC) -fcf-protection=none -o $@ spy.o sampler.o $(LDFLAGS)

spy.o: spy.c spy.h
	$(CC) $(CFLAGS) -c -o $@ spy.c

sampler.o: sampler.S
	$(CC) -c -o $@ sampler.S

spy-victim: spy-victim.c
	$(CC) -O2 -Wall -Wextra -Werror -fcf-protection=none -fno-tree-vectorize -mavx2 -o $@ spy-victim.c $(LDFLAGS)

devmem-probe: devmem-probe.c
	$(CC) -O2 -Wall -Wextra -Werror -o $@ devmem-probe.c $(LDFLAGS)

clean:
	rm -f spy spy-victim devmem-probe spy.o sampler.o
