/*
 * Probe /dev/mem MMIO candidates for the UC assist page (run as root).
 *
 * Prints open/mmap status, the first byte and a load latency per
 * candidate so the runner can pick UCPHYS for spy(1). The default
 * candidate is the local APIC page (0xfee00000); reads of these pages
 * are side-effect free.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static const unsigned long cands[] = {
    0xfee00000UL,   /* local APIC */
    0xfed00000UL,   /* HPET */
    0xfec00000UL,   /* IOAPIC */
    0xfed10000UL,   /* LPC / chipset */
    0xfed20000UL,
};

static inline uint64_t reload_time(const void *p)
{
    unsigned lo, hi;
    uint64_t a, b;

    asm volatile("mfence\n\tlfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    a = ((uint64_t)hi << 32) | lo;
    asm volatile("mov (%0), %%eax" :: "r"(p) : "eax", "memory");
    asm volatile("lfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    b = ((uint64_t)hi << 32) | lo;
    return b - a;
}

int main(void)
{
    size_t i;
    int fd;

    printf("devmem-probe euid=%d (root needed)\n", (int)geteuid());
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "open /dev/mem: %s\n", strerror(errno));
        return 2;
    }
    for (i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
                       fd, (off_t)cands[i]);
        volatile uint8_t v;
        uint64_t t;

        if (p == MAP_FAILED) {
            printf("0x%lx: mmap failed: %s\n", cands[i], strerror(errno));
            continue;
        }
        v = *(volatile uint8_t *)p;
        t = reload_time(p);
        printf("0x%lx: OK first_byte=0x%02x reload=%llu\n",
               cands[i], (unsigned)v, (unsigned long long)t);
        munmap(p, 4096);
    }
    close(fd);
    return 0;
}
