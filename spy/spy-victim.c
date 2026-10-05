/*
 * Cross-thread GDS spy -- victim side (Downfall lab, Stage 1).
 *
 * Pins itself (CPU=3 default, the SMT sibling of the attacker's CPU 1),
 * fills a page with CANARY and pushes it through YMM registers in a loop
 * (MODE=vmov), or copies the page with rep movsb (MODE=repmov). Prints its
 * own banner so the log is self-describing (pid, requested cpu, actual
 * cpu, canary, mode).
 *
 * This is a lab victim: it holds no secret; the canary makes the channel
 * measurable. Run it as a separate process from the attacker.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void die(const char *msg)
{
    fprintf(stderr, "spy-victim: %s: %s\n", msg, strerror(errno));
    exit(2);
}

static int env_int(const char *name, int def)
{
    const char *s = getenv(name);
    char *end;
    long v;

    if (s == NULL || s[0] == '\0')
        return def;
    v = strtol(s, &end, 0);
    if (end == s)
        return def;
    return (int)v;
}

static void pin_cpu(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        die("sched_setaffinity");
}

static void __attribute__((noinline)) push_vmov(const uint8_t *src,
                                                uint8_t *dst)
{
    asm volatile(
        "vmovups    (%0), %%ymm0\n\t"
        "vmovups  32(%0), %%ymm1\n\t"
        "vmovups  64(%0), %%ymm2\n\t"
        "vmovups  96(%0), %%ymm3\n\t"
        "vpaddb  %%ymm1, %%ymm0, %%ymm4\n\t"
        "vpaddb  %%ymm3, %%ymm2, %%ymm5\n\t"
        "vpaddb  %%ymm5, %%ymm4, %%ymm4\n\t"
        "vmovups %%ymm4, (%1)\n\t"
        :: "r"(src), "r"(dst)
        : "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "memory");
}

static void __attribute__((noinline)) push_repmov(const uint8_t *src,
                                                  uint8_t *dst)
{
    asm volatile("rep movsb"
                 :: "D"(dst), "S"(src), "c"(4096UL)
                 : "memory");
}

int main(void)
{
    int cpu_id = env_int("CPU", 3);
    int canary = env_int("CANARY", 0x42);
    const char *mode = getenv("MODE");
    uint8_t *buf, *dst;

    if (mode == NULL || mode[0] == '\0')
        mode = "vmov";
    if (canary < 0 || canary > 255 || cpu_id < 0) {
        fprintf(stderr, "spy-victim: bad CANARY or CPU\n");
        return 2;
    }

    pin_cpu(cpu_id);

    buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    dst = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED || dst == MAP_FAILED)
        die("mmap");
    memset(buf, canary, 4096);
    memset(dst, 0, 4096);

    printf("spy-victim pid=%d cpu=%d running_on=%d canary=0x%02x mode=%s\n",
           (int)getpid(), cpu_id, sched_getcpu(), canary, mode);
    fflush(stdout);

    for (;;) {
        if (strcmp(mode, "repmov") == 0)
            push_repmov(buf, dst);
        else
            push_vmov(buf, dst);
    }

    return 0;
}
