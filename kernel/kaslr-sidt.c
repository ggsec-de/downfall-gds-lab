/*
 * M4a -- unprivileged KASLR slide probe: SIDT leak (negative control).
 *
 * `sidt` is not privileged on CPUs without UMIP (this i3-6100 has no
 * UMIP). Historically the kernel programmed IDTR with the address of
 * `idt_table`, so the IDT base leaked the KASLR slide directly. On this
 * kernel the measurement shows IDTR pointing into the cpu_entry_area at
 * the fixed address 0xfffffe0000000000 -- the old leak is closed, and
 * this program is kept as the documented negative control. The derived-
 * address paths below remain for completeness (IDT_OFF/BANNER_OFF).
 *
 * Env: IDT_OFF=<hex>, BANNER_OFF=<hex> -- optional; derived addresses are
 * printed when the offsets are provided. Pure userspace: one instruction,
 * no root, no /proc access.
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct idtr {
	uint16_t limit;
	uint64_t base;
} __attribute__((packed));

static unsigned long long env_ull(const char *name, int *ok)
{
	const char *s = getenv(name);

	*ok = 0;
	if (s == NULL || s[0] == '\0')
		return 0;
	*ok = 1;
	return strtoull(s, NULL, 0);
}

int main(void)
{
	struct idtr idtr = { 0, 0 };
	int have_idt, have_banner;
	unsigned long long idt_off, banner_off, text, banner;

	asm volatile("sidt %0" : "=m"(idtr));

	printf("sidt base=0x%016llx limit=0x%04x\n",
	       (unsigned long long)idtr.base, (unsigned)idtr.limit);

	idt_off = env_ull("IDT_OFF", &have_idt);
	banner_off = env_ull("BANNER_OFF", &have_banner);
	if (have_idt) {
		text = (unsigned long long)idtr.base - idt_off;
		printf("derived text base=0x%016llx (idt_off=0x%llx)\n",
		       text, idt_off);
		if (have_banner) {
			banner = text + banner_off;
			printf("derived linux_banner=0x%016llx "
			       "(banner_off=0x%llx)\n", banner, banner_off);
		}
	}
	return 0;
}
