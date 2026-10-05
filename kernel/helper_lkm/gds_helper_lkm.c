// SPDX-License-Identifier: GPL-2.0
/*
 * gds_helper_lkm -- an ioctl-triggered memcpy gadget for the GDS kernel
 * leak lab (labs/downfall/kernel).
 *
 * Port of the helper module from the flowyroll/downfall POC
 * (POC/gds_memcpy_prefetch/helper_lkm, Daniel Moghimi) to kernel 7.1.5,
 * with one deliberate layout change: the three pages are laid out as
 * [dest][source][secret], so a rep-mov prefetch past the end of `source`
 * lands in `secret`.
 *
 * Three check variants are selected at build time (see Makefile/build.sh):
 *   KERNEL_GADGET_SAFE  -- bounds check keeps the copy inside source
 *   KERNEL_GADGET_SAFEZ -- weakened check zeroes the length for out-of-range
 *   KERNEL_GADGET_BUG   -- missing offset+length check
 * The gadget is a lab simulation of a vulnerable kernel copy path. The
 * module is loaded by the lab operator; the device is world-writable on
 * purpose so the trigger and the attacker are ordinary processes.
 */

#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "gds_helper_lkm.h"

#define PAGE_BYTES 4096

#ifndef KERNEL_GADGET_SAFE
#define KERNEL_GADGET_SAFE 0
#endif
#ifndef KERNEL_GADGET_SAFEZ
#define KERNEL_GADGET_SAFEZ 0
#endif
#ifndef KERNEL_GADGET_BUG
#define KERNEL_GADGET_BUG 0
#endif

#if !KERNEL_GADGET_SAFE && !KERNEL_GADGET_SAFEZ && !KERNEL_GADGET_BUG
#error "select a gadget variant (see Makefile: GDS_GADGET=SAFE|SAFEZ|BUG)"
#endif

#if KERNEL_GADGET_SAFE
#define GDS_VARIANT_NAME "SAFE"
#elif KERNEL_GADGET_SAFEZ
#define GDS_VARIANT_NAME "SAFEZ"
#elif KERNEL_GADGET_BUG
#define GDS_VARIANT_NAME "BUG"
#endif

static char gds_buf[3 * PAGE_BYTES] __attribute__((aligned(PAGE_BYTES)));
#define gds_dest   (gds_buf)
#define gds_source (gds_buf + PAGE_BYTES)
#define gds_secret (gds_buf + 2 * PAGE_BYTES)

static const char builtin_text[] =
	"GGDSEC-DOWNFALL-STAGE2-KERNEL-LEAK-CANARY-0123456789ABCDEF";

static bool device_busy;
static unsigned int swz_applied;	/* secret-page rotation in effect */

static int secret_byte = -1;
module_param(secret_byte, int, 0644);
MODULE_PARM_DESC(secret_byte,
		 "fill the secret page with this byte (0-255); <0 uses secret_text");

static char *secret_text;
module_param(secret_text, charp, 0644);
MODULE_PARM_DESC(secret_text, "text for the secret page (default: built-in)");

static int device_open(struct inode *inode, struct file *file)
{
	if (device_busy)
		return -EBUSY;
	device_busy = true;
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	device_busy = false;
	return 0;
}

static long device_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	struct gds_helper_lkm_params params;

	switch (cmd) {
	case GDS_HELPER_LKM_IOCTL_INFO: {
		struct gds_helper_lkm_info info;

		info.dest = (unsigned long)gds_dest;
		info.source = (unsigned long)gds_source;
		info.secret = (unsigned long)gds_secret;
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case GDS_HELPER_LKM_IOCTL_OOB_GADGET:
		if (copy_from_user(&params, (void __user *)arg,
				   sizeof(params)))
			return -EFAULT;
#if KERNEL_GADGET_SAFE
		/* Safe: the copy stays inside the source page. */
		if (params.ulong2 < PAGE_BYTES &&
		    params.ulong2 + params.ulong1 < PAGE_BYTES)
			memcpy(gds_dest, gds_source + params.ulong1,
			       params.ulong2);
#elif KERNEL_GADGET_SAFEZ
		/*
		 * Weaker: out-of-range zeroes the length, but the source
		 * pointer (source + ulong1) still reaches memcpy.
		 */
		{
			unsigned long len = params.ulong2;

			if (len >= PAGE_BYTES ||
			    len + params.ulong1 >= PAGE_BYTES)
				len = 0;
			memcpy(gds_dest, gds_source + params.ulong1, len);
		}
#else
		/* Buggy: no offset+length check at all. */
		if (params.ulong2 < PAGE_BYTES)
			memcpy(gds_dest, gds_source + params.ulong1,
			       params.ulong2);
#endif
		return 0;
	case GDS_HELPER_LKM_IOCTL_KREPMOV:
		if (copy_from_user(&params, (void __user *)arg,
				   sizeof(params)))
			return -EFAULT;
		if (params.ulong2 > 65536)
			return -EINVAL;
		{
			char *d = gds_dest;
			const char *s = gds_source + params.ulong1;
			unsigned long n = params.ulong2;

			asm volatile("rep movsb"
				     : "+D"(d), "+S"(s), "+c"(n)
				     :
				     : "memory");
		}
		return 0;
	case GDS_HELPER_LKM_IOCTL_KCOPY: {
		struct gds_helper_lkm_copy cp;

		if (copy_from_user(&cp, (void __user *)arg, sizeof(cp)))
			return -EFAULT;
		if (cp.len > 65536)
			return -EINVAL;
		switch (cp.mode) {
		case 0: {
			char *d = gds_dest;
			const char *s = gds_source + cp.offset;
			unsigned long n = cp.len;

			asm volatile("rep movsb"
				     : "+D"(d), "+S"(s), "+c"(n)
				     :
				     : "memory");
			break;
		}
		case 1: {
			char *d = gds_dest;
			const char *s = gds_source + cp.offset;
			unsigned long n = cp.len / 8;

			asm volatile("rep movsq"
				     : "+D"(d), "+S"(s), "+c"(n)
				     :
				     : "memory");
			break;
		}
		case 2: {
			char *d = gds_dest;
			unsigned long n = cp.len;
			unsigned char al = (unsigned char)cp.byte;

			asm volatile("rep stosb"
				     : "+D"(d), "+c"(n)
				     : "a"(al)
				     : "memory");
			break;
		}
		case 3: {
			volatile unsigned char *d =
				(volatile unsigned char *)gds_dest;
			const volatile unsigned char *s =
				(const volatile unsigned char *)gds_source +
				cp.offset;
			unsigned long i;

			for (i = 0; i < cp.len; i++)
				d[i] = s[i];
			break;
		}
		case 4: {
			char *d = gds_dest;
			const char *s = gds_source + cp.offset;
			unsigned long k;

			/* Bytewalk (M3): keep the copy engine continuously
			 * busy on a single secret byte -- cp.len x 1-byte
			 * rep movsb from a fixed offset. */
			for (k = 0; k < cp.len; k++) {
				char *dd = d;
				const char *ss = s;
				unsigned long one = 1;

				asm volatile("rep movsb"
					     : "+D"(dd), "+S"(ss), "+c"(one)
					     :
					     : "memory");
			}
			break;
		}
		default:
			return -EINVAL;
		}
		return 0;
	}
	case GDS_HELPER_LKM_IOCTL_SWIZZLE: {
		unsigned int target, delta, i;

		if (copy_from_user(&params, (void __user *)arg,
				   sizeof(params)))
			return -EFAULT;
		target = (unsigned int)(params.ulong1 & 7);
		delta = (target - swz_applied) & 7;
		if (delta != 0) {
			for (i = 0; i < PAGE_BYTES; i++) {
				unsigned char b = gds_secret[i];

				gds_secret[i] = (unsigned char)((b >> delta) |
								(b << (8 - delta)));
			}
			swz_applied = target;
		}
		pr_info("swizzle: rotate-right=%u applied=%u\n", target,
			swz_applied);
		return 0;
	}
	default:
		return -EINVAL;
	}
}

static const struct file_operations gds_helper_lkm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,
};

static struct miscdevice gds_helper_lkm_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = GDS_HELPER_LKM_DEVICE_NAME,
	.fops = &gds_helper_lkm_fops,
	.mode = 0666,
};

static int __init gds_helper_lkm_init(void)
{
	memset(gds_dest, 0, PAGE_BYTES);
	memset(gds_source, '*', PAGE_BYTES);
	if (secret_byte >= 0 && secret_byte <= 255) {
		memset(gds_secret, secret_byte, PAGE_BYTES);
	} else {
		const char *text = secret_text ? secret_text : builtin_text;

		strscpy(gds_secret, text, PAGE_BYTES);
	}
	pr_info("gds_helper_lkm: variant=%s dest=%px source=%px secret=%px\n",
		GDS_VARIANT_NAME, gds_dest, gds_source, gds_secret);
	return misc_register(&gds_helper_lkm_miscdev);
}

static void __exit gds_helper_lkm_exit(void)
{
	misc_deregister(&gds_helper_lkm_miscdev);
	pr_info("gds_helper_lkm: unloaded\n");
}

module_init(gds_helper_lkm_init);
module_exit(gds_helper_lkm_exit);

MODULE_AUTHOR("Daniel Moghimi (original gds_memcpy_prefetch POC); GG Advanced IT Security lab port");
MODULE_DESCRIPTION("ioctl-triggered memcpy gadget for the GDS kernel-leak lab");
MODULE_LICENSE("GPL");
