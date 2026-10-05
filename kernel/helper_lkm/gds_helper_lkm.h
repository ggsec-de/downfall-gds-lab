/* SPDX-License-Identifier: GPL-2.0 */
/*
 * gds_helper_lkm -- ioctl interface for the GDS kernel-leak lab helper.
 *
 * See gds_helper_lkm.c for the module and README.md for the lab context.
 */
#ifndef GDS_HELPER_LKM_H
#define GDS_HELPER_LKM_H

#define GDS_HELPER_LKM_DEVICE_NAME "gds_helper_lkm"
#define GDS_HELPER_LKM_DEVICE_PATH "/dev/" GDS_HELPER_LKM_DEVICE_NAME

#define GDS_HELPER_LKM_IOCTL_MAGIC_NUMBER (long)'B'

struct gds_helper_lkm_params {
	unsigned long ulong1;
	unsigned long ulong2;
};

struct gds_helper_lkm_info {
	unsigned long dest;
	unsigned long source;
	unsigned long secret;
};

#define GDS_HELPER_LKM_IOCTL_OOB_GADGET \
	_IOR(GDS_HELPER_LKM_IOCTL_MAGIC_NUMBER, 1, struct gds_helper_lkm_params)
#define GDS_HELPER_LKM_IOCTL_INFO \
	_IOR(GDS_HELPER_LKM_IOCTL_MAGIC_NUMBER, 2, struct gds_helper_lkm_info)

/* Copy source+ulong1 -> dest with an inline rep movsb, ulong2 = length
 * (<= 65536). Kernel-mode copy-engine probe, independent of the runtime
 * memcpy dispatch used by OOB_GADGET. */
#define GDS_HELPER_LKM_IOCTL_KREPMOV \
	_IOR(GDS_HELPER_LKM_IOCTL_MAGIC_NUMBER, 3, struct gds_helper_lkm_params)

struct gds_helper_lkm_copy {
	unsigned long offset;
	unsigned long len;
	unsigned long mode;   /* 0 movsb, 1 movsq, 2 stosb, 3 scalar,
			       * 4 bytewalk (len x 1-byte rep movsb at a
			       * fixed offset; M3 per-byte walk) */
	unsigned long byte;   /* fill byte for stosb */
};

#define GDS_HELPER_LKM_IOCTL_KCOPY \
	_IOR(GDS_HELPER_LKM_IOCTL_MAGIC_NUMBER, 4, struct gds_helper_lkm_copy)

/* Rotate the secret page right by ulong1 bits (0-7). The module tracks the
 * applied rotation, so the target is idempotent: SWIZZLE(2) then SWIZZLE(0)
 * rotates by 2 and back. M3 uses the ror=2 view to pull each byte's high
 * bits into the sampled low-6 class window. */
#define GDS_HELPER_LKM_IOCTL_SWIZZLE \
	_IOR(GDS_HELPER_LKM_IOCTL_MAGIC_NUMBER, 5, struct gds_helper_lkm_params)

#endif /* GDS_HELPER_LKM_H */
