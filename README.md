# Downfall / GDS lab -- same-thread canary, cross-thread spy, kernel rep-movs leak

Educational reproduction of Gather Data Sampling (CVE-2022-40982, "Downfall",
Daniel Moghimi, USENIX Security 2023) on one Intel Core i3-6100 (Skylake).
One oracle geometry across three stages:

- **Stage 0, same-thread canary** -- `downfall.S`, `downfall-oneshot.c`
- **Stage 1, cross-thread spy** -- `spy/`: an attacker on the SMT sibling
  samples a UC-assist gather while a victim process pushes a canary
- **Stage 2, kernel rep-movs leak** -- `kernel/`: a kernel `rep movs` copy
  aimed at an attacker-chosen address; byte-exact recovery of a module
  secret page and of the kernel's own `linux_banner`

Oracle everywhere: slot stride `0x1040` (a 4096-byte stride aliases every
slot into one L1D set on this CPU), 64 classes per row, hot reload under
150 cycles, `class = (byte ^ 0x3f) & 0x3f`. Full numbers and reading:
`RESULTS.md`; host record: `results/host.txt`, `results/perf-host.txt`.
Use only on hardware you own and control.

## Host

Detox-01: Intel i3-6100 (Skylake, AVX2, no AVX-512), Kali, kernel
`7.1.5+kali-amd64`, microcode bypass via `dis_ucode_ldr` (GDS reports
`Vulnerable: No microcode`), cmdline includes `isolcpus=1 pti=off
iomem=relaxed`, CPU 3 online for the SMT arms, `performance` governor.
Attacker CPU 1 and victim CPU 3 are the SMT pair.

## Stage 0 -- same-thread canary

Question: does a retired AVX2 `vpgatherdd`, followed by one mispredicted
`vpgatherdd`, leave a Flush+Reload trace of a byte the same thread just
gathered? Each attempt is 30 calls; the last call (and every `j % 6 == 0`)
is an attack call whose base is a `PROT_NONE` page; the other 25 calls are
training calls. The gather destination is `ymm5`; the low qword is encoded
byte by byte into the oracle, six bits per byte.

Controls:

- **Value swap** -- gather a page of `0x42`, then a page of `0x24`: a
  passing run moves the hot class 61 -> 27 and the other class stays below
  majority. The trace follows the value, not one always-hot slot.
- **Final-encode suppression** (`SPEC_NOENCODE=1`) -- training still
  encodes, flushes and delays stay; only the last call's touch is
  redirected to a sink. Both classes then read 0/64 (`verdict: CONTROL
  cold`), while a page-swap run on the same binary still passes.

`SPEC=1` is the measurement; `verdict: VOID` means setup/self-test failed
(not a negative result); `FAIL spec-cold` means the swap missed its bar.
A passing process can still contain cold rounds -- they are part of the
result and visible in the logs. Recorded open question: the trace is
assigned to the last encode, not yet to `ymm5` vs the training bytes.

Build and run, from this directory:

```sh
make
env CPU=1 SPEC=1 ./downfall-oneshot
env CPU=1 SPEC=1 SPEC_NOENCODE=1 ./downfall-oneshot
env CPU=1 SELFTEST=1 ./downfall-oneshot
```

The published `flowyroll/downfall` tree is not drop-in here: its default is
AVX-512, its AVX2 branch still emits `vpxord`, and it initializes PTEditor.
This directory is the AVX2 measurement only.

## Stage 1 -- cross-thread spy (`spy/`)

An attacker process on CPU 1 samples a UC-assist gather (`ASSIST=uc`, a
`/dev/mem` UC page chosen with `devmem-probe`) while a victim process on
the SMT sibling CPU 3 pushes a canary through YMM registers (or
`rep movsb`), one process per run.

Result (2026-10-04; `LOADS=4 ROUNDS=8 TRIALS=64 REPEAT=2`, performance
governor, CPU 3 online): canary `0x42` PASS x2 and canary `0x24` PASS x2 --
`rows_exp=8/8` in every round, ~80% and ~75% of row-trials, control class
0%. The canary swap moves the hot class (61 <-> 27). Controls stay flat:
`ASSIST=none` with a live victim, idle victim, victim on the other core --
0 majority rounds; time-slice stays weak (1.6-2.7%, not claimed). Logs:
`results/spy-*` with the victim banners beside them.

Build and run:

```sh
cd spy && make
./devmem-probe            # pick a working UCPHYS (0xfee00000 APIC on this host)
bash run.sh smt           # smt | timeslice | idle | othercore
# env: REPEAT ROUNDS TRIALS LOADS PRINT ASSIST VERBOSE
```

`sampler.S` is an AVX2 port of the upstream `s_load_encode` shape
(`P_CACHE_MISS` prep); no AVX-512 opcodes. `PRINT=1` adds the per-row
argmax + top-3 dump used by the Stage 2 decoders.

## Stage 2 -- kernel rep-movs leak (`kernel/`)

A userspace trigger (`ktrigger`) loops an ioctl on the helper module
(`helper_lkm/`, variants SAFE / SAFEZ / BUG like the upstream POC) while
the Stage 1 sampler on the SMT sibling watches the kernel copy engine's
read stream.

**Engine discrimination** (two runs per arm, `ROUNDS=8`, canary 0x47):

| instrument | verdict | exp rate |
|---|---|---|
| user `rep movsb`; kernel `rep movsb` (`MODE=krep`, `KCOPY movsb`) | PASS x2 | 100.000% |
| kernel `rep movsq` (`KCOPY movsq`) | PASS x2 | 100.000% |
| kernel `rep stosb`, scalar byte loop, `memcpy()` | FAIL x2 | 0.000% |
| same-CPU control (`MODE=krep` on CPU 1) | FAIL x2 | 2.7-3.1% |

This build ships `memcpy_orig` and no `memcpy_erms` (CPU has ERMS, no
FSRM), so a 4 KiB `memcpy` never enters the string engine; the explicit
inline `rep movs` gadgets (`KREPMOV`, `KCOPY`) sample the real resource.

**Measured window geometry**: a 1-byte `rep movsb` loop at allocation
offset P exposes bytes `[P+16 .. P+23]` in the sampler's eight rows of
round 0 (row r = byte P+16+r; a second window sits near P+47). Byte i is
read at P = i-16; the read-ahead crosses page boundaries.

**M3 -- module secret page**: `KCOPY KOP=bytewalk` + `spy PRINT=1`
(byte low6 = `class ^ 0x3f`); a second walk with `SWIZZLE` (secret page
rotated right by 2) supplies bits 7..2. Run 185750 recovered all 58
characters byte-exact:

```text
GGDSEC-DOWNFALL-STAGE2-KERNEL-LEAK-CANARY-0123456789ABCDEF
```

(`results/kernel-m3/decode-185750.txt`)

**M3b -- linux_banner**: `TARGET=banner` rebases the trigger offset onto
the kallsyms address (sudo needed for kallsyms). A second walk with spy
`ESHIFT=2` (encoder-side qword shift, `shr %cl` in `sampler.S`) exposes
bits 7..2 without touching the target, so it works on the kernel image
too. Five runs merged (up to 40 votes per byte) recover the full
203-character banner line + newline, byte-exact against `/proc/version`;
single runs give 127/128 (residual bit-6 ties such as `,` vs `l`, resolved
by cross-run voting). Evidence: `results/kernel-m3b/decode-merged.txt`.

Build, load and run:

```sh
cd kernel && make && ./helper_lkm/build.sh
bash reload.sh byte        # 0x47-filled secret page (matrix arms)
bash matrix.sh             # discriminating matrix (ROUNDS=8 for a record run)
bash reload.sh text        # built-in text page (M3 walk)
SWZ=1 bash reconstruct.sh  # secret page -> recovered6 / recovered8
bash banner.sh             # linux_banner walk, 128 bytes (sudo for kallsyms)
COUNT=224 bash banner.sh   # wider banner window
```

## What is new vs the upstream POC

- **Engine discrimination on this build** -- the sampleable resource is the
  rep-mov copy engine (load side); the `memcpy` dispatch caveat is
  identified (`memcpy_erms` absent), and explicit `rep movs` gadgets
  replace the broken assumption.
- **Measured read-ahead window** `[P+16 .. P+23]`, used as a positional
  read primitive (byte i at offset i-16), with up to 8 votes per byte.
- **Two-pass full-byte decoding** -- `SWIZZLE` for the module page and
  `ESHIFT` (encoder-side shift) for any kernel memory, without modifying
  the target.
- **Evidence discipline** -- gated runners, artifact-aware decoding (the
  class-0 all-ones deposit saturates every row and blinds naive argmax
  decoding; decode from a top-3 dump with a hit threshold), a same-CPU
  negative control, archived logs.

## Attribution

Port and extension of the `flowyroll/downfall` POC by Daniel Moghimi
("Downfall: Exploiting Speculative Data Gathering", USENIX Security 2023;
CVE-2022-40982):

- https://downfall.page
- https://github.com/flowyroll/downfall

Files derived from the upstream POC:

- `kernel/helper_lkm/gds_helper_lkm.c` -- port of
  `POC/gds_memcpy_prefetch/helper_lkm` (SAFE / SAFEZ / BUG semantics)
- `spy/sampler.S` -- AVX2 port of the `s_load_encode` shape
  (`P_CACHE_MISS` configuration)
- `spy/spy.c` -- attacker harness built on the same shape
- `downfall.S`, `downfall-oneshot.c` -- follow the published single-thread
  sequence; see the file headers for the full credit lines

The upstream repository has no explicit license file; the derived parts
are published here for research and educational purposes only, with
credit to the original author.

## License and scope

All other code in this lab is published for research and educational use,
as-is, without warranty of any kind. Use only on hardware you own and
control.
