# Results, 2026-10-04

Three alternating pairs of `SPEC=1` and `SPEC=1 SPEC_NOENCODE=1` on one
binary. `TRIALS=64`, `ROUNDS=8`, pinned to CPU 1. Full logs are in
`results/`. Weaker rounds are kept.

The binary was not rebuilt between the six processes.

| File | sha256 |
|---|---|
| `downfall-oneshot` | `c7798004bc5e09ec5ad985c3e23e929b64953329d631fe1558b31a2831270da4` |
| `downfall-oneshot.c` | `b6594957444e7f40477619c10ee13d69d2fd7513bd13c824a96cd070b1964df5` |
| `downfall.S` | `413299a40661fa8e0be1c4c8eee8d65056228d97c968de142795be21c1339fd9` |
| `Makefile` | `a12d0d430170498571b9404c1f271d65a6f014c9585ae49cd4fd7cdacc97dd00` |

`sha256_after` of the binary matches `sha256_before`.

## Host

Recorded in `results/host.txt` at 2026-10-04T21:56:46+02:00. The six logs
are stamped from 21:56:46 to 21:56:47.

| Item | Value |
|---|---|
| Machine | Detox-01, Linux 7.1.5+kali-amd64 |
| CPU | Intel Core i3-6100 @ 3.70 GHz |
| Microcode | 0xba (`dis_ucode_ldr` on the command line) |
| Compiler | gcc (Debian 15.3.0-2) 15.3.0 |
| `gather_data_sampling` | Vulnerable: No microcode |
| Online CPUs | `nproc` 3, CPU 3 online |
| CPU 1 governor | `powersave` |
| CPU 1 frequency | 1599454 kHz at the first process, then 3700000 kHz |

CPU 3 shares the core with CPU 1. The standing lab note is CPU 3 offline
and the performance governor. This series did not restore that setup:
`sudo -n` asks for a password. The command line still has `isolcpus=1`,
`pti=off`, and `clearcpuid=308,295,514`.

## Series

| Run | freq kHz | selftest hot/cold | page 0x42 | page 0x24 | verdict | exit |
|---|---|---|---|---|---|---|
| pair1-spec | 1599454 | 44 / 308 | 8/8 class 61 | 1/8 class 27, other class majority 7/8 | FAIL spec-cold | 1 |
| pair1-noencode | 3700003 | 32 / 360 | 0/8 | 0/8 | CONTROL cold | 0 |
| pair2-spec | 3700000 | 34 / 230 | 8/8 class 61 | 8/8 class 27 | PASS | 0 |
| pair2-noencode | 3699998 | 32 / 242 | 0/8 | 0/8 | CONTROL cold | 0 |
| pair3-spec | 3700005 | 34 / 234 | 8/8 class 61 | 8/8 class 27 | PASS | 0 |
| pair3-noencode | 3700001 | 34 / 242 | 0/8 | 0/8 | CONTROL cold | 0 |

Suppression counts are 0/64 on both classes in every round of all three
`SPEC_NOENCODE=1` processes. That is stronger than the verdict label,
which only requires no majority round.

### pair1-spec, the failed page swap

Started at 1.6 GHz. Page `0x42` stays on class 61. Page `0x24` follows
class 27 only in round 0 (49/64). Later rounds light class 61, the class
of `0x42`, at 54/64 to 64/64. These are hits on the other class, not
cold misses.

| Round | page 0x42 class 61 | page 0x42 class 27 | page 0x24 class 27 | page 0x24 class 61 |
|---|---|---|---|---|
| 0 | 64/64 | 0/64 | 49/64 | 14/64 |
| 1 | 64/64 | 0/64 | 0/64 | 64/64 |
| 2 | 62/64 | 1/64 | 0/64 | 64/64 |
| 3 | 64/64 | 0/64 | 10/64 | 54/64 |
| 4 | 64/64 | 0/64 | 0/64 | 64/64 |
| 5 | 64/64 | 0/64 | 9/64 | 55/64 |
| 6 | 64/64 | 0/64 | 0/64 | 64/64 |
| 7 | 64/64 | 0/64 | 0/64 | 64/64 |

### pair2-spec and pair3-spec

Both at 3.7 GHz. Every round is a majority on the page's own class, and
the other class is never a majority. The only counts below 64/64 on the
expected class are pair2 round 7 page `0x42` at 63/64 (class 27 = 1/64)
and pair3 round 7 page `0x24` at 63/64 (class 61 = 1/64).

## Reading

At 3.7 GHz on this binary the page byte selects the hot class, and
pointing the last encode at a sink removes both classes. The 1.6 GHz
process is part of the same series: there the second page kept lighting
class 61. The suppression runs stay at zero on either side of that
process, so the stuck class is not a background hit that the control
missed.

This series does not say whether the byte comes from the previous
`ymm5` or from the training page. Those two carry the same byte here.

## Full-power series, same binary

Recorded at 2026-10-04T22:23:42+02:00 after the governor was set to
`performance`, `min_perf_pct` to 100, and CPU 3 offline. EPP on CPU 1
was `performance`. `scaling_min_freq` stayed 800000. The binary hash is
unchanged. Logs are `results/perf-pair*.log` and `results/perf-host.txt`.

An idle read of `scaling_cur_freq` is 800000. That file is an average
that includes time in C1. A one-second spin on CPU 1 reads 3700000, and
the overlapping sample during `perf-pair1-spec` was 3701951 kHz. Samples
taken after a process has already exited fall back to 800000. The hot
reload in every selftest here is 34 cycles.

| Run | page 0x42 | page 0x24 | verdict | exit |
|---|---|---|---|---|
| perf-pair1-spec | 8/8 class 61 | 8/8 class 27 | PASS | 0 |
| perf-pair1-noencode | 0/8 | 0/8 | CONTROL cold | 0 |
| perf-pair2-spec | 8/8 class 61 | 8/8 class 27 | PASS | 0 |
| perf-pair2-noencode | 0/8 | 0/8 | CONTROL cold | 0 |
| perf-pair3-spec | 8/8 class 61 | 8/8 class 27 | PASS | 0 |
| perf-pair3-noencode | 0/8 | 0/8 | CONTROL cold | 0 |

Every suppression round is 0/64 on both classes. On the passing runs,
page `0x42` is 63/64 or 64/64 on class 61. Page `0x24` is 52/64 to 63/64
on class 27. Class 61 on that page is 1/64 to 12/64 and is never a
majority. The lowest page `0x24` round is perf-pair3 round 7: class 27
= 52/64, class 61 = 12/64.

## Cross-thread spy, Stage 1 -- first PASS series (2026-10-04)

`spy/` (UC-assist gather sampler, AVX2 port of the upstream `s_load_encode`
shape; attacker on CPU1, victim a separate process). Series: `LOADS=4`,
`ROUNDS=8`, `TRIALS=64`, `REPEAT=2`, `performance` governor, CPU3 online
(`sib cpu1: 1,3`). Logs: `results/spy-*20261004-231[4-7]*.txt` and the
victim banners beside them; spy binary sha256
`15ccec9d4aaa5ad3e52218f08399f26ad3f049bf2293f5c011cc632b93ea319b`.

| Run | canary | `rows_exp` | `exp_majority` | verdict |
|---|---|---|---|---|
| smt 0x42 r1/r2 | 0x42 (class 61) | 8/8 in 8/8 rounds | 8/8 both | PASS |
| smt 0x24 r1/r2 | 0x24 (class 27) | 8/8 in 8/8 rounds | 8/8 both | PASS |
| ASSIST=none r1/r2 | 0x42, victim live | 0/8 | 0/8 both | FAIL (control) |
| idle r1/r2 | none | 0/8 | 0/8 both | FAIL (control) |
| othercore r1/r2 | 0x42 on CPU0 | 0/8 | 0/8 both | FAIL (control) |
| timeslice r1/r2 | 0x42 / 0x24 | 0/8 | 0/8 both | FAIL (weak, no claim) |

Per-row rates over the run: smt 0x42 exp 79.9-81.1%, ctl 0.0%; smt 0x24 exp
73.4-76.2%, ctl 0.0%; ASSIST=none exp 0 and 3.2% (one process each), ctl 0;
idle exp 0.0%; timeslice exp 1.6-2.7%. The canary swap moves the hot class
(61<->27) and `rows_ctl` never reaches majority.

Reading: on this binary and bench (attacker CPU1, victim CPU3, the SMT pair),
the victim's canary bytes reach the attacker's UC-assist sample at a majority
rate in every round; the normal WB page (`ASSIST=none`) with a live victim
does not reach a majority, which places the signal in the assist path. The
time-slice shape stays at a few percent and is not claimed.

Diagnostic observations (recorded, not fully attributed): every UC-assist scan
also deposits a deterministic class-0 slot (low six bits 0x3f), consistent
with sampling a recent all-ones register (the gather mask); and UC-assist
scans deposit multiple classes per row per trial while `ASSIST=none` deposits
exactly one. Dumps: `results/diag-20261004/l1` (LOADS=1) and `l4` (LOADS=4).

## Stage 2, kernel rep movs leak -- discriminating matrix + record series (2026-10-05)

`kernel/`: helper LKM (`gds_helper_lkm-BUG.ko`) + `ktrigger`; attacker = the
Stage 1 `spy` on CPU1, trigger on CPU3 (the SMT pair), `LOADS=4`, byte page
filled with 0x47 ('G', class 56). The trigger is an ordinary process; the
copy runs in kernel context. Record series: two runs per arm, `ROUNDS=8`
`TRIALS=64`; logs `results/kernel-smoke/kt-*` (both runs identical per arm).

| arm (copy instrument) | verdict | exp row 0 / row 4 |
|---|---|---|
| user `rep movsb` (`USER=0x47 REPMOV=1`) | PASS x2 | 100.000% |
| kernel `rep movsb` (`MODE=krep`, LEN 4095) | PASS x2 | 100.000% |
| kernel `rep movsb` (`KCOPY KOP=movsb`, LEN 4095) | PASS x2 | 100.000% |
| kernel `rep movsq` (`KCOPY KOP=movsq`, LEN 4096) | PASS x2 | 100.000% |
| kernel `rep stosb` fill (`KCOPY KOP=stosb`) | FAIL x2 | 0.000% |
| kernel scalar byte loop (`KCOPY KOP=scalar`) | FAIL x2 | 0.000% |
| kernel `memcpy()` (`MODE=arb TARGET=secret`) | FAIL x2 | 0.000% |
| same-CPU control (`MODE=krep` on CPU1) | FAIL x2 | 2.7-3.1% |

Reading: the sampled resource is the rep-mov **copy engine** (load side).
Value-tracking swaps (0x47<->0x2A) move the hot class with the payload;
stores (`stosb`), scalar copies and the runtime `memcpy()` are invisible.
Why the `memcpy` floor on this box: kernel 7.1.5 ships `memcpy_orig` and no
`memcpy_erms` (CPU flags: `erms` set, `fsrm` absent), so a 4 KiB `memcpy`
never enters the string engine -- the explicit inline `rep movs` gadget is
the working instrument (matching upstream's ERMS premise).

M3 -- secret text reconstructed (2026-10-05, run 185750): the bytewalk leak
is a read-ahead window -- a 1-byte copy at allocation offset P puts secret
bytes [P+16 .. P+23] into the spy's round-0 rows (row r = byte P+16+r, at
61-64/64 hits per row; a second window sits near P+47). Reading byte i uses
P = 0x1000 + i - 16 (i < 16 lands in the source page; the engine read-ahead
crosses the page boundary), and every run also exposes i+1..i+7, so each
byte decodes from up to 8 independent votes (spy top3 dump; strongest
non-zero class >= 8 hits; class 0 is the known all-ones artifact). The
6-bit pass gives `low6 = class ^ 0x3f`; the SWIZZLE rotate-right-2 pass
moves bits 7..2 into the window (b6 = z>>4&1, b7 = z>>5&1) and completes
the byte. Probes: i=16 -> 'S' (class 44, gate), i=0 -> 'G' (56), i=6 ->
'-' (18). Result, 58/58 bytes exact:
`GGDSEC-DOWNFALL-STAGE2-KERNEL-LEAK-CANARY-0123456789ABCDEF`
(votes logged per byte: min 1, max 8, avg 7.5; byte 0 has a single vote by
construction). Evidence: `results/kernel-m3/rec-*185750*` and
`results/kernel-m3/decode-185750.txt`. Runner:
`bash reload.sh text && SWZ=1 bash reconstruct.sh`.

## Stage 2, M3b -- linux_banner recovered from the kernel image (2026-10-05)

`banner.sh` walks `linux_banner` (kallsyms under sudo; ktrigger
`TARGET=banner` rebases the offset) with the same window geometry: banner
byte i reads at OFFSET = i - 16 with up to 8 votes per byte, and a second
walk with spy `ESHIFT=2` (encoder-side qword shift, `shr %cl` in
sampler.S) supplies bits 7..2 -- no page rotation, so the trick works on
foreign kernel memory. Gates: byte 0 'L' (64/64), byte 1 'i' (62/64),
byte 6 'v' (63/64). Result: the full 203-character banner line + newline
recovered byte-exact against /proc/version. Single runs reproduce the line
with 0-6 residual byte errors (127/128 at best), all bit-6 ties on
punctuation (',' 0x2c vs 'l' 0x6c share class 19) or ~+6-byte window
jitter; merging five runs (up to 40 votes per byte) resolves them (byte 97
',' wins 21:19 in the ESHIFT pass). Reading continues past the newline
into adjacent kernel .rodata. Evidence: `results/kernel-m3b/recb-*` and
`results/kernel-m3b/decode-merged.txt`.

## Stage 2c, M4 -- unprivileged KASLR + no-root banner (2026-10-05)

`kaslr-sidt` (negative control): `sidt` base = `0xfffffe0000000000`
(cpu_entry_area, fixed) -- the classic SIDT KASLR leak is closed on this
kernel. `kaslr-prefetch` (v2: TLB eviction per pass, one sample per
candidate): the mapped image is a contiguous fast run at 2 MiB
granularity (~33-35 cycles vs ~48-50 outside, 22-26 candidates depending
on the run threshold), and across six runs the detected start was exactly
`_text`. Root calibration (once): `_text 0xffffffff8ac00000`,
`entry_SYSCALL_64 0xffffffff8ac00080`, `linux_banner 0xffffffff8bfd18c0`
(offset from `_text`: 0x13d18c0). End-to-end `banner-noroot.sh`, run
222601: base == `_text` exactly; derived banner == the kallsyms value;
probes L/i/v 63/62/58 of 64; recovered 125/128 bytes exact in a single
run (residual bit-6/copy jitter, as in M3b single runs). Evidence:
`results/kernel-m4/recb-*222601*` and `decode-noroot-222601.txt`; the
pre-fix run 222234 (wrong offset constant, 16 MiB low) failed the
roll-call gate -- a negative control for the derived address.
