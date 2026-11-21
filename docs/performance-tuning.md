# Performance tuning: parameter classes, sweep results, and the autotuner

This documents why `tuning.h`'s constants are the way they are, what has been
measured on which hardware, and how performance-sensitive users tune their own
machines. A LOCAL change that wins on the machine it was swept on can regress
on another tier of CPU (see the LPN gathers below), so the defaults stay
conservative and per-machine values come from measurement.

## Three classes of parameter

Not everything that looks like a knob may be tuned, and the boundary is a
correctness/security line, not a performance one. Every constant in
`tuning.h` belongs to exactly one class:

| Class | Meaning | Examples | Tunable? |
|---|---|---|---|
| **LOCAL** | Changes scheduling/layout only; the computed function and every byte on the wire are identical, so parties may differ freely | `lpn_batch_m`, `cggm_tile_*`, choice of transpose/packing kernel | Yes — per machine |
| **AGREEMENT** | Shapes the transcript (chunk boundaries, message sizes); every party must use the same value | `softspoken_chunk_blocks` (d_buf chunking), `softspoken_ferret_bootstrap_chunk_blocks` | Only by out-of-band agreement; per-machine tuning desyncs heterogeneous parties |
| **SECURITY** | Part of a proof | LPN parameter sets (`ferret_b*`: t, logk, depth), `lpn_d`, MITCCRH `ReuseShift` | Never |

The autotuner cannot reach the AGREEMENT and SECURITY classes (see *The
socket* below). A tuner that "optimizes" one party's chunk size breaks
interop; one that touches LPN parameters breaks the security claim.

## Why LOCAL defaults are conservative: the LPN gathers

A LOCAL knob's best value depends on the cache hierarchy in ways that no
queryable machine property predicts. The LPN fold is the measured case. It
does `d = 10` random 16-byte gathers per output into the `pre` table
(ferret_b12: 2^19 blocks = 8 MiB). Raising `lpn_batch_m` from 32 to 64 (more
independent accumulator chains in flight) together with a software prefetch
of upcoming outputs' gather targets on tables over 2 MiB (all M·d indices sit
in the PRG scratch before the fold, so the targets are known ahead of use)
measured, in bench_lpn ns/output at n = 2^22:

| table (logk) | Zen 5 | Apple M4 | Intel Granite Rapids (c8i) |
|---|---|---|---|
| 2^10 (16 KiB) | +5% | flat/regress | **−3.3%** |
| 2^17 (2 MiB) | wash | — | −4.3% (the one Intel win) |
| 2^19 (8 MiB, production) | **+9.8%** | **regression** | **−4.1%** |
| 2^20 (16 MiB) | — | **−21% .. −34%** | — |

On Zen 5 (1 MiB private L2, 32 MiB L3 per CCX) production tables spill past
the small L2. On Apple M4 the large shared L2 keeps even "large" tables
cache-resident, and the wider batch thrashes. On Granite Rapids the 480 MiB
shared L3 keeps the 8 MiB table far from memory, so a prefetch has no latency
to hide and is pure instruction overhead. Two rules follow:

1. **A value swept on one machine does not transfer.** Granite Rapids
   regressed at exactly the production size, so a default must be the value
   that is safe on hardware nobody swept.
2. **No formula over cache sizes picks the value.** The 8 MiB table is
   L3-resident on both Zen 5 and Granite Rapids, yet the change helps one and
   hurts the other. Only measurement on the machine itself decides, which is
   what `make tune` does.

Swept separately with interleaved runs on 12 microarchitectures (Granite
Rapids, Sapphire Rapids, Ice Lake, Skylake, Zen 3/4/5, Graviton 2/3/4, Apple
M4; two box sizes for Zen 5), the two halves differ. M = 64 wins 1–4% on five
of them and is a registry knob. The prefetch never clears the variance gate on
any of them, Zen 5 included: its share of the Zen 5 gain in the table is drift
between runs that were not interleaved. There is no prefetch knob.

## Methodology requirements for any sweep

A sweep, by the tuner or by hand, must defend against these measurement
traps:

- **Interleave A/B runs** (A,B,A,B,...) — never A,A,A then B,B,B. Machine
  state drifts (thermal, frequency, page cache).
- **Thermal throttling**: fanless machines (Apple laptops) throttle under
  sustained benching; a sweep taken minutes apart is not comparable. One
  mid-session phantom "34% regression" on an M4 was exactly this.
- **Variance gates**: at cloud-VM noise levels (±5–8% on loopback e2e runs),
  a ±3% effect is unresolvable by two runs. If the spread exceeds the effect
  size, the honest verdict is "no change", not the mean delta.
- **Sweep the actual production shape** (table sizes, chunk sizes), not just
  microbench defaults — bench_lpn's default args stop at L1-resident sizes.

## `make tune`

Defaults always remain the safe swept-conservative values; tuning is
per build directory, once.

**The override header is build-directory state.** CMake creates
`<build>/tuning-include/emp-ot/tuning_local.h` at configure time — a
canonical marked stub, meaning shipped defaults — and prepends its
directory to the `emp-ot` target's include path, so it shadows any copy left
in the source tree (CMake warns while one exists, and `tune-clean` deletes
it). The tuner overwrites the stub via an atomic write-then-rename;
`install` ships the file the library objects were compiled with, so
installed consumers compile against the same configuration as the
binary. Concurrent build directories, differently-configured checkouts,
and `-DEMP_OT_AUTO_TUNE=OFF` builds therefore cannot see each other's
overrides. `test_tuning_local` pins the stub/override/shadowing
semantics.

The stub is marked with a canonical signature. The automatic hook sweeps
only a missing, empty, or exactly canonical stub; every other nonempty
header is treated as an intentional override and preserved. This includes
hand-written build-directory overrides and hand-written headers migrated
from the source tree.

**Release builds tune automatically.** A top-level, non-cross-compiled
`CMAKE_BUILD_TYPE=Release` build sweeps the LOCAL knobs before compiling
the library — the tuner links no emp-ot objects, so it builds first and
measures on an otherwise idle machine, and the library then compiles
with the overrides in the same invocation. The sweep runs only while the
build directory's `tuning_local.h` is the untuned stub, so every build
after the first is deterministic and sweep-free (the no-op path also
warns if the kept result records a different host CPU than the current
one). Debug/unspecified build types and subproject consumers never
auto-tune; `-DEMP_OT_AUTO_TUNE=OFF` disables the automatic sweep — a
result written by the explicit `tune` target still applies until
`tune-clean`.

```
cmake --build build --target tune        # explicit re-sweep (any build type)
cmake --build build --target tune-clean  # restore the untuned stub
                                         # (an auto-tune Release build dir
                                         #  re-sweeps on its next build;
                                         #  configure with
                                         #  -DEMP_OT_AUTO_TUNE=OFF to keep
                                         #  shipped defaults)
```

Because the header exists from configure time onward, it is in every
consuming TU's dependency file from the first compile: rewriting it (by
`tune` or `tune-clean`) is all it takes for the next build to recompile
exactly the affected TUs. Hand-editing the build-dir file works the same
way.

How it works:

- **The socket.** tuning.h includes a generated `emp-ot/tuning_local.h`
  when present (`__has_include`); every tuner-managed LOCAL knob is an
  `#ifndef`-guarded macro default forwarded into its constexpr, while the
  fixed LOCAL policies (`cot_chosen_input_tile`, `mp_gadget_flush_trees`,
  `ot_extension_stream_flush_bytes`) are plain constexpr. AGREEMENT and SECURITY knobs have no macro guard —
  the generated file has no channel to reach them, so the class boundary
  is enforced by construction.
- **The tuner** (`tools/tune.cpp`, target `emp-ot-tune`). Every knob is a
  template parameter, so all candidate values are instantiated side by
  side in one binary and selected at runtime — one build, one run, no
  reconfigure loop. Each knob is measured at its PRODUCTION shape (chunk-
  sized butterfly, depth-12 trees, the 8 MiB `ferret_b12` LPN table), with the
  methodology above: candidates interleaved across 5 rounds, min-of-3
  windows per measurement, medians across rounds, and a variance gate —
  a candidate that does not beat the shipped default by more than the
  default's own cross-round spread (and at least 1%) is not emitted.
- **Cache-coupled knobs are scored jointly, in context.** `cggm_tile` and
  `lpn_batch_m` interact through the cache (every Ferret tree expansion
  runs interleaved with LPN folds against the 8 MiB table), and isolated
  kernel sweeps produce rankings that do not survive the full pipeline:
  on Zen 4 the isolated cggm sweep reported tile 64 as +12.8%, while
  exhaustive end-to-end measurement shows the shipped default tile is
  the true optimum there. The tuner therefore measures the (tile, M)
  cross-product on a Ferret-shaped composite — build one depth-12 tree
  into the out slice, then LPN-fold that slice against the table, per
  candidate pair — and emits the pair that wins the composite. The
  composite is shaped like the default `ferret_b12` regime (depth-12
  trees, 8 MiB table); exhaustive grids at the 2 and 4 MiB tables (depths
  11 and 12) showed no penalty resolvable above run noise. The compute-local knobs
  (`sfvole_tile`, the pinned `cot_chosen_input_tile`) stay kernel-scored.
- **The output.** The build directory's `tuning_local.h` carries provenance
  (host CPU, date, the full verdict table) so a stale file is auditable.
  An empty override list is a *correct* outcome, not a failure: it means
  the shipped defaults are right for this machine.
- **The guard.** `test_tuning_invariance` runs every registry knob at its
  extreme candidates and asserts bit-identical outputs, so a knob that
  actually shapes the transcript can never sit in the registry unnoticed.

Registry (all LOCAL): `sfvole_tile_k{2,4,8}` (butterfly j-tile; k=2 and
k=4 are swept-but-informational-only — see the policy note below —
and only k=8 is emission-eligible), `cggm_tile`, `lpn_batch_m` (candidates
{16,32,64} only: they divide every production fold length and keep M·d
word-aligned, which the invariance test enforces), and
`cot_chosen_input_tile` (swept-but-informational-only: a `MITCCRH`
call runs under one key, so the tile stops at 2^ReuseShift = 8, and it
has not beaten its noise band on any measured host; the value is pinned
as a plain constexpr in `tuning.h`).

### Validation against exhaustive search

The tuner's picks were checked against exhaustive per-platform e2e
sweeps (every live knob combination rebuilt and loopback-benched: 3
uniform-tile builds span the whole butterfly space since per-k tiles
never co-execute, plus the full 15-cell cggm×lpn grid) on six
microarchitectures (Zen 4/5, Granite Rapids, Graviton 2/3/4). Result:
for SoftSpoken k=4/k=8 and Ferret — the configurations that matter in
deployments — the tuner's pick equals the exhaustive e2e argmax or
sits within run noise on every platform.

**Known limitation, handled by policy:** the SoftSpoken butterfly tile
at small k has a two-party scheduling component no single-process score
can see (tile changes each party's chunk duration, which flips a
sleep/wake rendezvous at the per-chunk recv). Kernel rankings missed the
e2e optimum in BOTH directions: on Granite Rapids the e2e optimum at k=2
is T16 (+12%) while the kernel is tile-flat; on Zen 5 the kernel prefers
T32 (+16% in isolation) while the e2e optimum is T16. The policy: **the
k=2 and k=4 tiles are swept and reported but never auto-emitted** — only
the k=8 tile (kernel-dominated at 32 AES/OT; verified to transfer
faithfully) is eligible for emission. The forfeited wins are small and
confined to fast-link niches (`SoftSpoken<2>` moves ~8 B/OT and is
bandwidth-bound on real networks; the measured cost of not emitting is
~5% on its malicious path at ≥9 Gbps links, zero elsewhere). Users in
exactly that niche can A/B by hand with `bench_softspoken` and set
`EMP_TUNE_SFVOLE_TILE_K{2,4}` in `tuning_local.h` directly (Granite
Rapids + fast link: T16 at k=2 measured +12%).

## Sweep provenance of current defaults

- `cggm_tile_arch_default()` (32 on VAES-512 and VAES-256, 4 otherwise;
  registry knob `EMP_TUNE_CGGM_TILE`): on Granite Rapids and Zen 5, 32
  beats 16 at production depths, and larger tiles help Zen 5 but regress
  Granite Rapids. AArch64 is flat across 4–64.
- `softspoken_chunk_blocks` (64 for k ≤ 4, 128 for k = 8): AGREEMENT class;
  swept on x86, both parties must match.
- `lpn_batch_m = 32`: the safe cross-platform setting (see the LPN gathers
  above), and a registry knob (`EMP_TUNE_LPN_BATCH_M`). On Zen 5 (EPYC
  9R45), `make tune` measures M = 64 at +3.8% on the LPN kernel at the
  production shape.
- `ferret_b9`–`ferret_b13`: SECURITY class. Do not touch for performance;
  how they were selected is in [`lpn-security.md`](lpn-security.md).

## Measured performance analysis

These measurements are from two m8a.8xlarge (cluster placement group,
Release builds using one tuner result frozen across both hosts). The
frozen result selected cGGM tile 64 and LPN batch 64. The README's tables
are measured on two m8a.large with the same tuner result. Their single-core
rows agree with the m8a.8xlarge figures to within a few percent; the
aggregate-bandwidth figures below are m8a.8xlarge's.

**What binds each configuration.**

- `IKNP` and `SoftSpoken<2>` use 89–98% of the measured 9.54 Gbps
  single-flow rate; semi-honest `SoftSpoken<4>` also reaches 92%.
  That rate is the AWS per-connection
  ceiling (~10 Gbps inside a cluster placement group, ~5 Gbps outside;
  ENA Express/SRD would lift it to ~25 Gbps but is unsupported on m8a).
  A pair of these instances carries 14.9 Gbps aggregate over ≥2 flows — the NIC's
  15 Gbps baseline — which is what `clone_lane` exists to exploit.
  Their compute limits are only visible on loopback: `SoftSpoken<2>`
  semi runs ~2× faster there on the same silicon.
- Malicious mode hashes every wire byte into the Fiat–Shamir transcript
  on both sides, in-line. For `IKNP` this hides entirely under the wire
  wait (semi ≈ malicious throughput). For `SoftSpoken<2>` it does not:
  the malicious row sits at 89% of the link (vs semi's 96%) with
  essentially the same wire volume — the gap is transcript hashing on
  the critical path. SHA-256 runs 15–17.6 Gbps on these cores, so on
  links faster than that (multi-lane aggregate, ENA Express) the
  transcript hash — not the wire — becomes the malicious-mode ceiling
  for the comm-heavy protocols. emp-tool's `EMP_FS_HASH=blake3` build
  option swaps that hash for BLAKE3.
- Malicious `SoftSpoken<4>`, both `SoftSpoken<8>` modes, `Ferret`, and
  `SilentFerret` are CPU-bound at these link rates. The published values
  use nine-run medians: `IKNP` and semi-honest `SoftSpoken<2>` varied by under 1%
  across the runs, semi-honest `SoftSpoken<4>` and malicious `SoftSpoken<2>` by
  about 3%, and the CPU-bound rows by 4–10%, so no blanket reproducibility figure
  is claimed.

**Wire-format facts behind the bits/RCOT column.** At the common
33,251,328-output length (two `ferret_b12` rounds), Ferret uses 0.476
bits/RCOT including the one-time bootstrap (0.388 in steady state).
SilentFerret sends the same correction stream. The semi-honest totals are
identical; in malicious mode a two-round prepaid batch folds the two
per-round checks into one, saving 48 bytes total (about 0.000012
bits/RCOT). Parameter choice must be agreed by both parties.

These measurements include no tuned-versus-default A/B, so they make no
claim about the tuner's isolated contribution. Any such A/B must freeze
one source revision and compare both builds in the same interleaved
session.
