# Performance tuning: parameter classes, sweep results, and the autotune plan

This documents why `tuning.h`'s constants are the way they are, what has been
measured on which hardware, and the design for letting performance-sensitive
users tune their own machines. It exists because a tuning change that was a
clear win on the machine it was swept on turned out to be a regression on a
different tier of CPU (details below) — the lesson is recorded here so it is
not re-learned.

## Three classes of parameter

Not everything that looks like a knob may be tuned, and the boundary is a
correctness/security line, not a performance one. Every constant in
`tuning.h` belongs to exactly one class:

| Class | Meaning | Examples | Tunable? |
|---|---|---|---|
| **LOCAL** | Changes scheduling/layout only; the computed function and every byte on the wire are identical, so parties may differ freely | `lpn_batch_m`, `cggm_tile_*`, choice of transpose/packing kernel | Yes — per machine |
| **AGREEMENT** | Shapes the transcript (chunk boundaries, message sizes); every party must use the same value | `softspoken_chunk_blocks` (d_buf chunking), `softspoken_ferret_bootstrap_chunk_blocks` | Only by out-of-band agreement; per-machine tuning desyncs heterogeneous parties |
| **SECURITY** | Part of a proof | LPN parameter sets (`ferret_b*`: t, logk, depth), bucket sizes, MITCCRH `ReuseShift`, ssp | Never |

Any future autotuner must be physically unable to touch the AGREEMENT and
SECURITY classes. A tuner that "optimizes" one party's chunk size breaks
interop; one that touches LPN parameters breaks the security claim.

## Case study: the LPN gather tuning (added 0b61590, reverted 7efb923)

The LPN fold does `d = 10` random 16-byte gathers per output into the `pre`
table (ferret_b13: 2^19 blocks = 8 MiB). Two seemingly-safe LOCAL changes were
swept on AMD Zen 5 (1 MiB private L2, 32 MiB L3 per CCX):

- `lpn_batch_m` 32 → 64 (more independent accumulator chains in flight);
- software prefetch of upcoming outputs' gather targets, gated on table size
  > 2 MiB (all M·d indices sit in the PRG scratch before the fold, so the
  targets are known ahead of use).

Swept results (bench_lpn, ns/output at n = 2^22):

| table (logk) | Zen 5 | Apple M4 | Intel Granite Rapids (c8i) |
|---|---|---|---|
| 2^10 (16 KiB) | +5% | flat/regress | **−3.3%** |
| 2^17 (2 MiB) | wash | — | −4.3% (the one Intel win) |
| 2^19 (8 MiB, production) | **+9.8%** | **regression** | **−4.1%** |
| 2^20 (16 MiB) | — | **−21% .. −34%** | — |

Three different microarchitectures, three different verdicts:

- **Zen 5**: both changes win; production tables spill past the small L2 and
  the prefetch hides L3 latency.
- **Apple M4**: both changes lose. The large shared L2 keeps even "large"
  tables cache-resident; the wider batch thrashes.
- **Granite Rapids**: both changes lose at production size. The 480 MiB
  shared L3 means the 8 MiB table never approaches memory; prefetch has no
  latency to hide and is pure instruction overhead.

Two deeper conclusions, which drove the revert:

1. **Fixed constants failed out-of-sample.** The first unswept tier (Intel)
   regressed at exactly the size that matters.
2. **Formula derivation also fails for this knob.** The natural fix — derive
   the prefetch threshold from the machine's cache sizes at runtime — does
   not work: the 8 MiB table is L3-resident on BOTH Zen 5 and Granite Rapids,
   yet prefetch helps on one and hurts on the other. No queryable quantity
   separates the two behaviors. Only measurement on the actual machine does.

Hence the revert: defaults must be safe on hardware nobody swept, and the
recipe is parked here for the tuner to recover per-machine:

```
# The Zen-5-winning configuration (as parked at the time):
#   lpn_batch_m = 64
#   gather prefetch, ahead-distance 4, enabled when table > 2 MiB
# Implementation sketch: template <bool Prefetch> split of Lpn::compute_block,
# per-instance selection from the table size (see 0b61590's diff).
```

**Case study closed (2026-07):** the tuner swept both halves of the recipe
independently, interleaved, on 12 microarchitectures (Granite Rapids,
Sapphire Rapids, Ice Lake, Skylake, Zen 3/4/5, Graviton 2/3/4, Apple M4,
across two box sizes for Zen 5). The batch-size half is real — M=64 wins
+1–4% on five of them and is a registry knob. The prefetch half **never
cleared the variance gate anywhere, including Zen 5**: the original +9.8%
decomposes into the M=64 contribution plus non-interleaved sweep drift.
The prefetch knob and its `template <bool Prefetch>` split were removed
(recoverable from git if a future part disagrees).

## Methodology requirements for any sweep

Both failure modes we hit are measurement traps; a tuner (or a human) must
defend against them:

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

## `make tune` (implemented)

Defaults always remain the safe swept-conservative values; tuning is
per-machine, once.

**Release builds tune automatically.** A top-level, non-cross-compiled
`CMAKE_BUILD_TYPE=Release` build sweeps the LOCAL knobs before compiling
the library — the tuner links no emp-ot objects, so it builds first and
measures on an otherwise idle machine, and the library then compiles
with the overrides in the same invocation. The sweep runs only when no
`tuning_local.h` exists, so every build after the first is deterministic
and sweep-free. Debug/unspecified build types and subproject consumers
never auto-tune; `-DEMP_OT_AUTO_TUNE=OFF` opts a Release tree out of a
new automatic sweep. It does not suppress an existing source-tree
`tuning_local.h`; that header remains active until `tune-clean` removes it.

```
cmake --build build --target tune        # explicit re-sweep (any build type)
cmake --build build --target tune-clean  # delete overrides; next build reverts
                                         # (an auto-tune Release tree re-sweeps
                                         #  on its next build; configure with
                                         #  -DEMP_OT_AUTO_TUNE=OFF before that
                                         #  build to keep shipped defaults)
```

A build-dependency subtlety the tooling handles for you: the include of
`tuning_local.h` sits behind `__has_include`, so compiler dependency
files record it only once it exists — creating it does NOT make a plain
rebuild recompile anything. The tuner therefore touches `tuning.h`
whenever it (re)writes the file, which forces every consumer to
recompile on the next build. (Manually deleting or hand-editing
`tuning_local.h` in an already-built tree: `touch emp-ot/tuning.h`
yourself, or use the `tune`/`tune-clean` targets, which handle it.)

How it works:

- **The socket.** tuning.h includes a generated `emp-ot/tuning_local.h`
  when present (`__has_include`); every LOCAL knob is an `#ifndef`-guarded
  macro default forwarded into the existing constexpr. AGREEMENT and
  SECURITY knobs have no macro guard — the generated file has no channel
  to reach them, so the class boundary is enforced by construction.
- **The tuner** (`tools/tune.cpp`, target `emp-ot-tune`). Every knob is a
  template parameter, so all candidate values are instantiated side by
  side in one binary and selected at runtime — one build, one run, no
  reconfigure loop. Each knob is measured at its PRODUCTION shape (chunk-
  sized butterfly, depth-13 trees, the 8 MiB b13 LPN table), with the
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
  cross-product on a Ferret-shaped composite — build one depth-13 tree
  into the out slice, then LPN-fold that slice against the table, per
  candidate pair — and emits the pair that wins the composite. The
  composite is shaped like the default `ferret_b13` regime (depth-13
  trees, 8 MiB table); exhaustive grids at the smaller b11/b12 regimes
  showed no penalty resolvable above run noise. The compute-local knobs
  (`sfvole_tile`, `cot_chosen_input_tile`) stay kernel-scored.
- **The output.** `tuning_local.h` is gitignored and carries provenance
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
`cot_chosen_input_tile`.

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
sleep/wake rendezvous at the per-chunk recv — the same mechanism behind
the k=4 io-stall). Kernel rankings missed the e2e optimum in BOTH
directions: on Granite Rapids the e2e optimum at k=2 is T16 (+12%)
while the kernel is tile-flat; on Zen 5 the kernel prefers T32 (+16%
in isolation) while the e2e optimum is T16. The policy: **the k=2 and
k=4 tiles are swept and reported but never auto-emitted** — only the
k=8 tile (kernel-dominated at 32 AES/OT; verified to transfer
faithfully) is eligible for emission. The forfeited wins are small and
confined to fast-link niches (`SoftSpoken<2>` moves ~8 B/OT and is
bandwidth-bound on real networks; the measured cost of not emitting is
~5% on its malicious path at ≥9 Gbps links, zero elsewhere). Users in
exactly that niche can A/B by hand with `bench_softspoken` and set
`EMP_TUNE_SFVOLE_TILE_K{2,4}` in `tuning_local.h` directly (Granite
Rapids + fast link: T16 at k=2 measured +12%).

## Sweep provenance of current defaults

- `cggm_tile_x86_vaes512/vaes256 = 32`, `cggm_tile_aarch64 = 4`: swept as
  part of the cGGM tile work (see git history of tuning.h).
- `softspoken_chunk_blocks` (64 for k ≤ 4, 128 for k = 8): AGREEMENT class;
  swept on x86, both parties must match.
- `lpn_batch_m = 32`, no gather prefetch: the safe cross-platform setting
  (see the case study above). `lpn_batch_m` is now a registry knob
  (EMP_TUNE_LPN_BATCH_M); the gather-prefetch half of the old Zen-5
  recipe was removed (it never cleared the variance gate on any swept
  machine — see the case study) and is not a knob. Measured `make tune`
  outcome on Zen 5
  (EPYC 9R45): M=64 wins +3.8% on the LPN kernel at the production shape;
  the prefetch half did NOT clear the variance gate there — the case
  study's ~+10% was the combined recipe at the older sweep shape, and
  should not be quoted as a make-tune expectation.
- `ferret_b13/b12/b10`: SECURITY class. Do not touch for performance.

## Measured performance analysis (2026-07 campaign)

Context for the README's observed numbers (two m8a.8xlarge, cluster
placement group, Release builds using one final-source tuner result
frozen across both hosts; raw outputs and the iperf3/ping captures are
archived with the results). The frozen result selected cGGM tile 32 and
LPN batch 64.

**What binds each configuration.**

- `IKNP` and `SoftSpoken<2>` use 91–98% of the measured 9.50 Gbps
  single-flow rate; semi-honest `SoftSpoken<4>` also reaches 91%.
  That rate is the AWS per-connection
  ceiling (~10 Gbps inside a cluster placement group, ~5 Gbps outside;
  ENA Express/SRD would lift it to ~25 Gbps but is unsupported on m8a).
  The same pair carries 14.9 Gbps aggregate over ≥2 flows — the NIC's
  15 Gbps baseline — which is what `clone_lane` exists to exploit.
  Their compute limits are only visible on loopback: `SoftSpoken<2>`
  semi runs ~2× faster there on the same silicon.
- Malicious mode hashes every wire byte into the Fiat–Shamir transcript
  on both sides, in-line. For `IKNP` this hides entirely under the wire
  wait (semi ≈ malicious throughput). For `SoftSpoken<2>` it does not:
  the malicious row sits at 91% of the link (vs semi's 96%) with
  essentially the same wire volume — the gap is transcript hashing on
  the critical path. SHA-256 runs 15–17.6 Gbps on these cores, so on
  links faster than that (multi-lane aggregate, ENA Express) the
  transcript hash — not the wire — becomes the malicious-mode ceiling
  for the comm-heavy protocols. (Mitigations on the roadmap: the
  BLAKE3 transcript backend, and overlapping the absorb with the wire
  wait.)
- Malicious `SoftSpoken<4>`, both `SoftSpoken<8>` modes, `Ferret`, and
  `SilentFerret` are CPU-bound at these link rates. The published values
  use nine-run medians: most rows were tightly clustered, while the
  SoftSpoken<8> series contained isolated slow samples, so the former
  blanket 1–2% reproducibility claim has been removed.

**Wire-format facts behind the bits/RCOT column.** At the common
30,015,488-output length, b13 Ferret uses 0.278 bits/RCOT including the
one-time bootstrap. SilentFerret sends the same correction stream. The
semi-honest totals are identical; in malicious mode a two-round prepaid
batch folds the two per-round checks into one, saving 48 bytes total
(about 0.000013 bits/RCOT). `ferret_b11` measured 0.806 bits/RCOT and
123.8 MOT/s on this setup; parameter choice must be agreed by both
parties.

This absolute-number campaign did not repeat a tuned-versus-default A/B,
so it makes no claim about the tuner's isolated contribution. Any such
A/B must freeze one source revision and compare both builds in the same
interleaved session; older percentages are not carried forward across the
current kernel and SilentFerret changes.
