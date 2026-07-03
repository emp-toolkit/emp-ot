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
# The Zen-5-winning configuration (recoverable via make tune, future):
#   lpn_batch_m = 64
#   gather prefetch, ahead-distance 4, enabled when table > 2 MiB
# Implementation sketch: template <bool Prefetch> split of Lpn::compute_block,
# per-instance selection from the table size (see 0b61590's diff).
```

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

## The autotune plan (for performance-sensitive users)

Phased; defaults always remain the safe swept-conservative values.

- **Phase 0 — classify and socket.** Mark every `tuning.h` constant with its
  class (LOCAL / AGREEMENT / SECURITY). Wrap LOCAL constants in
  `#ifndef`-style overrides and include a generated `tuning_local.h` when
  present (`__has_include`). No behavior change.
- **Phase 1 — derive where a formula truly exists.** Some knobs are honest
  functions of queryable machine facts. Note the LPN prefetch threshold is
  NOT one of them (see above); candidates must prove the formula on at least
  two microarchitectures before shipping.
- **Phase 2 — `make tune` (the old-style configure).** An opt-in target that
  sweeps the LOCAL knobs with the methodology above (interleaved, medians of
  ≥3 rounds, variance-gated) and emits `tuning_local.h` with provenance (CPU
  model, cache sizes, date, and the measured table baked into a comment). A
  tuned value whose measured advantage is inside the noise band is not
  emitted. The tuner enumerates a registry of LOCAL knobs only.

## Sweep provenance of current defaults

- `cggm_tile_x86_vaes512/vaes256 = 32`, `cggm_tile_aarch64 = 4`: swept as
  part of the cGGM tile work (see git history of tuning.h).
- `softspoken_chunk_blocks` (64 for k ≤ 4, 128 for k = 8): AGREEMENT class;
  swept on x86, both parties must match.
- `lpn_batch_m = 32`, no gather prefetch: the safe cross-platform setting
  (see the case study above). Zen-5-only users can recover ~+10% on the LPN
  kernel with the parked recipe.
- `ferret_b13/b12/b10`: SECURITY class. Do not touch for performance.
