# emp-ot — audit findings

Distilled from the implementation audit in [`audit-report/`](audit-report/)
(audit basis `481cc1d`, re-verified at HEAD `da3ca9a`). Full ledger with per-claim evidence:
[`audit-report/claims.md`](audit-report/claims.md). Method: 7 subsystem
deep-readers + 3 design critics, 114 claims adversarially verified (96
confirmed / 17 refuted / 1 unverified), every security-class claim checked
through two independent lenses.

This file is the confirmed, action-facing subset. Anchors are repo-relative;
source lives under the inner `emp-ot/emp-ot/…` tree, tests at `test/`.

## Systemic themes

1. **NDEBUG-elidable asserts guard security/correctness invariants.** The
   single most pervasive issue: ~10 findings below are release-build silent
   because the guard is `assert()`. Candidates for promotion to always-on
   `error()`: CSW `length≥80`, Δ LSB=1 (COT and both sVOLE paths),
   `set_delta`-before-`begin` (Fp), double-`begin`, `clone_lane` salt.
2. **Malicious paths are unexercised.** Every consistency-check abort exists
   in code but no test drives a deviating party or malformed message; all
   `malicious=true` runs are honest-execution correctness only.
3. **Streaming contract is doc-prose, not enforced.** Mode-mixing hazards
   (`run()` vs `begin/next_n`, `produce_range` vs cursor, auto-rollover)
   are documented but caught only by debug asserts — silent corruption or
   distributed hang under NDEBUG.

---

## HIGH severity

### H1 · `clone_lane` salt is the only lane domain separator, assert-only
`emp-ot/ot_extension/softspoken/softspoken.cpp:104,480`; `softspoken.h:78,85,121`

`lane_salt` (nonzero, distinct per lane) is the sole separator between
concurrent lanes sharing one Δ and one PPRF leaf set. It is asserted nonzero
only (NDEBUG-elidable) with **no duplicate check**, over a 16-bit space. A
zero or duplicate salt makes the per-chunk AES key `makeBlock(lane_salt,
session)` identical across two lanes (session counters both start at 0), so
they **silently emit byte-identical COT streams — Δ/choice reuse**. Directly
affects the lane-parallel COT feature (`481cc1d`); a fix should make the salt
contract an always-on check and dedup nonzero salts.

### H2 · Fp sVOLE runs with Δ=0 if `set_delta` is forgotten → forgeable MACs
`emp-ot/svole/fp_vole.h:105`; `svole.h:119,131-136`; `test/test_fp_vole.cpp:55-62`

The Fp path never asserts `set_delta` was called before `begin()`; the
default `delta_value_` is 0, so a caller who forgets it runs the whole sVOLE
with Δ=0, yielding trivially forgeable MACs. No precondition guard.

### H3 · No malicious/negative test anywhere
`emp-ot/common/mp_gadget.h:592-593,664-665`; `base_ot/csw.h:171,252`; `svole/fp_base_svole.h:261-275`; `test/test.h:14-37` (+ all test drivers)

The consistency-check abort paths (mp_gadget χ-fold, IKNP/SoftSpoken
tampered-matrix/PPRF, CSW send/recv-check, `Point::from_bin` off-curve, BMM
malformed `r`, FTyped/COPE sVOLE checks) are never exercised negatively.
Repo-wide grep for corrupt/tamper/malform/deviate/off-curve/bit-flip/
FaultIO/EXPECT_DEATH → zero hits. The malicious security is untested.

### H4 · `check_cot`/`check_rot` have zero callers
`test/test.h:40-61,64-82`; `emp-ot/ot.h:42-43,84-116`

The chosen-message COT/ROT wire paths (`send_cot/recv_cot`, `send_rot/
recv_rot`) have no exercising test in any `test/*.cpp` or `bench/*.cpp` —
entirely unverified by CI.

### H5 · `check_rcot_streaming` has zero callers
`test/test.h:118-128`

The `begin()/next()/end()` streaming contract central to the subsystem is
verified only indirectly (via `run()`'s internal loop), never directly.

---

## MED severity

### Base OT
- **M1 · CSW `length≥80` (σ=40 extraction bound `l>2σ`) is assert-only** —
  a release caller passing `length<80` silently weakens security, no abort.
  `base_ot/csw.h:105,182,46`
- **M2 · SHAKE-128/256 + `gen_matrix` reimplemented on OpenSSL EVP** rather
  than lifted from pq-crystals — the primary non-upstream code needing
  independent audit against FIPS 202 / the Kyber spec (the `kyber/`
  arithmetic files are byte-identical to upstream). `mlkem/crs.hpp:35-92`;
  `mlkem/symmetric.h:104-198`
- **M3 · OpenSSL <3.3 SHAKE squeeze falls back to an O(n²) loop**; byte-
  identity with `EVP_DigestSqueeze` and cross-version interop is untested.
  `mlkem/symmetric.h:60-62,128-150`
- **M4 · A CSW instance is stateful across the core/check split** (`p0_/p1_/
  p_bi_/b_copy_/length_` overwritten per core call) — not safe for
  concurrent/interleaved OT batches. `base_ot/csw.h:72,104,181`

### OT extension
- **M5 · base-OT extraction check deferred to parent's first `end()`**;
  `setup_done` guarantees only the PPRF check ran. `ot_extension.h:132,137`
- **M6 · Δ LSB=1 invariant is assert-only** (also ctor-pinned) — release
  build unguarded. `ot_extension.h:79,165`; `ot.h:150`
- **M7 · `run()`/rcot vs `begin/next_n` mutual exclusion is doc-only** — one
  shared `leftover_` buffer, no assert against mixing; a classic OT call on
  an instance holding a long-lived session (e.g. emp-zk's persistent
  Ferret) double-enters, caught only by a debug assert →
  silent draw-ordering corruption under NDEBUG. `streaming_extension.h:163-177`
- **M8 · tripwire posture** — `~StreamingExtension` mid-session is always-on
  `error()`, but enter/exit checks are debug-only asserts; the receiver null
  `gadget_send_` deref path is real. `ot_extension.h:76`; `streaming_extension.h:133-161`

### Silent (Ferret / SilentFerret)
- **M9 · `abs_round_` advances only in `end()`** — a `begin()` reusing a
  non-advanced `abs_round_` repeats the LPN and cGGM-seed PRG streams (fork
  `G = abs_round*t + local`); NDEBUG-reachable. `ferret/silent_ferret.cpp:150,87`
- **M10 · `produce_range` + cursor mixing → duplicate COTs** in a prepaid
  round (const, no cursor advance); the nearby assert is bounds-only.
  `ferret/silent_ferret.h:104`; `cpp:235`
- **M11 · `prepare_all` bit-identity to serial is structural, not asserted**;
  no pooled test verifies transcript identity. `common/mp_gadget.h:196-198,499-506`
- **M12 · SilentFerret: `gadget_send_->prg` must never advance after
  `cggm_seed_key_` is captured** — a `Ferret::run_next_tree` on the sender
  gadget silently produces wrong COTs. `ferret/silent_ferret.cpp:71,78`
- **M13 · Fp LPN `kLpnSafeAddsPerReduce=5` is overflow-critical, unguarded**
  — `d=10` adds must not overflow the Mersenne accumulator before a partial
  reduce; no runtime bound check, no overflow test. `common/lpn.h:52-65`
- **M14 · `Ferret::bootstrap_` leaves `csw_base_` dangling** — `base_ot` is
  `std::move`d into a temporary destroyed on return; safe today only because
  the guard is assert-only. Any future code keyed on `csw_base_ != nullptr`
  (or a release-build post-bootstrap `set_sid`) is a UAF/null-deref.
  `ferret/ferret.cpp:156-157`
- **M15 · Auto-rollover does live I/O inside a "wire-free" draw** — if peer
  cumulative draw counts diverge, one side blocks in the reprepay exchange
  while the other never enters it → silent distributed hang, no draw-total
  handshake. `ferret/silent_ferret.cpp:211`

### sVOLE
- **M16 · Mixed sid derivation** — inner Ferret gets a derived child sid,
  the gadgets get the raw `sid.value()`; separation depends on no concurrent
  raw-sid reuse. `svole/svole.h:208,221-226`
- **M17 · F2k Δ LSB=1 is assert-only** — release accepts an even Δ.
  `svole/f2k_vole.h:93-100`
- **M18 · `AuthValueFp` aligned `__m128i` loads on an 8-byte-aligned struct**
  — `{uint64_t val; uint64_t mac;}` has no `alignas(16)`, yet `auth_add_into`/
  `auth_partial_reduce` reinterpret_cast to `block*` and use aligned-load
  intrinsics; formal UB that works by allocation accident and can fault
  (movaps/movdqa) at an 8-mod-16 offset. `svole/fp_vole.h:83-96`; `common/lpn.h:60`
- **M19 · `AuthValue` val-first layout is a comment-only cross-repo ABI** —
  emp-zk depends on `val` in the low 64 bits and reinterpret_casts
  `__uint128_t*` → `AuthValueFp*` (`ostriple.h:59`) on every draw, with no
  `static_assert` on `sizeof`/`offsetof` to back it; reordering silently
  corrupts downstream. `svole/f2k_vole.h:26-31`; `fp_vole.h:28-31`

### Build / tuning (added in the `da3ca9a` refresh)
These two are reproducibility/build-hygiene, not wire security: the only
overridable knobs are LOCAL-class and `test/test_tuning_invariance.cpp`
asserts bit-identical output across their extreme values, and the
AGREEMENT/SECURITY constants have no macro channel (`tuning.h:20-25`).
- **M20 · A default Release build writes a machine-generated `tuning_local.h`
  into the source tree** — `EMP_OT_AUTO_TUNE` defaults ON for a top-level,
  non-cross `Release` configure, and the `tune-auto` `ALL` target
  (`add_dependencies(emp-ot tune-auto)`) runs the sweep *before* the library
  compiles, emitting `emp-ot/tuning_local.h` into the checked-out source dir
  (and `utime`-touching the tracked `tuning.h` to force the recompile). The
  default optimized build therefore mutates the working tree and bakes
  per-machine knob values into the binary — the shipped artifact is no longer
  a pure function of the commit — and the file is `.gitignore`d, hiding the
  mutation from `git status`. Opt out durably with `-DEMP_OT_AUTO_TUNE=OFF`;
  `make tune-clean` only reverts to swept defaults, and a later default
  Release build re-tunes. `CMakeLists.txt:30-38`; `tools/CMakeLists.txt:43-53`;
  `tools/tune.cpp:411-444`; `.gitignore:59`
- **M21 · `tuning.h` is not a pure function of the commit — an ODR-adjacent
  axis** — each LOCAL knob is an `EMP_TUNE_*` `#ifndef`/`#define` socket filled
  by the shipped default or by a `__has_include("emp-ot/tuning_local.h")`
  override whose *presence* differs per checkout, so two builds of the same
  commit can bake different `inline constexpr` values (`cot_chosen_input_tile`,
  `cggm_tile()`, `sfvole_tile<k>()`, `lpn_batch_m`) into these header-inline
  symbols. Within one link all TUs agree, so there is no in-build violation;
  but a prebuilt `libemp-ot` from a tuned checkout linked against a consumer
  that includes `tuning.h` with no `tuning_local.h` present gives the two
  sides disagreeing definitions of the same inline symbols — a latent
  one-definition hazard across the header boundary. A `static_assert` pin, or
  a documented "regenerate-or-absent consistently across a lib+consumer pair"
  rule, would close it. `emp-ot/tuning.h:27-29,73-76,87-104,118-131,190-193`

---

*Refuted claims (17) are dropped or corrected in place in `claims.md` —
notably the wire-trace README baseline was independently re-run this pass and
matches byte-for-byte (no drift).*
