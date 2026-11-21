# Changelog

Notable changes to emp-ot. Versions are the git tags. CMake package
metadata is numeric (see the README's version guidance).

## Unreleased

### Security

- `F2kVOLE` / `FpVOLE`: the multi-point gadget hashes every tree leaf before it
  becomes a field element, with a MITCCRH stream: one gid per leaf, taken by both
  parties in the same order, from a fresh start point
  `RO("emp-ot:mpcot:leaf-hash", sid, round)` each round. The sVOLE trees are
  correlated GGM trees whose every level XORs to the inner `Ferret`'s Δ, which
  all trees share; the hash keeps each punctured leaf pseudorandom to the
  receiver, as the sVOLE relation needs. All sVOLE outputs and transcripts
  change: both parties must upgrade together, and the sVOLE rows of
  `test/trace_hash.baseline` are regenerated. `Ferret` and `SilentFerret` are
  unchanged.
- `FpVOLE`: every F_p element received from the other party (the base sVOLE's
  corrections, check reply and check seed, and the multi-point gadget's
  per-tree sum and check value) must be canonical, below p, or the receiving
  party aborts. The field arithmetic assumes canonical operands. `recv_fp`
  (`svole/fp_utility.h`) is the F_p receive, and a `kHasSecretSum` carrier
  provides `f_canonical(F)` for the gadget. Honest transcripts are unchanged.
- `F2kVOLE` / `FpVOLE`: the round-final check compares the two parties' check
  values by an equality test in which the Δ-holder commits first. The receiver
  sends `x*` as before; the Δ-holder answers with a commitment
  `RO("emp-ot:mpcot:check-ftyped", sid, vb, salt)` under a fresh 128-bit salt,
  the receiver reveals its value, and the Δ-holder sends the salt only if the
  values match. The Δ-holder used to send a hash of its value, which is linear
  in Δ, so a receiver that deviated in `x*` could test candidate Δs against it
  offline, a 2⁶¹ search for `FpVOLE`. The check takes one more round trip per
  round. Malicious-mode sVOLE transcripts change: both parties must upgrade
  together, and the malicious sVOLE rows of `test/trace_hash.baseline` are
  regenerated.
- `FpVOLE`: the base sVOLE (COPE) takes its base OTs from `CSW`, which is
  malicious-secure, instead of `CO`, which is semi-honest, through `CSW`'s
  standalone `send` / `recv`, so every `CSW` round, the extraction check
  included, completes before COPE uses an output. A `CSW` batch holds at least
  `CSW::kMinLength` = 80 OTs: COPE runs 80, one per bit of Δ and 19 more with
  random choice bits, and drops the 19. All `FpVOLE` transcripts change: both
  parties must upgrade together, and the `FpVOLE` rows of
  `test/trace_hash.baseline` are regenerated.
- `CSW`: each chosen-input ciphertext is the message XORed with a hash of its
  pad, `RO("emp-ot:csw-base-ot:msg-key", sid, i, p)`, instead of with the pad
  itself. The extraction check sends `χ_i = H3(p_{i,0}) ⊕ H3(p_{i,1})`, so a
  receiver holding one pad learns `H3` of the other, and a ciphertext under the
  bare pad let it test guesses of the message it did not choose, one hash per
  guess: a message with little entropy was exposed. The OT extensions and COPE
  send uniformly random messages through `CSW`, which this did not expose.
  Every transcript that runs `CSW` changes: both parties must upgrade together,
  and the `test/trace_hash.baseline` rows of `CSW` and of every protocol that
  bootstraps through it are regenerated.
- `SoftSpoken::clone_lane(new_io)` no longer takes a salt (issue #103). A lane
  takes a fresh child of its parent's session id, and every `SoftSpoken`
  instance, lane or not, expands its leaves under per-session AES keys derived
  from its own session id, `RO("emp-ot:softspoken:session-key", sid, session)`.
  Two lanes cloned with one salt used to produce the same COTs, with every check
  passing. A lane can also no longer be cloned before its parent's deferred
  base-OT check has run, so no lane certifies outputs ahead of it. Every
  `SoftSpoken` transcript changes, and so does every protocol that bootstraps
  through `SoftSpoken`: both parties must upgrade together, and those
  `test/trace_hash.baseline` rows are regenerated.

- `OTExtension::set_choice_seed` and `Ferret::set_lpn_matrix_seed` are removed,
  and every receiver draws its randomness from its own PRG. `SoftSpoken` built
  its receiver's trees from the choice seed, and `Ferret` and `SilentFerret`
  seeded their nested `SoftSpoken` from it, so two instances given one seed had
  the same receiver state: senders who combined their views read every choice
  bit. The README and the `Ferret` docs described sharing one choice pattern
  across instances, with a shared matrix root, as supported. A protocol that
  needs one party's bits under several keys can instead correct each
  instance's random choices to them, at one bit per COT. Messages are
  unchanged; the receivers now draw from a different PRG stream, so the
  test-mode `test/trace_hash.baseline` rows of the OT extensions and sVOLEs
  are regenerated.
- `FpVOLE` rejects, at its first `begin()`, a custom parameter set whose
  `t + k + 1` exceeds the output of its `ferret_b9` pre-stage. The bootstrap
  copies that many pre-stage outputs into the carry-over, and such a set used to
  make it read before the start of the pre-stage buffer. Every shipped set fits.

### Removed

- `OTExtension::set_choice_seed`, with `OTExtension::choice_prg`, and
  `Ferret::set_lpn_matrix_seed`; see Security.
- `OTIdeal` (`emp-ot/ideal.h`), a test-only ideal COT that no test used. Its
  chosen-input and ROT wrappers went out of step after the first call, because
  the wrapper drew its start point from the PRG the mock shared between parties.

### Changed

- `PrimalLPNParameter` requires `tree_depth ≥ 2`. The cGGM applies its
  leaf-LSB mask only from depth 2 on, so a depth-1 set gave broken COTs in
  semi-honest mode and made honest parties abort in malicious mode.
- `BMM`'s SHAKE shim aborts when an OpenSSL digest call fails, instead of
  continuing with unwritten output.
- `COT::send` and `RandomCOT::recv_cot` flush before returning, as `send_rot`
  does, so a caller whose next step waits on another channel no longer leaves
  its peer blocked.
- The role-explicit wrappers (`send` / `recv`, `send_rot` / `recv_rot`,
  `send_cot` / `recv_cot`) reject a call of the other role on an OT extension.
  A sender-role extension's `recv_cot` used to send its choice bits in the
  clear.
- `EMP_TUNE_LPN_BATCH_M` must be a power of two in [4, 512], checked at compile
  time. Other values fold a different LPN matrix, so parties built with different
  values would silently disagree; a LOCAL knob must not change outputs.
- `tools/lpn_security.py` rejects a missing or negative `--d`, a non-integer
  argument and `k ≤ 0` before it evaluates anything.
- The multi-point gadget's `run_next_tree` takes its tree index as `int64_t`,
  like the parameter set's tree count, and the base sVOLE's receiver flushes its
  check reply instead of relying on its next receive to drain it.
- An OT, OT extension or sVOLE whose session id was not set with `set_sid()`
  takes its channel's next session id (emp-tool's
  `IOChannel::next_session_id()`) at its first use, instead of the zero id.
  First uses come in the order the parties run their protocols, so both draw
  the same ids; nested objects still get derived children of their parent's
  id, and on a channel without a session root the id stays zero. Every
  session-bound derivation (base-OT key derivation and reference points, LPN
  matrices, check hashes) now differs per session, so transcripts change and
  both parties must upgrade together. `session_id()` reads an OT's or
  sVOLE's id. Requires emp-tool's channel session ids.
- Four session-id fixes. The malicious-mode Fiat-Shamir challenges (the chi
  seeds of `IKNP`, `SoftSpoken` and the multi-point gadget that `Ferret`,
  `SilentFerret`, `F2kVOLE` and `FpVOLE` run) hash the transcript digest with
  the session id of the object running the check, `RO("emp-ot:fs-challenge",
  sid)`, instead of using the digest alone. `Ferret::set_sid` no longer gives
  the base OT a child id, which the bootstrap overwrote when it handed the
  base OT to a nested extension; the base OT's id is now set once, by the
  extension that runs it, and `Ferret` no longer keeps a pointer to the base
  OT it hands over. `FpVOLE`'s pre-stage gadgets take their own derived child
  id instead of sharing the main gadgets' id. A `SoftSpoken::clone_lane` lane
  takes its own id, a child of its parent's id, instead of a copy of its
  parent's. Every malicious-mode OT-extension and sVOLE
  transcript changes, and so do semi-honest `Ferret`, `SilentFerret` and
  sVOLE transcripts whenever the object has a session id (set, or taken from
  the channel), since their base OT now runs under a different derived id;
  base-OT transcripts and semi-honest `IKNP` and `SoftSpoken` transcripts are
  unchanged. Both parties must upgrade together, and
  `test/trace_hash.baseline` is regenerated.
- `CO` and `CSW` flush each message as soon as the other party can use it, so
  the two parties' work overlaps. Each direction carries the same bytes in the
  same order, and `test/trace_hash.baseline` is unchanged.
- `PVW` computes u and the c term of each branch as two-point products where
  OpenSSL runs its dedicated P-256 code, which is constant-time for any number
  of points (x86-64 and AArch64), and its receiver streams round 1. Elsewhere
  it keeps two single-point products. Transcripts are unchanged.
- `BMM` streams per OT, with at most 32 OTs outstanding, instead of sending each
  round as one batch. Each direction carries the same bytes in the same order.
  A receiver message that is not canonical now aborts the sender after it has
  replied to the earlier OTs.
- `BMM`'s SHAKE shim fetches its SHAKE implementations once per thread and
  reuses one SHAKE-128 context. It used to resolve OpenSSL's legacy digest
  handles on every initialization and allocate a context per polynomial.
  Outputs are unchanged.
- `FpVOLE`'s base sVOLE (COPE) sends each bit position's corrections in one call
  and no longer builds its four whole-batch arrays, which cuts the bootstrap's
  time and peak memory. Transcripts are unchanged.
- `F2kVOLE`'s bootstrap packs its base COTs window by window from one session
  of the inner `Ferret`, instead of from one buffer holding all of them (139 MB
  at the default set). Outputs and transcripts are unchanged.
- `FpVOLE`: the multi-point gadget's per-tree sums of macs and the check
  accumulation reduce once instead of after every term. A `kHasSecretSum`
  carrier now provides `MacSum`, the per-tree sum. Outputs are unchanged.
- The LPN fold takes each output's indices in a fixed-length loop that unrolls
  fully. Outputs are unchanged.

## v1.0.0-alpha.2

Second alpha of the 1.0 development line, pairing with emp-tool
`v1.0.0-alpha.2`, which it requires (`F2kVOLE` uses its
`vector_inn_prdt_sum_red_x4`). The Ferret, sVOLE and `BMM` transcripts change, so
both parties must upgrade together.

### Security

- Ferret LPN parameter sets `ferret_b9`–`ferret_b13` (default `ferret_b12`),
  selected so that every counted attack costs at least 2¹⁴¹, a 10% margin, for the
  binary instance and for the large-field instance: the lpnestimator.com routines,
  the XFL and WXL algorithms of Furue–Aikawa (eprint 2026/2470), and WXL over the
  sparse rows of the 10-local matrix, and elimination on the samples inside a greedily
  peeled coordinate subset (`docs/lpn-security.md` §3). Tables of 1–16 MiB
  (`ferret_b10`–`ferret_b13` now denote twice the table they did in
  `v1.0.0-alpha.1`; `ferret_b9` is new), one tree level shallower at every table size
  (`logk − tree_depth = 7`), about 1.8× the correction traffic per COT at the same
  table. The `v1.0.0-alpha.1` sets `ferret_b10`–`ferret_b13` (128.1–128.6 bits under
  the estimator, 111.3–120.6 under sparse WXL) are removed. The sets shape the
  transcript: both parties must run the same release; `test/trace_hash.baseline` is
  regenerated. The Ferret bootstrap and the sVOLE pre-stage nest through `ferret_b9`,
  and the bootstrap SoftSpoken chunk follows `ferret_b9.M`. The README gains an *LPN
  security* section; the assumption, the sets and how they were chosen are in
  `docs/lpn-security.md`, and `tools/lpn_security.py` reproduces the Furue–Aikawa,
  sparse-WXL and restricted-ISD costs for any `(N, k, t)`.
- `F2kVOLE`: every entry of the LPN matrix is a pseudorandom GF(2¹²⁸) element
  instead of 0/1, applied to the val and mac halves alike (`common/lpn.h`; a carrier
  opts in with `kLpnCoefficients`). The coefficients come from the same public PRG
  stream as the indices, so both parties derive them locally and nothing extra is
  sent. Rows are folded four at a time with emp-tool's `vector_inn_prdt_sum_red_x4`,
  and the Δ-holder folds its mac half only. `F2kVOLE` outputs and transcripts change:
  both parties must upgrade together, and the `F2kVOLE` rows of
  `test/trace_hash.baseline` are regenerated. `Ferret`, `SilentFerret` and `FpVOLE`
  keep their unit-entry matrices. With the coefficients, `F2kVOLE`'s LPN stage is a
  large-field instance, and the large-field figures above cover it. Needs an emp-tool
  with `vector_inn_prdt_sum_red_x4`.
- `F2kVOLE` / `FpVOLE`: the mask of the round-final malicious check, carry slot `t`, is
  no longer also coordinate 0 of the round's LPN secret. The LPN now reads slots
  `t + 1` to `t + k`, which were already carried, so the check value `x*`, sent in the
  clear, is one-time padded; before, it gave the Δ-holder one linear equation tying
  that coordinate to the round's noise. Both protocols' outputs change in both modes,
  so both parties must upgrade together. `test/trace_hash` gains `F2kVOLE(b9)` and
  `FpVOLE(b9)` rows that run two whole rounds, because an sVOLE round's LPN output
  reaches the wire only through the next round; the baseline is regenerated.
  `Ferret` is unaffected.
- `F2kVOLE` / `FpVOLE`: the public LPN matrix is seeded from the session id, as
  `Ferret`'s is: `RO("emp-ot:f2kvole:lpn-seed", sid)` / `RO("emp-ot:fpvole:lpn-seed",
  sid)`, and `RO("emp-ot:fpvole:pre-lpn-seed", sid)` for `FpVOLE`'s pre-stage, derived
  locally by both parties at bootstrap. Before, every instance used the seed
  `zero_block`, so all sessions shared one matrix, and an instance's main and nested or
  pre-stage matrices read one PRG stream at different `k` (their indices agreed mod the
  smaller `k`). Callers that never call `set_sid` still share one matrix per protocol;
  distinct sids give distinct matrices. Both protocols' outputs change; the sVOLE rows
  of `test/trace_hash.baseline` are regenerated.
- `BMM` base OT: every OT index `i` derives its own CRS matrix `A_i` from
  `(sid, i)`, where one matrix served every index, and the 128-bit OT string is
  carried directly in the first half of the PKE's 256-bit message instead of
  under a hash pad, so the sender sends 1,536 bytes per OT instead of 1,568. The
  transcript changes; the `BMM` row of `test/trace_hash.baseline` is regenerated.

### Added

- Counted OT streams: `begin(n_ots)` records an upper bound on the session's
  coming `next_n()` draws, so a backend can shrink its last production unit, and
  `check()` certifies every chunk generated since `begin()` or the previous
  `check()` while keeping the session open. IKNP, SoftSpoken and Ferret track the
  per-chunk checks; `SilentFerret` certifies in `begin()`, so its `check()` does
  nothing. The first `check()` also runs CSW's deferred base-OT extraction check.
- `SilentFerret` range reducers: an LPN sink path that computes the current
  round's COT XORs with one tree of scratch, and a fused path that skips storing
  the finalized outputs.
- `Ferret::set_lpn_matrix_seed(seed)`, called before bootstrap, seeds the LPN
  matrix independently of the transcript's session id. By default the seed is
  still derived from the session id.

### Changed

- `Ferret`'s constructor takes the injectable base OT before the optional LPN
  parameter, as `IKNP` and `SoftSpoken` do:
  `Ferret(party, io, malicious, base_ot, param)`, where `v1.0.0-alpha.1` had
  `param` before `base_ot`. A caller that passed a parameter set positionally
  must pass the base OT (or `nullptr`) first. `SilentFerret` keeps its order.
- The wire-format gate `trace_hash_baseline` runs only in a Release tree
  configured against an emp-tool built with `-DEMP_TEST_MODE=ON`, since emp-tool's
  deterministic test mode is now a build option; CI gains a test-mode job that
  runs it.
- `./run` uses `EMP_PORT` when set and 12345 otherwise, and `ctest` gives each
  two-party test its own ports from 21000 up.

## v1.0.0-alpha.1

First tagged alpha of the 1.0 development line, pairing with emp-tool
`v1.0.0-alpha.1`. The 0.3.x line (tag `0.3.0` / branch `v0.3.x`) is
maintained separately and receives backported fixes.

### Stability

- Pre-1.0 API: headers and names may change between alpha tags and
  before the final `1.0.0`. Pin to a specific tag, and pin the paired
  emp-tool tag.
- CMake package metadata is numeric `1.0.0` (`project(VERSION)` cannot
  carry a prerelease suffix); the alpha status lives in the git tag.

### Contents

- Base OTs: `CO` (semi-honest), `CSW` / `PVW` / `BMM` (malicious-secure);
  `BMM` is post-quantum over ML-KEM-512 (Kyber) internals.
- OT extensions (RCOT): `IKNP`, `SoftSpoken<k>`, `Ferret`, and the
  wire-free `SilentFerret`.
- Subfield-VOLE generators `F2kVOLE` / `FpVOLE` over Ferret.
- One streaming API (`begin`/`next`/`end`, `next_n`, `run`) across every
  extension, plus OT-extension `begin(n_ots)` and `check()`: counted begin
  bounds session demand and lets SoftSpoken shorten its terminal transfer to
  128-COT granularity, while check certifies a mid-session prefix without
  dropping its buffered tail. Always-on `expecting` lifecycle/argument/role
  contracts survive `NDEBUG`.
- Per-build-directory auto-tuning of LOCAL scheduling knobs
  (output- and wire-invariant; see `docs/performance-tuning.md`).
- Wire-trace framework: `trace_hash` + the `trace_hash_baseline` CI gate
  diff protocol digests against a checked-in baseline, so wire-format
  changes cannot slip through silently.

### Requirements

- emp-tool `v1.0.0-alpha.1` (CMake floor `1.0`); OpenSSL ≥ 3.0;
  CMake ≥ 3.21 (emp-tool needs ≥ 3.25).

### Security

See the README's Security section. In particular: `FpVOLE` malicious
mode is not 128-bit sound (field p = 2⁶¹ − 1), the malicious OT
extensions realize selective-abort functionalities with streaming
outputs provisional until `check()` or `end()`, and `BMM` is a custom
construction over ML-KEM-512 internals (not standardized FIPS-203).
Research software; no independent audit.

The Ferret LPN sets, as `(t, logk, tree_depth)`: `ferret_b13` (1,900, 19, 13) ·
`b12` (1,520, 18, 12) · `b11` (1,170, 17, 11) · `b10` (850, 16, 10), all with
`logk − tree_depth = 6`; `ferret_b13` is the default. Their estimator minimum is
128.2 · 128.1 · 128.2 · 128.6 bits (hybrid; BJMM for `b10`). Under the sparse WXL
of `docs/lpn-security.md` §3 they cost 112.8 · 111.3 · 113.1 · 120.6 bits
(`b13` · `b12` · `b11` · `b10`), and the default costs 130.3 under dense XFL/WXL
over F₂.

## 0.1.0 – 0.3.0

Releases before the 1.0 line. Only their LPN parameters are recorded here.

### Security

- `0.2.4`–`0.3.0`, as `(N, k, t)`: `ferret_b13` (10,485,760; 452,000; 1,280) ·
  `b12` (10,268,672; 238,000; 2,507) · `b11` (10,180,608; 124,000; 4,971), with
  setup sets (470,016; 32,768; 918) · (268,800; 17,384; 1,050) ·
  (178,944; 17,384; 699). Estimator minimum 125.3 · 104.5 · 92.8 bits (hybrid);
  setup 119.8 · 113.7 · 124.0. The `0.3.x` sets were chosen against the
  Liu–Wang–Yang–Yu estimator of 2022, before the regular-ISD, hybrid and AGB 2.0
  attacks.
- `0.1.0`–`0.2.3`: (10,608,640; 589,824; 1,295) with setup (649,728; 36,288;
  1,269), within 2% of the CCS'20 sets of the attack literature
  (10,805,248; 589,760; 1,319) / (609,728; 36,288; 1,269), whose 609,728 is a
  Ferret-paper typo for 649,728. The CCS'20 sets cost 149.9 bits (main) and
  126.6 (setup) under the hybrid attack.
- In every 0.1.0–0.3.0 release the extension round reuses base COTs across
  roles: cGGM choice bits occupy slots `[0, t·log_bin)`, the chi check
  `[0, 128)`, the LPN secret `[128, 128 + k)`, so the first `t·log_bin − 128`
  secret coordinates are also noise-position bits. The setup round is disjoint,
  and the LPN matrix seed is sampled by one party and sent in the clear. The
  estimates above assume the standard instance.
- The sets shape the transcript: both parties must run the same release.
