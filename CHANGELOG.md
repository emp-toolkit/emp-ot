# Changelog

Notable changes to emp-ot. Versions are the git tags. CMake package
metadata is numeric (see the README's version guidance).

## Unreleased

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
  are unchanged. With the coefficients, `F2kVOLE`'s LPN stage is a large-field
  instance, and the large-field figures above cover it. Needs an emp-tool with
  `vector_inn_prdt_sum_red_x4`.

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
