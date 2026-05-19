# Agent guide for emp-ot

Entry point for AI coding agents working on this repository. Read
this file first, then load only the subdocs relevant to your task.

## Project at a glance

emp-ot is the OT layer of the EMP toolkit, on top of emp-tool. It
ships three families of protocols:

- **Base OTs** (chosen-input): `OTCO`, `OTCSW`, `OTPVW`, `OTPVWKyber`.
- **OT extensions** (RandomCOT): `IKNP`, `SoftSpokenOT<k, kChunkBlocks>`,
  `Ferret`.
- **sVOLE extensions** (authenticated linear correlations):
  `F2kVOLE` (= `Svole<AuthValueF2k>`),
  `FpVOLE` (= `Svole<AuthValueFp>`).

Two abstractions tie those families together. `StreamingExtension<Element>`
(in [`emp-ot/common/streaming_extension.h`](emp-ot/common/streaming_extension.h))
is the shared begin/next/end + leftover + Fiat-Shamir lifecycle for
both OT and sVOLE extensions. Each protocol family then plugs in
under it: `OTExtension : public StreamingExtension<block>` adds Δ /
base_ot / choice_prg; `Svole<AuthValue, IO> : public StreamingExtension<AuthValue>`
parameterizes on a carrier type. The carrier (`AuthValueXxx`) is
where every protocol-specific detail lives — field type, arithmetic
ops, wire-format traits, chi-fold helpers, LPN ops, sVOLE bootstrap.
The generic templates (`Svole<>`, `MultiPointGadget<>`, `Lpn<>`) only
see the carrier through this contract.

Shared kernels (gadgets the protocols compose, not specific to one
family) live in [`emp-ot/common/`](emp-ot/common/):
`mp_gadget.h` (multi-point sibling-OT), `lpn.h` (LPN amplifier),
`cggm.h` (Half-Tree cGGM puncturable PRF), `streaming_extension.h`
(the lifecycle base).

## Building and running tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Most tests are two-party — they need a sender and a receiver
running concurrently on localhost. The `./run` script does the
launch:

```bash
./run ./build/test_choice_seed              # alice + bob; default port
./run ./build/test_f2k_vole
./run ./build/bench_ferret_rcot
```

Single-process tests / benches run directly:

```bash
./build/bench_lpn
./build/bench_cggm
```

`ctest` knows which kind each is (CMakeLists.txt registers them via
`add_test_case` for single-process or `add_test_case_with_run` for
two-party). To rebuild + re-run one test in isolation:

```bash
cmake --build build -j --target test_f2k_vole
./run ./build/test_f2k_vole
```

### Deterministic mode (`EMP_TEST_MODE=1`)

emp-tool's test-mode hook swaps every randomness source for a
counter-derived deterministic stream — same inputs, same wire bytes
across runs and across machines. Required for the wire-trace gate
and for any byte-equivalence diagnostics:

```bash
EMP_TEST_MODE=1 ./run ./build/trace_hash | grep '^[A-Za-z(]' > /tmp/before.txt
# … apply a change, rebuild …
EMP_TEST_MODE=1 ./run ./build/trace_hash | grep '^[A-Za-z(]' > /tmp/after.txt
diff /tmp/before.txt /tmp/after.txt    # must be empty for wire-equivalence
```

Without `EMP_TEST_MODE=1`, the hashes are non-deterministic and the
diff is meaningless. See [docs/wire-trace-hashes.md](docs/wire-trace-hashes.md)
for the full workflow and the README baseline.

### Build flavors

The `build/` directory is the default (Release-style: optimized,
no asserts beyond `NDEBUG`-respecting). A `build-debug/` is also
checked in for debugging:

```bash
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug -j
ctest --test-dir build-debug --output-on-failure
```

Debug builds use shorter stress lengths in some tests so the suite
finishes in reasonable time; the wire-trace baseline in README is
Release-mode and won't match Debug-mode output.

## When to read what

Pick the smallest set of subdocs that covers your task. Each is
self-contained and assumes you've read this index.

| Task | Subdoc(s) |
|---|---|
| Understand who inherits from whom; where each carrier / gadget / LPN / cGGM lives | [docs/class-organization.md](docs/class-organization.md) |
| Modify a `Svole<>`, `Ferret`, `IKNP`, or `SoftSpokenOT<>` body | [docs/class-organization.md](docs/class-organization.md) + [docs/streaming-api.md](docs/streaming-api.md) |
| Modify the begin/next/end lifecycle, leftover buffer, or Fiat-Shamir hooks on `StreamingExtension` / `OTExtension` | [docs/streaming-api.md](docs/streaming-api.md) |
| Add a new sVOLE field, OT extension, or base OT | [docs/adding-a-protocol.md](docs/adding-a-protocol.md) (+ [class-organization.md](docs/class-organization.md) for the shape of the carrier contract) |
| Modify a carrier (`AuthValueFerret` / `AuthValueF2k` / `AuthValueFp`) | [docs/class-organization.md § "The carrier is the protocol description"](docs/class-organization.md) |
| Modify a chi-fold flavor (`F2kPacked` vs `FTyped`) inside `mp_gadget.h` | [docs/class-organization.md § "The inner gadget"](docs/class-organization.md) + [adding-a-protocol.md § 4](docs/adding-a-protocol.md) |
| Verify a refactor didn't change wire bytes | [docs/wire-trace-hashes.md](docs/wire-trace-hashes.md) |
| Investigate a non-empty trace-hash diff | [docs/wire-trace-hashes.md § "You changed the hash. Now what?"](docs/wire-trace-hashes.md) |
| Diagnose at byte level after `trace_hash` flags a change | [docs/wire-trace-hashes.md](docs/wire-trace-hashes.md) (`trace_equiv.cpp` is the byte-level drill-down) |

## Top-level rules (apply to all work)

These are short enough to live here so you don't have to load them
from a subdoc.

- **Wire-trace check before *and* after any change that could touch
  bytes on the wire.** Run
  `EMP_TEST_MODE=1 ./run ./build/trace_hash | grep '^[A-Za-z(]' > /tmp/<phase>.txt`
  before the change, again after, and `diff` them. Empty diff means
  the wire is preserved. Any change to the protocol's wire format —
  even an algebraically equivalent reordering — must be intentional
  and update the baseline table in [README.md](README.md). See
  [docs/wire-trace-hashes.md](docs/wire-trace-hashes.md) for the full
  workflow. This is the single most important rule in this repo.

- **Buffer-length and count parameters use `int64_t`.** Not `int`
  (overflows at 2^31 elements) or `size_t` (underflows in `len -=
  batch` loops). This mirrors the convention emp-tool's public API
  uses and which Ferret's `param.t`, `param.M`, `chunk_size()`, etc.
  already follow. Internal counters (`int64_t i = 0; i < len; ++i`)
  match. Template non-type parameters (`int k`, `int kChunkBlocks`)
  stay `int`.

- **Carrier-first when extending.** New field, new wire shape, new
  chi-fold convention — express it as a new `AuthValueXxx` carrier
  in a fresh header under `emp-ot/svole/` or alongside the protocol
  that uses it. The generic templates pick it up via its trait
  constants and static methods; don't write a parallel
  `MyFieldGadget` / `MyFieldLpn`. See
  [docs/adding-a-protocol.md § 1](docs/adding-a-protocol.md).

- **Lazy bootstrap, gated by `setup_done`.** Subclasses do no wire
  I/O in their constructor — pre-bootstrap setters (`set_delta`,
  `set_choice_seed`) need a window to fire. The first `do_begin`
  performs the bootstrap and flips `setup_done = true`; subsequent
  begins see `setup_done` and skip. Setters assert `!setup_done` to
  catch ordering bugs.

- **Fresh NetIO per protocol in diagnostic harnesses.** When running
  multiple protocols back-to-back from the same binary (as
  `test/trace_hash.cpp` does), construct a fresh `NetIO` (or
  whichever transport) for each protocol — don't try to reuse one
  IOChannel across protocols with `disable_fs` / `reset_fs` /
  similar plumbing. Each protocol's `enable_fs(send_first)` has its
  own convention; mixing them on one IOChannel desyncs the chi-fold
  check. A fresh socket per protocol is slower but isolates state
  reliably.

- **No perf numbers in comments.** Comments explain design logic.
  Benchmark deltas, "this was 3× faster", etc., belong in commit
  messages — they rot in source.

- **No downstream refs in upstream comments.** Headers in `common/`
  describe their own contract. Don't name a specific caller
  ("used by Ferret's MPCOT bootstrap" etc.) — those rot when the
  caller renames or moves.

- **`random_data_unaligned` at unaligned call sites.** emp-tool's
  `PRG::random_data` asserts 16-byte alignment on the destination.
  For stack-allocated ints, small structs, and any other call site
  that isn't naturally aligned, use `random_data_unaligned`. Don't
  retrofit `alignas(16)` onto a local just to satisfy `random_data`.

- **`int64_t` length params, not `int` or `size_t`** — repeated here
  because it's the single most-common API mistake. New emp-ot APIs
  taking a "number of bytes / blocks / bools / OTs" parameter follow
  this convention.

- **New file-scope `block` / `__m128i` constants use `inline constexpr
  makeBlock(...)`** — never `inline const`, `static const`, or other
  dynamic-init forms. The current codebase's `zero_block`,
  `lsb_only_mask`, etc. are the model. See emp-tool's
  [`docs/static_init.md`](https://github.com/emp-toolkit/emp-tool/blob/main/docs/static_init.md)
  for the underlying reason.

- **Commit policy.** Only commit when explicitly asked. When asked,
  surface the drafted commit message first and wait for a go-ahead;
  use `-F /tmp/<file>` to pass multiline messages (heredocs corrupt
  apostrophes). Don't push without an explicit instruction.
