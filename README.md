# emp-ot

![build](https://github.com/emp-toolkit/emp-ot/workflows/build/badge.svg)
[![CodeQL](https://github.com/emp-toolkit/emp-ot/actions/workflows/codeql.yml/badge.svg)](https://github.com/emp-toolkit/emp-ot/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

> **Which version do I want?**
>
> - **Existing projects pinned to a published release: stay on `0.3.0`** —
>   tag [`0.3.0`](https://github.com/emp-toolkit/emp-ot/releases/tag/0.3.0)
>   or branch [`v0.3.x`](https://github.com/emp-toolkit/emp-ot/tree/v0.3.x).
>   Bug fixes and security patches will be backported to `v0.3.x`.
> - **New projects, or willing to migrate: track the development branch**
>   (this branch). It will become `1.0.0-alpha` after a polish pass and
>   then `1.0.0`. New SoftSpoken butterfly kernel with rounds 0-2
>   fused into AES generation at k=8 (eight leaves' Davies-Meyer
>   outputs folded through three halving levels in-register;
>   cross-platform via emp-tool's AesLane abstraction over VAES-512 /
>   VAES-256 / AES-NI / NEON), post-quantum `PVWKyber` base OT,
>   reorganized base OTs and extensions, the wire-equivalence framework
>   from emp-tool 1.0 — but the API is not yet frozen and headers may
>   move between alphas. Requires emp-tool ≥ 1.0.0-alpha.

State-of-the-art OT implementations on top of [emp-tool](https://github.com/emp-toolkit/emp-tool):
four base OTs (`CO`, `PVW`, `CSW`, `PVWKyber`), IKNP and
SoftSpoken OT extensions (semi-honest + malicious), and Ferret silent
COT extension. All hash functions used for OT are instantiated with
[MITCCRH](https://github.com/emp-toolkit/emp-tool/blob/main/emp-tool/crypto/mitccrh.h)
for optimal concrete security.

> **Heads up — AI-assisted drafts, not yet audited.** `PVWKyber` is not
> yet auditted.

## Requirements

- CMake ≥ 3.21
- A C++17 compiler (Clang ≥ 12, GCC ≥ 9, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- OpenSSL ≥ 3.0. `PVWKyber`'s SHAKE shim uses `EVP_DigestSqueeze` on
  ≥ 3.3 (one-shot squeeze) and falls back to a re-init / re-absorb
  loop on 3.0.x — same answers, slightly slower CRS expansion. No
  build-time configuration needed; the version is detected from
  `OPENSSL_VERSION_NUMBER`.
- pthreads

emp-ot builds a small static library (`emp-ot::emp-ot`) that bundles
the IKNP, SoftSpoken, and Ferret OT bodies; the rest of the surface
(base OTs, headers consumed inline) lives in headers.

## Build and install

emp-ot consumes emp-tool through its installed CMake package. Install
emp-tool first, then build emp-ot the same way:

```bash
# emp-tool
git clone https://github.com/emp-toolkit/emp-tool.git
cmake -S emp-tool -B emp-tool/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-tool/build -j
cmake --install emp-tool/build       # respects CMAKE_INSTALL_PREFIX

# emp-ot
git clone https://github.com/emp-toolkit/emp-ot.git
cmake -S emp-ot -B emp-ot/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-ot/build -j
cmake --install emp-ot/build
```

If you don't want to install emp-tool, point emp-ot directly at its build
tree:

```bash
cmake -S emp-ot -B emp-ot/build \
    -DCMAKE_BUILD_TYPE=Release \
    -Demp-tool_DIR=/abs/path/to/emp-tool/build
```

### CMake options

| Option | Default | Effect |
|---|---|---|
| `EMP_OT_BUILD_TESTS` | `ON` when top-level | Build the test suite under `test/`. |
| `EMP_OT_INSTALL`     | `ON` when top-level | Generate install + export rules. |

## Consuming from another CMake project

```cmake
find_package(emp-ot CONFIG REQUIRED)
target_link_libraries(my-app PRIVATE emp-ot::emp-ot)
```

`emp-ot::emp-ot` is an `INTERFACE` target that pulls in `emp-tool::emp-tool`
transitively, so consumers don't need to find emp-tool separately.

## Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The two-party benches (`bench_iknp_rcot`, `bench_softspoken_rcot`,
`bench_ferret_rcot`, `bench_ot_extension`, `bench_base_ot`,
`trace_equiv`) launch ALICE/BOB on localhost via the `run` script.
`bench_lpn` and `bench_cggm` are single-process
benchmarks of internal kernels.

### Wire-trace hashes

`test/trace_hash.cpp` runs every protocol in the repo under a fresh
`NetIO` with Fiat-Shamir enabled and prints one SHA-256 digest per
direction per protocol. Each protocol is measured from a reset
deterministic seed state, so the digests are *order-independent*:
adding or reordering a protocol changes only its own row. Refactors
that leave the wire bytes untouched leave the hashes untouched;
refactors that *do* change the wire are visible as a single-line
diff. See [`docs/wire-trace-hashes.md`](docs/wire-trace-hashes.md)
for the full workflow.

```
$ EMP_TEST_MODE=1 ./run ./build/trace_hash | grep '^[A-Za-z(]'
```

**Current baseline** (ALICE's view; first 16 hex of each direction's
SHA-256). A change to any of these hashes means the corresponding
protocol's wire format changed — fine if intentional, but flag it
clearly in the commit message and update this table.

`Ferret(b11)` and `SilentFerret(b11)` are run over a whole number of
SilentFerret rounds, where the two are **wire-identical by design**
(SilentFerret only changes *when* the correction traffic is sent, not
the bytes). Their rows must stay equal in both modes; a divergence
means a refactor broke the equivalence, not just one protocol's format.

```
CO                     send=cb1241385e1fa266 recv=1527f501eb006b21
CSW                    send=9f713474307b6bef recv=223f31baeb44267d
PVW                    send=fb1f9d384ef04ffe recv=b64a168b41ee1583
PVWKyber               send=07594864b631b0c5 recv=4a58e856ecca07be
IKNP semi              send=86e8b983c8d94b52 recv=356ed16464da939e
SoftSpoken<2> semi     send=a68cae132c81937b recv=68c283a18fbe3260
SoftSpoken<8> semi     send=a68cae132c81937b recv=bbfe17cba524e658
Ferret(b11) semi       send=d34d028893e1c381 recv=ff4d708e0d3e10ab
SilentFerret(b11) semi send=d34d028893e1c381 recv=ff4d708e0d3e10ab
F2kVOLE semi           send=803c95c701a28917 recv=ded2e867aa512643
FpVOLE semi            send=a4542d2accf6a37d recv=64284c447cd40386
IKNP mali              send=86e8b983c8d94b52 recv=407f8129b0560674
SoftSpoken<2> mali     send=a68cae132c81937b recv=4163eb51f573dea9
SoftSpoken<8> mali     send=a68cae132c81937b recv=01c693ab2d69ad70
Ferret(b11) mali       send=718c719155039ea3 recv=c53770674b0d8bfa
SilentFerret(b11) mali send=718c719155039ea3 recv=c53770674b0d8bfa
F2kVOLE mali           send=9b19bae6bbfa35eb recv=4430fbb61f5e79d4
FpVOLE mali            send=612f33f1b5ba8273 recv=dd149a3730c384e6
```

## Usage

```cpp
#include <emp-tool/emp-tool.h>     // NetIO etc.
#include <emp-ot/emp-ot.h>         // OTs
using namespace emp;

NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);
```

### Interfaces

All OTs in emp-ot derive from a four-layer hierarchy in
[`emp-ot/ot.h`](emp-ot/ot.h) and
[`emp-ot/ot_extension/ot_extension.h`](emp-ot/ot_extension/ot_extension.h).
Each layer adds methods on top of the previous one; you can always
call a lower-level method on a higher-level object.

| Interface                 | New methods                                       | Semantics added                                                                 |
|---------------------------|---------------------------------------------------|---------------------------------------------------------------------------------|
| `OT`                      | `send(m0, m1, n)` / `recv(mc, c, n)`              | chosen-input 1-out-of-2: sender supplies both messages, receiver picks one      |
| `COT : OT`                | `send_cot(m0, n)` / `recv_cot(mc, c, n)`; free `send_rot`/`recv_rot` | chosen-correlation: sender's two messages always differ by a public `Delta` |
| `RandomCOT : COT`         | `rcot(data, n)` (role implicit in instance party) | random correlation: no choice-bit input; receiver's choice ends up in `getLSB(data[i])`, and `Delta`'s LSB is forced to 1 so the correlation survives that one bit |
| `OTExtension : RandomCOT` | `set_delta(const bool* delta_bool)` (sender-only Δ override), `chunk_size()`, `begin/next/end`, `next_n(data, n)`, `run(data, num)` | streaming RCOT (one fixed-size chunk per `next`); base-OT bootstrap fires lazily on the first `begin` |

Concrete classes attach as follows:

- **Base OTs** (`OT` only): `CO`, `PVW`, `CSW`, `PVWKyber`.
- **OT extensions** (`OTExtension`, so all of the above): `IKNP`,
  `SoftSpoken<k>`, `Ferret`.

The chosen-input / chosen-correlation / random conversions are
implemented once in the base classes (one MITCCRH pass per OT for the
chosen-message wrapper, one bit per OT for the random → chosen
correction), so picking a backend never forces you to also pick a
flavor.

### Base OTs

The four base OTs (`CO`, `PVW`, `CSW`, `PVWKyber`) implement
only the `OT` interface — chosen-input 1-out-of-2.

```cpp
block m0[length], m1[length];   // sender's two messages
block mc[length];               // receiver's chosen message
bool  c [length];               // receiver's choice bits

PVW ot(&io);
if (party == ALICE) ot.send(m0, m1, length);
else                ot.recv(mc, c, length);    // mc[i] = m_{c[i]}
```

All four implement the same `OT` interface. `CO` is semi-honest;
`CSW`, `PVW`, `PVWKyber` are malicious-secure.

### OT extensions

`IKNP`, `SoftSpoken<k>`, and `Ferret` all derive from
`RandomCOT`, take the same constructor shape, and the same object
exposes all four flavors:

```cpp
IKNP ote(party, &io);
// SoftSpoken<2> ote(party, &io); Ferret ote(party, &io); ... all the same below.
block buf[length];

// rcot() is single-method and role-implicit — the instance's party
// determines whether it acts as sender or receiver internally.
// Each side fills its own `buf`; sender's buf[i] ^ receiver's buf[i] = c[i] · Δ.
ote.rcot(buf, length);

// COT / ROT / OT flavors are role-explicit (different signatures by side):
if (party == ALICE) {
    ote.send_cot(m0, length);                     // COT:  fills m0; m1[i] = m0[i]^Δ
    ote.send_rot(m0, m1, length);                 // ROT:  fills m0, m1 (random)
    ote.send(m0, m1, length);                     // OT:   sends caller-chosen m0, m1
} else {
    ote.recv_cot(mc, c, length);                  // COT:  mc[i] = m0[i] ^ c[i]*Δ
    ote.recv_rot(mc, c, length);                  // ROT:  mc[i] = c[i] ? m1[i] : m0[i]
    ote.recv(mc, c, length);                      // OT:   mc[i] = c[i] ? m1[i] : m0[i]
}
```

The constructor allocates per-instance state and (on the sender side)
samples a random `Δ` with `LSB(Δ) = 1` pinned. No network I/O runs in
the ctor. The base-OT bootstrap runs on the first `begin()` (or the
first `rcot()` one-shot call, which delegates to `run()` → `begin()`
internally).

`Δ` is readable as `ote.Delta` immediately after construction. The
receiver has no `Δ`. To override the ctor-sampled `Δ` (e.g. when an
outer protocol like
[`emp-zk`](https://github.com/emp-toolkit/emp-zk) or
[`emp-sh2pc`](https://github.com/emp-toolkit/emp-sh2pc) supplies its
own correlation), call `set_delta` before the first `rcot()` call:

```cpp
IKNP ote(party, &io);
if (party == ALICE) {
    bool delta_bool[128]; /* fill from outer protocol; delta_bool[0] = true */
    ote.set_delta(delta_bool);
}
// ote.rcot(buf, length); // bootstrap fires here, on first streaming begin
```

`set_delta` must fire before the first `rcot/begin/run` call (asserts
otherwise).

Each extension can be parameterized to bootstrap from a non-default
base OT (default is `CSW`); pair an extension's malicious mode with
a malicious-secure base — `IKNP` / `SoftSpoken` / `Ferret` check
this at construction time and abort otherwise.

```cpp
IKNP            ote1(party, &io, /*malicious=*/true,
                     std::make_unique<CSW>(&io));
SoftSpoken<4>   ote2(party, &io, /*malicious=*/true,
                     std::make_unique<CSW>(&io));      // k=4
Ferret          ote3(party, &io, /*malicious=*/true,
                     ferret_b13,
                     std::make_unique<CSW>(&io));
```

### Streaming RCOT

The `OTExtension` base also exposes a streaming API for callers that
want to overlap RCOT production with downstream work (one fixed
`chunk_size()`-sized batch per `next()` call, no internal buffering):

```cpp
const int64_t chunk = ote.chunk_size();
BlockVec buf(chunk);

ote.begin();
for (int i = 0; i < n_chunks; ++i) {
    ote.next(buf.data());
    consume_chunk(buf.data(), chunk);  // role implicit in party
}
ote.end();
```

The one-shot `rcot(data, num)` is implemented in terms of this
streaming API plus a small leftover buffer for tails that aren't a
multiple of `chunk_size()`.

For callers that consume the stream **incrementally** — even one COT at
a time — draw from a single long-lived session with `next_n(dst, n)`
instead of calling `rcot` repeatedly:

```cpp
ote.begin();                       // open one session (e.g. in your ctor)
ote.next_n(&one, 1);               // draw any count; refills a chunk internally
ote.next_n(batch.data(), k);       // …amortizes the per-round end-work
ote.end();                         // close it (e.g. in your dtor)
```

This matters because `rcot(data, num)` opens and closes a session per
call, so the per-round end-work (refill trees + the malicious chi-fold
check) is paid every `chunk_size()` COTs. `next_n` keeps one session
open, amortizing that over the whole stream — e.g. emp-zk's per-AND-gate
COT draw is ~20× faster this way than calling `rcot(_, 1)` in a loop.
`next_n` is mutually exclusive with `run()`/`rcot()` on the same
instance (both touch the same leftover buffer).

## Performance

Two AWS `m8a.xlarge` (AMD EPYC, Zen 5, 4 vCPU each), us-east-1 same AZ,
Ubuntu 22.04, GCC 11.4, OpenSSL 3.0.2, `-march=native`. **The two parties
run on separate instances over the AWS private network** (~0.4 ms RTT) —
real inter-instance TCP, not loopback. Each party therefore gets a full
4-vCPU box, and the network is in the measured path.

### Base OTs

One batch of 128 base OTs (slower party's wall-clock, median of 3 runs;
send/recv bytes are deterministic).

| Protocol     | Time   |  Send B |  Recv B | Security                                     |
|--------------|-------:|--------:|--------:|----------------------------------------------|
| `CO`       |  12 ms |   4,165 |   8,832 | semi-honest                                  |
| `CSW`      | 9.6 ms |   6,229 |   8,864 | malicious-secure (CDH + RO)                  |
| `PVW`      |  40 ms |  39,424 |  17,664 | malicious-secure (DDH messy mode)            |
| `PVWKyber` | 9.9 ms | 200,704 |  98,304 | malicious-secure, post-quantum (ML-KEM-512)  |

### OT extensions (RCOT throughput)

Length 2²⁵ OTs (~33M), each party on its own instance over the private
network, **single-threaded** (one thread per party — `SilentFerret`'s
`begin()` expansion pool is disabled so every protocol is measured the same
way). `MOT/s` is the median of 5 runs, the slower of the two parties per run;
`bits/RCOT` (total wire bytes, both directions — deterministic) includes the
one-time base-OT bootstrap amortised over the length. With a
real network in the path the comm-heavy extensions become **bandwidth-bound**
(so `IKNP` semi and malicious collapse to the same rate) while `Ferret`'s
tiny footprint stays **compute-bound** — hence the wide MOT/s spread.

| Protocol         | Mode      | bits/RCOT | MOT/s |
|------------------|-----------|----------:|------:|
| `IKNP`           | semi      |       127 |    39 |
| `IKNP`           | malicious |       127 |    39 |
| `SoftSpoken<2>`  | semi      |        63 |    77 |
| `SoftSpoken<2>`  | malicious |        63 |    77 |
| `SoftSpoken<4>`  | semi      |        31 |   153 |
| `SoftSpoken<4>`  | malicious |        31 |   153 |
| `SoftSpoken<8>`  | semi      |        15 |    67 |
| `SoftSpoken<8>`  | malicious |        15 |    66 |
| `Ferret`         | semi      |      0.27 |   111 |
| `Ferret`         | malicious |      0.27 |   101 |
| `SilentFerret`   | semi      |      0.34 |    88 |
| `SilentFerret`   | malicious |      0.34 |    75 |

`IKNP` and `SoftSpoken<k>` traffic is one-direction: 127 bits/RCOT
for `IKNP`, `128/k − 1` bits/RCOT for `SoftSpoken<k>`. `Ferret`'s
0.27 bits/RCOT at 2²⁵ is ~0.20 bits/RCOT of steady-state per-round
MPCOT/LPN traffic plus ~0.07 bits/RCOT of one-time bootstrap; the
bootstrap fraction shrinks linearly with bench length. `SilentFerret`
keeps the same sub-bit footprint (0.34 bits/RCOT — a touch more on the
receiver side, since it prepays every round's corrections up front in
`begin()`); it trades a little throughput for moving all wire traffic
to `begin()`, leaving `next()` completely wire-free.

`COT`, `ROT`, `OT` flavors layer one MITCCRH pass (and, for
chosen-input `OT`, one block per OT on the wire) on top of `RCOT`.

## [Acknowledgement, Reference, and Questions](https://github.com/emp-toolkit/emp-readme/blob/master/README.md#citation)

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
