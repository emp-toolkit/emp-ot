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
>   VAES-256 / AES-NI / NEON), post-quantum `BMM` base OT,
>   reorganized base OTs and extensions, the wire-equivalence framework
>   from emp-tool 1.0 — but the API is not yet frozen and headers may
>   move between alphas. Requires emp-tool ≥ 1.0.0-alpha.

State-of-the-art OT implementations on top of [emp-tool](https://github.com/emp-toolkit/emp-tool):
four base OTs (`CO`, `PVW`, `CSW`, `BMM`), IKNP and
SoftSpoken OT extensions (semi-honest + malicious), the Ferret and
SilentFerret silent COT extensions, and the `F2kVOLE` / `FpVOLE`
subfield-VOLE generators built on top of Ferret. All hash functions
used for OT are instantiated with
[MITCCRH](https://github.com/emp-toolkit/emp-tool/blob/main/emp-tool/crypto/mitccrh.h)
for optimal concrete security.

## Requirements

- CMake ≥ 3.25 (emp-tool's floor; emp-ot alone configures with ≥ 3.21)
- A C++20 compiler (GCC ≥ 11, Clang ≥ 14, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- OpenSSL ≥ 3.0. `BMM`'s ML-KEM SHAKE shim uses `EVP_DigestSqueeze` on
  ≥ 3.3 (one-shot squeeze) and falls back to a re-init / re-absorb
  loop on 3.0.x — same answers, slightly slower CRS expansion. No
  build-time configuration needed; the version is detected from
  `OPENSSL_VERSION_NUMBER`.
- pthreads

emp-ot builds a small static library (`emp-ot::emp-ot`) that compiles
the IKNP, SoftSpoken, Ferret, and SilentFerret bodies plus the
post-quantum `BMM` base OT (with its vendored ML-KEM/Kyber sources);
the header-only base OTs (`CO`, `PVW`, `CSW`) and the sVOLE layer are
consumed inline.

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

Omitting `-DCMAKE_BUILD_TYPE` defaults to `Release`.

Release builds self-tune: the first top-level Release build runs a
one-time sweep of machine-local scheduling knobs (AES tile widths, LPN
batching — never anything protocol- or security-relevant) and compiles
with the winners; every later build reuses the recorded result
(`emp-ot/tuning_local.h`, gitignored, provenance-stamped) and is
deterministic. Tuning changes neither outputs nor wire bytes (enforced
by `test_tuning_invariance` and the trace-hash baseline below), so
differently-tuned parties interoperate freely. `-DEMP_OT_AUTO_TUNE=OFF`
prevents a new automatic sweep, but an existing `tuning_local.h` still
applies. To use the swept cross-platform defaults, configure with that
option and run `tune-clean` to discard the header. The `tune` target
forces a re-sweep. Design and methodology:
[`docs/performance-tuning.md`](docs/performance-tuning.md).

### CMake options

| Option | Default | Effect |
|---|---|---|
| `EMP_OT_BUILD_TESTS` | `ON` when top-level | Build the test suite under `test/`. |
| `EMP_OT_INSTALL`     | `ON` when top-level | Generate install + export rules. |
| `EMP_OT_AUTO_TUNE`   | `ON` for top-level native Release | One-time per-machine tuning sweep before the first build (see above). |

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

The two-party benches (`bench_base_ot`, `bench_iknp`,
`bench_softspoken`, `bench_ferret`, `bench_silentferret`,
`bench_ot_extension`, `bench_f2k_vole`, `bench_fp_vole`) launch
ALICE/BOB on localhost via the `run` script. `bench_lpn` and
`bench_cggm` are single-process benchmarks of internal kernels.

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
$ EMP_TEST_MODE=1 ./run ./build/trace_hash | grep 'send='
```

### Profiling the SoftSpoken pipeline (off by default)

The SoftSpoken chunk pipeline has optional per-phase wall-clock timers
(butterfly / io / derand / transpose / combine; per role — derand
exists only on the OT-sender side, so the receiver line reports it as
zero). They are **disabled by default** — a normal build compiles them
to nothing and carries no timing code. To enable, build into a separate
tree with the flag and run any SoftSpoken driver; a ns/OT breakdown
prints to stderr at every session end:

```bash
cmake -S . -B build-phases -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS=-DEMP_BENCH_PHASES
cmake --build build-phases -j
./run ./build-phases/bench_softspoken 24
# stderr: [phases send] ots=...  butterfly=... io=... derand=... transpose=... combine=...  (ns/OT; sum=...)
```

The instrumented build is wire-identical to the default build (pinned
by the trace-hash baseline above); only stderr output differs. See
`emp-ot/ot_extension/softspoken/ss_bench_phases.h`.

**Current baseline** (ALICE's view; first 16 hex of each direction's
SHA-256). A change to any of these hashes means the corresponding
protocol's wire format changed — fine if intentional, but flag it
clearly in the commit message and update this table. (The fingerprints
are Fiat–Shamir transcript digests under the build's FS hash; this
table assumes the default `sha256` — a stack built with emp-tool's
`EMP_FS_HASH=blake3` produces a different, internally consistent set.)

`Ferret(b11)` and `SilentFerret(b11)` are run over a whole number of
SilentFerret rounds, where the two are **wire-identical by design**
(SilentFerret only changes *when* the correction traffic is sent, not
the bytes). Their rows must stay equal in both modes; a divergence
means a refactor broke the equivalence, not just one protocol's format.

```
CO                     send=d698630b93938c23 recv=d9c1fafc2be169a6
CSW                    send=0c2796685cfc7b91 recv=51c6e689429102d6
PVW                    send=49680c637b810195 recv=c5631a7f473a0998
BMM                    send=1a153c6ad131ea0b recv=504bcea7a11ee9bf
IKNP semi              send=ac441b93d05b591e recv=c861d33efcc306b2
SoftSpoken<2> semi     send=c09818e2edddfcd6 recv=53f9e440f7df41f1
SoftSpoken<8> semi     send=c09818e2edddfcd6 recv=6bda77ca7c0f9037
Ferret(b11) semi       send=1f2d87e222bc509a recv=31f4d61323bea622
SilentFerret(b11) semi send=1f2d87e222bc509a recv=31f4d61323bea622
F2kVOLE semi           send=b3f5ce46fb1ab13d recv=0a7d75d69804b3ca
FpVOLE semi            send=5bdf7f4cab96398a recv=30fa025221220ae8
IKNP mali              send=ac441b93d05b591e recv=98125593b26d3b02
SoftSpoken<2> mali     send=c09818e2edddfcd6 recv=a549bba02e32f2a1
SoftSpoken<8> mali     send=c09818e2edddfcd6 recv=b8690d0258534cc0
Ferret(b11) mali       send=8f7e58077aa1d35f recv=74b34e5043665231
SilentFerret(b11) mali send=8f7e58077aa1d35f recv=74b34e5043665231
F2kVOLE mali           send=639b25364bcf3e8d recv=881af7fc8a3ad07c
FpVOLE mali            send=efdc33076a565743 recv=dc3bd67a79aeeeae
```

## Usage

```cpp
#include <emp-tool/emp-tool.h>     // NetIO etc.
#include <emp-ot/emp-ot.h>         // OTs
using namespace emp;

int party = parse_party(argv);   // argv[1]; port/IP come from $EMP_PORT / $EMP_PEER_IP
auto io = (party == ALICE) ? NetIO::listen(peer_port())
                           : NetIO::connect(peer_ip(), peer_port());
```

### Interfaces

All OTs in emp-ot derive from a four-layer hierarchy in
[`emp-ot/ot.h`](emp-ot/ot.h) and
[`emp-ot/ot_extension/ot_extension.h`](emp-ot/ot_extension/ot_extension.h).
Each layer adds methods on top of the previous one; you can always
call a lower-level method on a higher-level object. See
[`docs/class-organization.md`](docs/class-organization.md) for the
full class layout.

| Interface                 | New methods                                       | Semantics added                                                                 |
|---------------------------|---------------------------------------------------|---------------------------------------------------------------------------------|
| `OT`                      | `send(m0, m1, n)` / `recv(mc, c, n)`              | chosen-input 1-out-of-2: sender supplies both messages, receiver picks one      |
| `COT : OT`                | `send_cot(m0, n)` / `recv_cot(mc, c, n)`; free `send_rot`/`recv_rot` | chosen-correlation: sender's two messages always differ by a public `Delta` |
| `RandomCOT : COT`         | `rcot(data, n)` (role implicit in instance party) | random correlation: no choice-bit input; receiver's choice ends up in `getLSB(data[i])`, and `Delta`'s LSB is forced to 1 so the correlation survives that one bit |
| `OTExtension : RandomCOT` | `set_delta(const bool* delta_bool)` (sender-only Δ override), `chunk_size()`, `begin/next/end`, `next_n(data, n)`, `run(data, num)` | streaming RCOT (one fixed-size chunk per `next`); base-OT bootstrap fires lazily on the first `begin` |

Concrete classes attach as follows:

- **Base OTs** (`OT` only): `CO`, `PVW`, `CSW`, `BMM`.
- **OT extensions** (`OTExtension`, so all of the above): `IKNP`,
  `SoftSpoken<k>`, `Ferret`.

The chosen-input / chosen-correlation / random conversions are
implemented once in the base classes (one MITCCRH pass per OT for the
chosen-message wrapper, one bit per OT for the random → chosen
correction), so picking a backend never forces you to also pick a
flavor.

### Base OTs

The four base OTs (`CO`, `PVW`, `CSW`, `BMM`) implement
only the `OT` interface — chosen-input 1-out-of-2.

```cpp
block m0[length], m1[length];   // sender's two messages
block mc[length];               // receiver's chosen message
bool  c [length];               // receiver's choice bits

PVW ot(io.get());
if (party == ALICE) ot.send(m0, m1, length);
else                ot.recv(mc, c, length);    // mc[i] = m_{c[i]}
```

All four implement the same `OT` interface. `CO` is semi-honest;
`CSW`, `PVW`, `BMM` are malicious-secure.

### OT extensions

`IKNP`, `SoftSpoken<k>`, and `Ferret` all derive from
`RandomCOT`, take the same constructor shape, and the same object
exposes all four flavors:

```cpp
IKNP ote(party, io.get());
// SoftSpoken<2> ote(party, io.get()); Ferret ote(party, io.get()); ... all the same below.
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
IKNP ote(party, io.get());
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
IKNP            ote1(party, io.get(), /*malicious=*/true,
                     std::make_unique<CSW>(io.get()));
SoftSpoken<4>   ote2(party, io.get(), /*malicious=*/true,
                     std::make_unique<CSW>(io.get()));      // k=4
Ferret          ote3(party, io.get(), /*malicious=*/true,
                     tuning::ferret_b13,
                     std::make_unique<CSW>(io.get()));
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

In malicious mode, ordinary streaming output is provisional until
`end()` completes the session's consistency checks. Do not expose it or
make irreversible decisions from it before `end()` succeeds; the one-shot
`rcot()` path performs that check before returning, and `SilentFerret`
front-loads its checks into `begin(n_ots)`.

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
open, amortizing that over the whole stream. In a malicious b13 Ferret
benchmark matching emp-zk's one-COT-per-AND-gate consumption shape,
1,048,576 calls were 36.9× faster (slower-party median of 5) and used
45.2× less wire this way than with `rcot(_, 1)` in a loop.
`next_n` is mutually exclusive with `run()`/`rcot()` on the same
instance (both touch the same leftover buffer).

See [`docs/streaming-api.md`](docs/streaming-api.md) for the full
lifecycle contract.

### SilentFerret

`SilentFerret` is a drop-in `Ferret` subclass that can **front-load** all of
its wire traffic. Where `Ferret` interleaves the MPCOT/LPN correction
messages (and, in malicious mode, the chi-fold check) with production,
`SilentFerret::begin(n_ots)` concentrates every byte — and every malicious
check — into the initial call, leaving `next()` / `next_n()` **completely
wire-free** for both roles. The cGGM correction stream is identical to
Ferret's. The no-argument path prepays one round at a time and, over whole
rounds, remains byte-identical overall, as pinned by the `trace_hash`
baseline above. For a multi-round malicious `begin(n_ots)`, SilentFerret
folds the per-round consistency checks into one batch check, so its total
transcript is slightly smaller even though the corrections are unchanged.

Prepay a known number of COTs up front, then draw them with no communication
during the online phase:

```cpp
SilentFerret ote(party, io.get(), /*malicious=*/true);  // default param; n_threads = 1
ote.begin(n_ots);                  // ALL correction traffic + checks happen here
BlockVec buf(ote.chunk_size());
for (int i = 0; i < n_chunks; ++i)
    ote.next(buf.data());          // wire-free: no bytes either way
ote.end();
```

The no-arg `begin()` prepays a single round (`K = 1`); rollover past it is
live. The constructor's last argument `n_threads` sizes the `begin()`-time
expansion pool (`<= 1` runs serially), parallelizing the bursty setup. The
trade is a heavier, bursty `begin()` for a silent online phase — useful when
the interactive section of a protocol should move no OT bytes.

## Performance

Two AWS `m8a.8xlarge` (AMD EPYC 9R45, Zen 5) in a cluster placement
group, us-east-1, Ubuntu 22.04, GCC 11.4, OpenSSL 3.0.2,
`-march=native`. The two parties run on separate instances over the
AWS private network; the link measured 9.50–9.53 Gbps single-flow /
0.10–0.11 ms RTT (iperf3 and ping archived with the results). Release
build with one final-source auto-tuner result frozen across both hosts;
bench output buffers are pre-faulted.

### Base OTs

One batch of 128 base OTs (slower party's wall-clock, median of 3 runs;
send/recv bytes are deterministic).

| Protocol     | Time   |  Send B |  Recv B | Security                                     |
|--------------|-------:|--------:|--------:|----------------------------------------------|
| `CO`       |  10 ms |   4,165 |   8,832 | semi-honest                                  |
| `CSW`      | 9.4 ms |   6,229 |   8,864 | malicious-secure (CDH + RO)                  |
| `PVW`      |  40 ms |  39,424 |  17,664 | malicious-secure (DDH messy mode)            |
| `BMM`      |  11 ms | 200,704 | 106,496 | malicious-secure, post-quantum (ML-KEM-512)  |

### OT extensions (RCOT throughput)

Length 30,015,488 OTs (exactly two b13 rounds; ~30M), single-threaded
(one thread per party; `SilentFerret`'s `begin()` expansion pool
disabled). `MOT/s` is the median of 9 runs, the slower of the two
parties per run; `bits/RCOT`
(total wire bytes, both directions — deterministic) includes the
one-time base-OT bootstrap amortised over the length. Observed: the
`IKNP` and `SoftSpoken<2>` rows, plus semi-honest `SoftSpoken<4>`, ran
at 91–98% of the measured link rate; the remaining rows were CPU-bound.
Analysis of what binds each configuration is in
[`docs/performance-tuning.md`](docs/performance-tuning.md).

| Protocol         | Mode      | bits/RCOT | MOT/s |
|------------------|-----------|----------:|------:|
| `IKNP`           | semi      |       127 |    73 |
| `IKNP`           | malicious |       127 |    73 |
| `SoftSpoken<2>`  | semi      |        63 |   144 |
| `SoftSpoken<2>`  | malicious |        63 |   137 |
| `SoftSpoken<4>`  | semi      |        31 |   280 |
| `SoftSpoken<4>`  | malicious |        31 |   195 |
| `SoftSpoken<8>`  | semi      |        15 |    75 |
| `SoftSpoken<8>`  | malicious |        15 |    70 |
| `Ferret`         | semi      |      0.28 |   124 |
| `Ferret`         | malicious |      0.28 |   111 |
| `SilentFerret`   | semi      |      0.28 |   116 |
| `SilentFerret`   | malicious |      0.28 |   103 |

`IKNP` and `SoftSpoken<k>` traffic is one-direction (127 and
`128/k − 1` bits/RCOT). The `Ferret` and `SilentFerret` rows use the
default `ferret_b13` parameter set and are measured over two complete
rounds. Their correction traffic is identical, and their semi-honest
total traffic matches exactly. Malicious SilentFerret batches the two
per-round checks into one, saving 48 bytes total (about 0.000013
bits/RCOT), so both still round to 0.28 bits/RCOT. The no-argument,
one-round-at-a-time wire equivalence remains pinned by the trace table
above. `ferret_b11` measured 124 MOT/s at 0.81 bits/RCOT on the same
setup. The measured `SilentFerret` rows' `next()` calls are wire-free
(all traffic is in `begin(n_ots)`).

`COT`, `ROT`, `OT` flavors layer one MITCCRH pass (and, for
chosen-input `OT`, one block per OT on the wire) on top of `RCOT`.

## [Acknowledgement, Reference, and Questions](https://github.com/emp-toolkit/emp-readme/blob/master/README.md#citation)

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
