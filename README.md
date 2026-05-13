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
>   then `1.0.0`. New SoftSpokenOT recursive-butterfly kernel (cross-
>   platform, NEON + VAES-256/512), post-quantum `OTPVWKyber` base OT,
>   reorganized base OTs and extensions, the wire-equivalence framework
>   from emp-tool 1.0 — but the API is not yet frozen and headers may
>   move between alphas. Requires emp-tool ≥ 1.0.0-alpha.

State-of-the-art OT implementations on top of [emp-tool](https://github.com/emp-toolkit/emp-tool):
four base OTs (`OTCO`, `OTPVW`, `OTCSW`, `OTPVWKyber`), IKNP and
SoftSpoken OT extensions (semi-honest + malicious), and Ferret silent
COT extension. All hash functions used for OT are instantiated with
[MITCCRH](https://github.com/emp-toolkit/emp-tool/blob/main/emp-tool/crypto/mitccrh.h)
for optimal concrete security.

> **Heads up — AI-assisted drafts, not yet audited.** The development
> branch adds `OTPVW`, `OTCSW`, `OTPVWKyber`, and `SoftSpokenOT` on
> top of the long-standing `OTCO` / `IKNP` / `FerretCOT` core. These
> were implemented largely through AI-assisted coding against their
> published specifications; the byte-equality and cross-protocol
> consistency tests pass end-to-end, but the careful line-by-line
> human review usually expected of cryptographic code hasn't happened
> yet — these should be treated more as research-grade drafts than
> vetted releases. Fine for prototyping and exploration; for
> production paths today, stick to `OTCO` with `IKNP` / `FerretCOT`,
> or pin to the
> [`v0.3.x`](https://github.com/emp-toolkit/emp-ot/tree/v0.3.x) branch.

## Requirements

- CMake ≥ 3.21
- A C++17 compiler (Clang ≥ 12, GCC ≥ 9, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- OpenSSL ≥ 3.0. `OTPVWKyber`'s SHAKE shim uses `EVP_DigestSqueeze` on
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
`trace_equiv`) launch ALICE/BOB on localhost via the `run` script. `bench_lpn`,
`bench_cggm`, `bench_sfvole_v2`, and `prof_sfvole_local` are single-
process benchmarks of internal kernels.

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
| `RandomCOT : COT`         | `rcot_send(m0, n)` / `rcot_recv(mc, n)`           | random correlation: no choice-bit input; receiver's choice ends up in `getLSB(mc[i])`, and `Delta`'s LSB is forced to 1 so the correlation survives that one bit |
| `OTExtension : RandomCOT` | `chunk_ots()`, `rcot_send_begin/_next/_end`, `rcot_recv_begin/_next/_end` | streaming RCOT: one fixed-size chunk per `_next`, no internal buffering         |

Concrete classes attach as follows:

- **Base OTs** (`OT` only): `OTCO`, `OTPVW`, `OTCSW`, `OTPVWKyber`.
- **OT extensions** (`OTExtension`, so all of the above): `IKNP`,
  `SoftSpokenOT<k>`, `FerretCOT`.

The chosen-input / chosen-correlation / random conversions are
implemented once in the base classes (one MITCCRH pass per OT for the
chosen-message wrapper, one bit per OT for the random → chosen
correction), so picking a backend never forces you to also pick a
flavor.

### Base OTs

The four base OTs (`OTCO`, `OTPVW`, `OTCSW`, `OTPVWKyber`) implement
only the `OT` interface — chosen-input 1-out-of-2.

```cpp
block m0[length], m1[length];   // sender's two messages
block mc[length];               // receiver's chosen message
bool  c [length];               // receiver's choice bits

OTPVW ot(&io);
if (party == ALICE) ot.send(m0, m1, length);
else                ot.recv(mc, c, length);    // mc[i] = m_{c[i]}
```

Any of the four are drop-in interchangeable here. `OTCO` is the
semi-honest fast path; the other three are malicious-secure (see the
[Performance](#performance) section for the cost difference).

### OT extensions

`IKNP`, `SoftSpokenOT<k>`, and `FerretCOT` all derive from
`RandomCOT`, so the same object exposes all four flavors:

```cpp
IKNP ote(&io, /*malicious=*/false);
// FerretCOT ote(party, &io); SoftSpokenOT<2> ote(&io); ... all the same below.

if (party == ALICE) {
    ote.rcot_send(m0, length);                    // RCOT: fills m0; m1[i] = m0[i]^Δ
    ote.send_cot(m0, length);                     // COT:  fills m0; m1[i] = m0[i]^Δ
    ote.send_rot(m0, m1, length);                 // ROT:  fills m0, m1 (random)
    ote.send(m0, m1, length);                     // OT:   sends caller-chosen m0, m1
} else {
    ote.rcot_recv(mc, length);                    // RCOT: mc[i]=m_{c[i]}, c[i]=LSB(mc[i])
    ote.recv_cot(mc, c, length);                  // COT:  mc[i] = m0[i] ^ c[i]*Δ
    ote.recv_rot(mc, c, length);                  // ROT:  mc[i] = c[i] ? m1[i] : m0[i]
    ote.recv(mc, c, length);                      // OT:   mc[i] = c[i] ? m1[i] : m0[i]
}
```

`Δ` is the sender-side correlation (`ote.Delta`). It's set by the
backend's setup phase — at construction for `FerretCOT` (when
`run_setup=true`, the default), on the first `*_send` call for `IKNP`
and `SoftSpokenOT`. The receiver has no `Δ`.

Each extension can be parameterized to bootstrap from a non-default
base OT (default is `OTPVW`); pair an extension's malicious mode with
a malicious-secure base — `IKNP` / `SoftSpokenOT` / `FerretCOT` check
this at runtime and abort otherwise.

```cpp
IKNP        ote1(&io, /*malicious=*/true, std::make_unique<OTCSW>(&io));
SoftSpokenOT<4> ote2(&io, std::make_unique<OTCSW>(&io));     // k=4
FerretCOT   ote3(party, &io, /*malicious=*/true,
                 /*run_setup=*/true, ferret_b13,
                 std::make_unique<OTCSW>(&io));
```

### Streaming RCOT

The `OTExtension` base also exposes a streaming API for callers that
want to overlap RCOT production with downstream work (one fixed
`chunk_ots()`-sized batch per `_next` call, no internal buffering):

```cpp
const int64_t chunk = ote.chunk_ots();
BlockVec buf(chunk);

if (party == ALICE) {
    ote.rcot_send_begin();
    for (int i = 0; i < n_chunks; ++i) {
        ote.rcot_send_next(buf.data());
        consume_sender_chunk(buf.data(), chunk);
    }
    ote.rcot_send_end();
} else {
    ote.rcot_recv_begin();
    for (int i = 0; i < n_chunks; ++i) {
        ote.rcot_recv_next(buf.data());
        consume_receiver_chunk(buf.data(), chunk);
    }
    ote.rcot_recv_end();
}
```

The one-shot `rcot_send` / `rcot_recv` wrappers are implemented in
terms of this streaming API plus a small leftover buffer for tails
that aren't a multiple of `chunk_ots()`.

## Performance

Numbers from AWS `c8a.2xlarge` (AMD EPYC 9R45, Zen 5, 8 vCPU), single-
thread, both parties on localhost. Network is not a bottleneck — these
are compute-bound numbers (`bench_base_ot` and `bench_ot_extension`).
Run against `main` at commit `dcbafff` (depends on `emp-tool` at
`6d3e9f2`), Ubuntu 22.04, GCC 11.4, OpenSSL 3.3.2, `-march=native`
(AVX-512 + VAES + VPCLMULQDQ + SHA-NI).

### Base OTs

Time and total wire bytes for one batch of 128 base OTs. Time is the
wall-clock duration on Alice's side.

| Protocol     | Time   |  Send B |  Recv B | Security                                     |
|--------------|-------:|--------:|--------:|----------------------------------------------|
| `OTCO`       |  18 ms |   4,165 |   8,832 | semi-honest                                  |
| `OTCSW`      | 9.2 ms |   6,229 |   8,864 | malicious-secure (CDH + RO)                  |
| `OTPVW`      |  39 ms |  39,424 |  17,664 | malicious-secure (DDH messy mode)            |
| `OTPVWKyber` | 8.0 ms | 200,704 |  98,304 | malicious-secure, post-quantum (ML-KEM-512)  |

The three OT extensions (`IKNP`, `SoftSpokenOT`, `FerretCOT`) accept
any of these via the optional `std::unique_ptr<OT> base_ot` constructor
arg; they default to `OTPVW`. Pair an extension's malicious mode with
a malicious-secure base — a runtime check fires otherwise.

### OT extensions

Length ≈ 2²⁴ OTs (~16M), single-thread. MOT/s = million OTs per
second; each cell is the mean of four measurements (Alice + Bob
across two role-flipped runs). For `COT`/`ROT`/`OT` rows, sender and
receiver MOT/s differ noticeably (the sender's `rcot_send` finishes
before the receiver's `rcot_recv` returns) — the mean smooths that
out. The `bits/RCOT` column is the total wire footprint per RCOT
output (send + receive, divided by length).

| Protocol         | Mode      | bits/RCOT | RCOT | COT | ROT | OT  |
|------------------|-----------|----------:|-----:|----:|----:|----:|
| `IKNP`           | semi      |       127 |  127 | 100 |  50 |  42 |
| `IKNP`           | malicious |       127 |   42 |  38 |  28 |  17 |
| `SoftSpoken<2>`  | semi      |        63 |  104 |  84 |  46 |  24 |
| `SoftSpoken<2>`  | malicious |        63 |   97 |  80 |  45 |  22 |
| `SoftSpoken<4>`  | semi      |        31 |  107 |  87 |  47 |  23 |
| `SoftSpoken<4>`  | malicious |        31 |  100 |  82 |  46 |  23 |
| `SoftSpoken<8>`  | semi      |        15 |   38 |  35 |  26 |  17 |
| `SoftSpoken<8>`  | malicious |        15 |   37 |  35 |  26 |  16 |
| `FerretCOT`      | semi      |      0.22 |   65 |  57 |  37 |  20 |
| `FerretCOT`      | malicious |      0.22 |   59 |  52 |  35 |  20 |

`RCOT` = random correlated OT (raw extension output); `COT` = chosen-
correlation; `ROT` = random OT; `OT` = chosen-input. `SoftSpoken<k>`
shrinks the per-RCOT wire as `k` grows (roughly `128/k - 1` bits) at
the cost of more AES work per RCOT.

## Citation

```bibtex
@misc{emp-toolkit,
   author = {Xiao Wang and Alex J. Malozemoff and Jonathan Katz},
   title = {{EMP-toolkit: Efficient MultiParty computation toolkit}},
   howpublished = {\url{https://github.com/emp-toolkit}},
   year={2016}
}
```

## Acknowledgement

This work was supported in part by the National Science Foundation under
Awards #1111599 and #1563722. The Ferret implementation is partially
based upon work supported by DARPA under Contract No. HR001120C0087. Any
opinions, findings and conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the
views of DARPA. The authors would also like to thank the support from
PlatON Network and Facebook. Ferret is also developed and maintained by
Chenkai Weng.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
