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
>   then `1.0.0`. New SoftSpokenOT kernels (NEON butterfly on Apple M,
>   View B AVX-512 on Intel Sapphire Rapids+), reorganized base OTs,
>   restructured benches, and the wire-equivalence framework from
>   emp-tool 1.0 — but the API is not yet frozen and headers may move
>   between alphas. Requires emp-tool ≥ 1.0.0-alpha.

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
- OpenSSL ≥ 3.3 (the OTPVWKyber base OT uses `EVP_DigestSqueeze` for
  SHAKE; Ubuntu 22.04 ships 3.0.2, so build OpenSSL 3.3+ from source
  there)
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
```

### Standard OT (1-out-of-2)

```cpp
NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

block b0[length], b1[length];
bool  c[length];

OTCO co(&io);
if (party == ALICE) co.send(b0, b1, length);   // sender supplies both messages
else                co.recv(b0, c, length);    // receiver gets b_{c[i]}
```

`OTCO` can be replaced by `OTPVW`, `OTCSW`, `OTPVWKyber`, `IKNP`,
`SoftSpokenOT`, or `FerretCOT` and the `send`/`recv` calls stay
identical — they all implement the [`OT`](emp-ot/ot.h) interface.
Their constructors differ; in particular `FerretCOT` takes
`(party, threads, ios[], malicious, run_setup, param, pre_file)` rather
than just `(io)`.

### Correlated OT and Random OT (IKNP, FerretCOT)

```cpp
IKNP ote(&io, /*malicious=*/false);

// COT: ote.Delta is the correlation
if (party == ALICE) ote.send_cot(b0, length);
else                ote.recv_cot(br, c, length);    // br[i] = b0[i] ^ c[i]*Delta

// ROT: random outputs, no correlation visible to receiver
if (party == ALICE) ote.send_rot(b0, b1, length);
else                ote.recv_rot(br, c, length);    // br[i] = c[i] ? b1[i] : b0[i]
```

### Ferret OT (silent random correlated OT)

Ferret produces correlated OT with random choice bits — i.e. RCOT.
[`ferret_cot.h`](emp-ot/ferret/ferret_cot.h) exposes two interfaces:
`rcot()` fills an external buffer of any length (one extra memcpy);
`rcot_inplace()` writes directly into a caller-provided buffer of a
specific size (no memcpy, but the size is fixed per call —
`byte_memory_need_inplace(n)` returns the right size).

The receiver's choice bit is embedded in the LSB of the returned `block`,
and `Delta`'s LSB is set to 1 to keep the correlation valid across all
bits — see the point-and-permute discussion in
[`ferret_cot.cpp`](emp-ot/ferret/ferret_cot.cpp).

```cpp
IOChannel* ios[1] = { &io };
FerretCOT ferretcot(party, /*threads=*/1, ios);
if (party == ALICE) ferretcot.rcot_send(b0, length);   // ferretcot.Delta
else                ferretcot.rcot_recv(br, length);   // br[i] = b0[i] ^ LSB(br[i])*Delta
```

## Performance

Numbers from AWS `c8a.2xlarge` (AMD EPYC 9R45, Zen 5c), single-thread,
both parties on localhost. Network is not a bottleneck — these are
compute-bound numbers (`bench_base_ot` and `bench_ot_extension`). Run
against `main` at commit `76226bb`, OpenSSL 3.3.2.

### Base OTs

Time and total wire bytes for one batch of 128 base OTs. Time is the
wall-clock duration on Alice's side.

| Protocol     | Time   |  Send B |  Recv B | Security                                     |
|--------------|-------:|--------:|--------:|----------------------------------------------|
| `OTCO`       | 5.6 ms |   4,165 |   8,832 | semi-honest                                  |
| `OTCSW`      | 9.2 ms |   6,229 |   8,864 | malicious-secure (CDH + RO)                  |
| `OTPVW`      |  39 ms |  39,424 |  17,664 | malicious-secure (DDH messy mode)            |
| `OTPVWKyber` | 7.7 ms | 200,704 |  98,304 | malicious-secure, post-quantum (ML-KEM-512)  |

The three OT extensions (`IKNP`, `SoftSpokenOT`, `FerretCOT`) accept
any of these via the optional `std::unique_ptr<OT> base_ot` constructor
arg; they default to `OTPVW`. Pair an extension's malicious mode with
a malicious-secure base — a runtime check fires otherwise.

### OT extensions

Length ≈ 2²⁴ OTs (~16M), single-thread. MOT/s = million OTs per
second; rows show the average of two role-flipped runs (the throughput
is approximately symmetric, ±5%). The `bits/OT` column is the total
wire footprint per RCOT output (send + receive, divided by length).

| Protocol         | Mode      | bits/OT | RCOT | COT | ROT | OT  |
|------------------|-----------|--------:|-----:|----:|----:|----:|
| `IKNP`           | semi      |     127 |   92 |  95 |  49 |  44 |
| `IKNP`           | malicious |     127 |   38 |  38 |  28 |  26 |
| `SoftSpoken<2>`  | semi      |      63 |  112 | 117 |  54 |  48 |
| `SoftSpoken<2>`  | malicious |      63 |   76 |  77 |  44 |  39 |
| `SoftSpoken<4>`  | semi      |      31 |   92 |  93 |  48 |  44 |
| `SoftSpoken<4>`  | malicious |      31 |   75 |  76 |  43 |  40 |
| `SoftSpoken<8>`  | semi      |      15 |   35 |  36 |  26 |  25 |
| `SoftSpoken<8>`  | malicious |      15 |   33 |  34 |  25 |  24 |
| `FerretCOT`      | semi      |    0.27 |   39 |  39 |  27 |  35 |
| `FerretCOT`      | malicious |    0.27 |   35 |  35 |  25 |  33 |

`RCOT` = random correlated OT (raw extension output); `COT` = chosen-
correlation; `ROT` = random OT; `OT` = chosen-input. `SoftSpoken<k>`
trades wire bytes for compute as `k` grows: at high bandwidth `k=2`
wins; on bandwidth-constrained links larger `k` amortises more
compute per byte.

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
