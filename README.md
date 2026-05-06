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
two base OTs (Naor-Pinkas, Chou-Orlandi), IKNP OT extension (semi-honest +
malicious), and Ferret silent COT extension. All hash functions used for OT are
instantiated with [MITCCRH](https://github.com/emp-toolkit/emp-tool/blob/master/emp-tool/crypto/mitccrh.h)
for optimal concrete security.

## Requirements

- CMake ≥ 3.21
- A C++17 compiler (Clang ≥ 12, GCC ≥ 9, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- pthreads

emp-ot is header-only; the only thing it builds is its tests.

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

The two end-to-end tests (`ot`, `ferret`) launch ALICE/BOB on localhost via
the `run` script. `bench_lpn` is a single-process benchmark of the LPN
encoding kernel.

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

OTNP<NetIO> np(&io);
if (party == ALICE) np.send(b0, b1, length);   // sender supplies both messages
else                np.recv(b0, c, length);    // receiver gets b_{c[i]}
```

`OTNP` can be replaced by `OTCO`, `IKNP`, or `FerretCOT` and the
`send`/`recv` calls stay identical — they all implement the [`OT<IO>`](emp-ot/ot.h)
interface. Their constructors differ; in particular `FerretCOT` takes
`(party, threads, ios[], malicious, run_setup, param, pre_file)` rather
than just `(io)`.

### Correlated OT and Random OT (IKNP, FerretCOT)

```cpp
IKNP<NetIO> ote(&io, /*malicious=*/false);

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
[`ferret_cot.hpp`](emp-ot/ferret/ferret_cot.hpp).

```cpp
FerretCOT<NetIO> ferretcot(party, /*threads=*/1, &io);
if (party == ALICE) ferretcot.rcot_send(b0, length);   // ferretcot.Delta
else                ferretcot.rcot_recv(br, length);   // br[i] = b0[i] ^ LSB(br[i])*Delta
```

## Performance

Numbers below are from c5.4xlarge AWS instances. They predate the
emp-tool 1.0 modernization (VAES / VPCLMULQDQ-256 dispatch, faster
PRG/Hash kernels) and should be re-measured on current CPUs; the
relative shapes (semi-honest vs malicious, single- vs multi-thread) are
representative.

### IKNP

```
50 Mbps
128 NPOTs:        12577 us
Passive IKNP OT   129262 OTps        Passive IKNP COT  388316 OTps
Passive IKNP ROT  386190 OTps
128 COOTs:        11073 us
Active IKNP OT    129152 OTps        Active IKNP COT   387380 OTps
Active IKNP ROT   385235 OTps

10 Gbps
128 NPOTs:        11739 us
Passive IKNP OT   1.55e7 OTps        Passive IKNP COT  2.97e7 OTps
Passive IKNP ROT  1.66e7 OTps
128 COOTs:        20064 us
Active IKNP OT    1.40e7 OTps        Active IKNP COT   2.43e7 OTps
Active IKNP ROT   1.47e7 OTps
```

### Ferret (million RCOT/s)

| Threads | Semi-honest 10/30/50 Mbps | Malicious 10/30/50 Mbps |
|---|---|---|
| 1 | 12.1 / 16.0 / 16.0 | 11.6 / 13.9 / 13.9 |
| 2 | 16.3 / 27.0 / 30.8 | 16.0 / 26.6 / 27.1 |
| 3 | 18.3 / 34.2 / 40.7 | 18.3 / 33.8 / 40.0 |
| 4 | 19.7 / 39.5 / 48.8 | 19.6 / 38.3 / 47.4 |
| 5 | 20.5 / 43.2 / 55.0 | 20.4 / 42.4 / 53.7 |
| 6 | 21.4 / 47.1 / 61.2 | 21.3 / 46.5 / 59.8 |

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
