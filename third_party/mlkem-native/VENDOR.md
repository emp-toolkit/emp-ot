# Vendored mlkem-native

Upstream: https://github.com/pq-code-package/mlkem-native
Version:  v2.0.0
Commit:   d1b2fe782888bdb761a50336012923180be7f502
License:  Apache-2.0 OR ISC OR MIT; see `LICENSE`.

## Why it's here

The `BMM` post-quantum base OT (`emp-ot/base_ot/bmm.h`) is built on the
IND-CPA core of ML-KEM (FIPS 203 K-PKE), at all three parameter sets.
mlkem-native is the Post-Quantum Cryptography Alliance's implementation of
ML-KEM, a maintained fork of the pq-crystals Kyber reference code. Its C code
is formally verified for memory safety and type safety, and it carries
assembly backends for x86-64 (AVX2) and AArch64, including batched Keccak,
with a portable C fallback.

## What's included

The `mlkem/` directory of the release, unmodified: the C sources (`src/`),
the native backends (`src/native/`, `src/fips202/native/`), the
single-compilation-unit files `mlkem_native.c` and `mlkem_native_asm.S`, and
the default configuration `mlkem_native_config.h`. The repository's tests,
proofs, scripts and examples are not included.

## Build integration

The three levels are one multi-level build, mlkem-native's own layout for
several levels in one program. emp-ot compiles into `libemp-ot`:

- `emp-ot/base_ot/mlkem/mlkem512.c`, `mlkem768.c` and `mlkem1024.c`. Each
  sets its level and includes `mlkem_level.h`, which includes the vendored C
  sources, the same files in the same order as `mlkem_native.c`, and then
  defines the functions BMM calls at that level. The 512 file also compiles
  the level-independent code (`MLK_CONFIG_MULTILEVEL_WITH_SHARED`); the other
  two leave it out (`MLK_CONFIG_MULTILEVEL_NO_SHARED`). `mlkem_native.c`
  itself is not included, because it ends by undefining the internal names
  those functions use.
- `mlkem/mlkem_native_asm.S`, unmodified, built once with
  `MLK_CONFIG_MULTILEVEL_WITH_SHARED`, provides the assembly for all levels.

All are built with `MLK_CONFIG_FILE` pointing at
`emp-ot/base_ot/mlkem/mlkem_config.h`. That file sets the multi-level build, a
private symbol prefix and the native backends, and includes the vendored
default configuration for everything else. The levels share code across
files, so mlkem-native's functions are global symbols under that prefix.

The backend is chosen at compile time: AVX2 on x86-64 when the build targets
AVX2 (emp-tool's native build), AArch64 on arm64, and the C code otherwise.
`-DEMP_OT_MLKEM_PORTABLE=ON` builds the C code only, for comparing backends.

## Updating

Replace `mlkem/` and `LICENSE` with the new release's, refresh the version and
commit above, and compare the include list at the top of `mlkem_native.c` with
the one in `emp-ot/base_ot/mlkem/mlkem_level.h`. Check that the internal
functions `mlkem_level.h` calls still exist with the same meaning, including
the file-local `indcpa.c` helpers it reaches under their per-level names. The
wire-trace baseline (`test/trace_hash.baseline`) must not change, on every
backend.
