/*
 * mlkem-native configuration for BMM's ML-KEM-512 (selected with
 * MLK_CONFIG_FILE for mlkem512.c and for the vendored mlkem_native_asm.S).
 * It sets what differs from the vendored default configuration and includes
 * that default for everything else.
 */
#ifndef EMP_OT_MLKEM_CONFIG_H
#define EMP_OT_MLKEM_CONFIG_H

#define MLK_CONFIG_PARAMETER_SET 512

/* Every C function is static to mlkem512.c and every assembly symbol carries
 * this prefix, so another copy of mlkem-native in the same program cannot
 * collide with this one. */
#define MLK_CONFIG_NAMESPACE_PREFIX EMP_OT_MLKEM
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static

/* BMM runs only the deterministic internals, so no randombytes() is needed. */
#define MLK_CONFIG_NO_RANDOMIZED_API

/* Assembly backends where the target has one (AVX2 on an x86-64 build that
 * targets AVX2, AArch64), unless EMP_OT_MLKEM_PORTABLE asks for the C code. */
#if !defined(EMP_OT_MLKEM_PORTABLE)
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#endif

#include "mlkem/mlkem_native_config.h"

#endif /* EMP_OT_MLKEM_CONFIG_H */
