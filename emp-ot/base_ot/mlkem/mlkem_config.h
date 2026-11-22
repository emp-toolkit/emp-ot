/*
 * mlkem-native configuration for BMM's ML-KEM (selected with MLK_CONFIG_FILE
 * for mlkem{512,768,1024}.c and for the vendored mlkem_native_asm.S).
 * It sets what differs from the vendored default configuration and includes
 * that default for everything else.
 *
 * The three parameter sets are one multi-level build, mlkem-native's own
 * layout for several levels in one program: each level file sets
 * MLK_CONFIG_PARAMETER_SET, the 512 file also compiles the level-independent
 * code (MLK_CONFIG_MULTILEVEL_WITH_SHARED) and the others leave it out
 * (MLK_CONFIG_MULTILEVEL_NO_SHARED). The levels share that code across
 * files, so mlkem-native's functions are not file-static; they are global
 * symbols under this private prefix.
 */
#ifndef EMP_OT_MLKEM_CONFIG_H
#define EMP_OT_MLKEM_CONFIG_H

#define MLK_CONFIG_MULTILEVEL_BUILD

/* Every symbol carries this prefix, so another copy of mlkem-native in the
 * same program cannot collide with this one. */
#define MLK_CONFIG_NAMESPACE_PREFIX EMP_OT_MLKEM

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
