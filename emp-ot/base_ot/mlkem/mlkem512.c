/*
 * ML-KEM-512 for the BMM base OT, on the vendored mlkem-native
 * (third_party/mlkem-native, unmodified; see its VENDOR.md).
 *
 * This file compiles mlkem-native's C sources as one translation unit: the
 * same files in the same order as its mlkem_native.c, which cannot be
 * included itself because it ends by undefining the internal names used
 * below. The internal functions are static (mlkem_config.h); the assembly is
 * the vendored mlkem_native_asm.S, built with the same configuration.
 *
 * Encryption and decryption are mlkem-native's K-PKE functions, unchanged.
 * The receiver's key is K-PKE.KeyGen with the matrix seed rho supplied by
 * the caller: in BMM both parties derive rho from the session id and the OT
 * index, and the receiver must not be able to choose its own matrix.
 */
#if !defined(MLK_CONFIG_FILE)
#error "mlkem512.c must be built with MLK_CONFIG_FILE set (see CMakeLists.txt)"
#endif

#if defined(__GNUC__)
/* mlkem-native's KEM API is compiled in, static, and unused. */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

/* The include list of mlkem/mlkem_native.c. */
#include "mlkem/src/common.h"

#include "mlkem/src/compress.c"
#include "mlkem/src/debug.c"
#include "mlkem/src/indcpa.c"
#include "mlkem/src/kem.c"
#include "mlkem/src/poly.c"
#include "mlkem/src/poly_k.c"
#include "mlkem/src/sampling.c"
#include "mlkem/src/verify.c"

#if !defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER)
#include "mlkem/src/fips202/fips202.c"
#include "mlkem/src/fips202/fips202x4.c"
#include "mlkem/src/fips202/keccakf1600.c"
#endif

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH)
#if defined(MLK_SYS_AARCH64)
#include "mlkem/src/native/aarch64/src/aarch64_zetas.c"
#include "mlkem/src/native/aarch64/src/rej_uniform_table.c"
#endif
#if defined(MLK_SYS_X86_64)
#include "mlkem/src/native/x86_64/src/compress_consts.c"
#include "mlkem/src/native/x86_64/src/consts.c"
#include "mlkem/src/native/x86_64/src/rej_uniform_table.c"
#endif
#if defined(MLK_SYS_RISCV64)
#include "mlkem/src/native/riscv64/src/rv64v_debug.c"
#include "mlkem/src/native/riscv64/src/rv64v_poly.c"
#endif
#if defined(MLK_SYS_PPC64LE)
#include "mlkem/src/native/ppc64le/src/consts.c"
#endif
#endif /* MLK_CONFIG_USE_NATIVE_BACKEND_ARITH */

#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202)
#if defined(MLK_SYS_AARCH64)
#include "mlkem/src/fips202/native/aarch64/src/keccakf1600_round_constants.c"
#endif
#if defined(MLK_SYS_X86_64)
#include "mlkem/src/fips202/native/x86_64/src/keccakf1600_constants.c"
#endif
#if defined(MLK_SYS_ARMV81M_MVE)
#include "mlkem/src/fips202/native/armv81m/src/keccak_f1600_x4_mve.c"
#include "mlkem/src/fips202/native/armv81m/src/keccakf1600_round_constants.c"
#endif
#endif /* MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202 */

/* ------------------------------------------------------------------------- */

#include "emp-ot/base_ot/mlkem/mlkem512.h"

#if MLKEM_K != 2 || MLKEM_POLYVECBYTES != EMP_MLKEM512_POLYVECBYTES ||   \
    MLKEM_INDCPA_PUBLICKEYBYTES != EMP_MLKEM512_PKBYTES ||               \
    MLKEM_INDCPA_SECRETKEYBYTES != EMP_MLKEM512_SKBYTES ||               \
    MLKEM_INDCPA_BYTES != EMP_MLKEM512_CTBYTES ||                        \
    MLKEM_INDCPA_MSGBYTES != EMP_MLKEM512_MSGBYTES ||                    \
    MLKEM_SYMBYTES != EMP_MLKEM512_SYMBYTES
#error "mlkem512.h sizes do not match the ML-KEM-512 build"
#endif

/* Ĥ(seed)[j] = SampleNTT(seed || j || 0) for j < K = 2, for two seeds in one
 * call of the four-way Keccak. The samples are in FIPS 203's NTT order and
 * are then permuted into the backend's order, as mlk_gen_matrix does. */
static void bmm_hhat_x2(mlk_polyvec *h0, mlk_polyvec *h1,
                        const uint8_t seed0[MLKEM_SYMBYTES],
                        const uint8_t seed1[MLKEM_SYMBYTES])
{
  MLK_ALIGN uint8_t ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];
  unsigned l;
  for (l = 0; l < 4; l++)
  {
    mlk_memcpy(ext[l], l < 2 ? seed0 : seed1, MLKEM_SYMBYTES);
    ext[l][MLKEM_SYMBYTES + 0] = (uint8_t)(l % 2);
    ext[l][MLKEM_SYMBYTES + 1] = 0;
  }
  mlk_poly_rej_uniform_x4(&h0->vec[0], &h0->vec[1], &h1->vec[0], &h1->vec[1],
                          ext);
  mlk_polyvec_permute_bitrev_to_custom(h0);
  mlk_polyvec_permute_bitrev_to_custom(h1);
}

void emp_mlkem512_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                           size_t inlen)
{
  mlk_shake256(out, outlen, in, inlen);
}

void emp_mlkem512_bmm_receiver_key(uint8_t r[EMP_MLKEM512_POLYVECBYTES],
                                   uint8_t sk[EMP_MLKEM512_SKBYTES],
                                   const uint8_t rho[EMP_MLKEM512_SYMBYTES],
                                   const uint8_t noise[EMP_MLKEM512_SYMBYTES],
                                   const uint8_t h_seed[EMP_MLKEM512_SYMBYTES])
{
  MLK_ALIGN mlk_polymat a;
  MLK_ALIGN mlk_polyvec s, e, t, h, h_unused;
  MLK_ALIGN mlk_polyvec_mulcache s_cache;
  unsigned j;

  /* mlk_indcpa_keypair_derand's body, with rho given instead of taken from
   * G(coins || K) and noise as its noise seed. */
  mlk_gen_matrix(&a, rho, 0 /* no transpose */);
  mlk_keypair_getnoise_eta1(&s, &e, noise);
  mlk_polyvec_ntt(&s);
  mlk_polyvec_ntt(&e);
  mlk_polyvec_mulcache_compute(&s_cache, &s);
  mlk_matvec_mul(&t, &a, &s, &s_cache);
  mlk_polyvec_tomont(&t);
  mlk_polyvec_add(&t, &e);
  mlk_polyvec_reduce(&t);
  mlk_polyvec_reduce(&s);
  mlk_pack_sk(sk, &s);

  /* r = t̂ − Ĥ(h_seed). The four-way sampler fills a second, unused vector. */
  bmm_hhat_x2(&h, &h_unused, h_seed, h_seed);
  for (j = 0; j < MLKEM_K; j++)
  {
    mlk_poly_sub(&t.vec[j], &h.vec[j]);
  }
  mlk_polyvec_reduce(&t);
  mlk_polyvec_tobytes(r, &t);

  mlk_zeroize(&s, sizeof(s));
  mlk_zeroize(&e, sizeof(e));
  mlk_zeroize(&s_cache, sizeof(s_cache));
}

int emp_mlkem512_bmm_sender_keys(uint8_t ek0[EMP_MLKEM512_PKBYTES],
                                 uint8_t ek1[EMP_MLKEM512_PKBYTES],
                                 const uint8_t r[EMP_MLKEM512_POLYVECBYTES],
                                 const uint8_t rho[EMP_MLKEM512_SYMBYTES],
                                 const uint8_t h_seed0[EMP_MLKEM512_SYMBYTES],
                                 const uint8_t h_seed1[EMP_MLKEM512_SYMBYTES])
{
  MLK_ALIGN mlk_polyvec rv, h0, h1;

  mlk_memcpy(ek0, r, MLKEM_POLYVECBYTES);
  mlk_memcpy(ek0 + MLKEM_POLYVECBYTES, rho, MLKEM_SYMBYTES);
  if (mlk_kem_check_pk(ek0, 0) != 0)
  {
    return -1;
  }
  mlk_polyvec_frombytes(&rv, r);

  bmm_hhat_x2(&h0, &h1, h_seed0, h_seed1);
  mlk_polyvec_add(&h0, &rv);
  mlk_polyvec_add(&h1, &rv);
  mlk_polyvec_reduce(&h0);
  mlk_polyvec_reduce(&h1);
  mlk_polyvec_tobytes(ek0, &h0);
  mlk_polyvec_tobytes(ek1, &h1);
  mlk_memcpy(ek1 + MLKEM_POLYVECBYTES, rho, MLKEM_SYMBYTES);
  return 0;
}

int emp_mlkem512_encrypt(uint8_t ct[EMP_MLKEM512_CTBYTES],
                         const uint8_t m[EMP_MLKEM512_MSGBYTES],
                         const uint8_t ek[EMP_MLKEM512_PKBYTES],
                         const uint8_t coins[EMP_MLKEM512_SYMBYTES])
{
  return mlk_indcpa_enc(ct, m, ek, coins, 0);
}

int emp_mlkem512_decrypt(uint8_t m[EMP_MLKEM512_MSGBYTES],
                         const uint8_t ct[EMP_MLKEM512_CTBYTES],
                         const uint8_t sk[EMP_MLKEM512_SKBYTES])
{
  return mlk_indcpa_dec(m, ct, sk, 0);
}
