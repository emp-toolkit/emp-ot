/*
 * One ML-KEM level for the BMM base OT, on the vendored mlkem-native
 * (third_party/mlkem-native, unmodified; see its VENDOR.md). Included once by
 * each of mlkem512.c, mlkem768.c and mlkem1024.c, which set
 * MLK_CONFIG_PARAMETER_SET and say whether the level-independent code is
 * compiled here (mlkem_config.h); it is not a header for other files.
 *
 * This compiles mlkem-native's C sources: the same files in the same order as
 * its mlkem_native.c, which cannot be included itself because it ends by
 * undefining the internal names used below. In the level files that leave the
 * level-independent code out, those sources compile only their level-specific
 * parts. The assembly is the vendored mlkem_native_asm.S, built once for all
 * levels with the same configuration.
 *
 * Encryption and decryption are mlkem-native's K-PKE functions, unchanged.
 * The receiver's key is K-PKE.KeyGen with the matrix seed rho supplied by
 * the caller: in BMM both parties derive rho from the session id and the OT
 * index, and the receiver must not be able to choose its own matrix.
 */
#if !defined(MLK_CONFIG_FILE)
#error "mlkem_level.h must be built with MLK_CONFIG_FILE set (see CMakeLists.txt)"
#endif
#if !defined(MLK_CONFIG_PARAMETER_SET)
#error "mlkem_level.h is included by mlkem{512,768,1024}.c, which set the level"
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

#include "emp-ot/base_ot/mlkem/mlkem.h"

/* emp_mlkem<level>_<name> and EMP_MLKEM<level>_<size> for this file's level. */
#define EMP_MLKEM_CAT3_(a, b, c) a##b##_##c
#define EMP_MLKEM_CAT3(a, b, c) EMP_MLKEM_CAT3_(a, b, c)
#define EMP_MLKEM_FN(name) EMP_MLKEM_CAT3(emp_mlkem, MLK_CONFIG_PARAMETER_SET, name)
#define EMP_MLKEM_SIZE(name) EMP_MLKEM_CAT3(EMP_MLKEM, MLK_CONFIG_PARAMETER_SET, name)

/* indcpa.c's file-local helpers. In a multi-level build it names them per
 * level, through MLK_ADD_PARAM_SET, and undefines the short names at its end;
 * these reach the same functions. */
#define bmm_pack_pk MLK_ADD_PARAM_SET(mlk_pack_pk)
#define bmm_pack_sk MLK_ADD_PARAM_SET(mlk_pack_sk)
#define bmm_matvec_mul MLK_ADD_PARAM_SET(mlk_matvec_mul)
#define bmm_keypair_getnoise_eta1 MLK_ADD_PARAM_SET(mlk_keypair_getnoise_eta1)
#define bmm_polyvec_permute_bitrev_to_custom \
  MLK_ADD_PARAM_SET(mlk_polyvec_permute_bitrev_to_custom)

#if MLKEM_POLYVECBYTES != EMP_MLKEM_SIZE(POLYVECBYTES) ||               \
    MLKEM_INDCPA_PUBLICKEYBYTES != EMP_MLKEM_SIZE(PKBYTES) ||           \
    MLKEM_INDCPA_SECRETKEYBYTES != EMP_MLKEM_SIZE(SKBYTES) ||           \
    MLKEM_INDCPA_BYTES != EMP_MLKEM_SIZE(CTBYTES) ||                    \
    MLKEM_INDCPA_MSGBYTES != EMP_MLKEM_MSGBYTES ||                      \
    MLKEM_SYMBYTES != EMP_MLKEM_SYMBYTES
#error "mlkem.h sizes do not match this ML-KEM level"
#endif

/* SampleNTT(seed[l] || x[l] || 0) into out[l] for l < n, four at a time
 * through the four-way Keccak. Lanes past n sample into scratch
 * polynomials, one per lane, since the sampler's outputs must not alias. */
static void bmm_sample_ntt(mlk_poly *const out[], const uint8_t *const seed[],
                           const uint8_t x[], unsigned n)
{
  MLK_ALIGN uint8_t ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];
  MLK_ALIGN mlk_poly spare[4];
  unsigned i, l;
  for (i = 0; i < n; i += 4)
  {
    mlk_poly *dst[4];
    for (l = 0; l < 4; l++)
    {
      const unsigned k = i + l < n ? i + l : n - 1;
      dst[l] = i + l < n ? out[i + l] : &spare[l];
      mlk_memcpy(ext[l], seed[k], MLKEM_SYMBYTES);
      ext[l][MLKEM_SYMBYTES + 0] = x[k];
      ext[l][MLKEM_SYMBYTES + 1] = 0;
    }
    mlk_poly_rej_uniform_x4(dst[0], dst[1], dst[2], dst[3], ext);
  }
}

/* Ĥ(seed)[j] = SampleNTT(seed || j || 0) for j < K, for `count` (one or two)
 * seeds at once. The samples are in FIPS 203's NTT order and are then
 * permuted into the backend's order, as mlk_gen_matrix does. */
static void bmm_hhat(mlk_polyvec *const h[], const uint8_t *const seeds[],
                     unsigned count)
{
  mlk_poly *out[2 * MLKEM_K];
  const uint8_t *seed[2 * MLKEM_K];
  uint8_t x[2 * MLKEM_K];
  unsigned c, j, n = 0;
  for (c = 0; c < count; c++)
  {
    for (j = 0; j < MLKEM_K; j++)
    {
      out[n] = &h[c]->vec[j];
      seed[n] = seeds[c];
      x[n] = (uint8_t)j;
      n++;
    }
  }
  bmm_sample_ntt(out, seed, x, n);
  for (c = 0; c < count; c++)
  {
    bmm_polyvec_permute_bitrev_to_custom(h[c]);
  }
}

#if defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED)
void emp_mlkem_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                        size_t inlen)
{
  mlk_shake256(out, outlen, in, inlen);
}
#endif

void EMP_MLKEM_FN(bmm_receiver_key)(uint8_t *r, uint8_t *sk,
                                    const uint8_t *rho, const uint8_t *noise,
                                    const uint8_t *h_seed)
{
  MLK_ALIGN mlk_polymat a;
  MLK_ALIGN mlk_polyvec s, e, t, h;
  MLK_ALIGN mlk_polyvec_mulcache s_cache;
  mlk_polyvec *const hv[1] = {&h};
  const uint8_t *const seeds[1] = {h_seed};
  unsigned j;

  /* mlk_indcpa_keypair_derand's body, with rho given instead of taken from
   * G(coins || K) and noise as its noise seed. */
  mlk_gen_matrix(&a, rho, 0 /* no transpose */);
  bmm_keypair_getnoise_eta1(&s, &e, noise);
  mlk_polyvec_ntt(&s);
  mlk_polyvec_ntt(&e);
  mlk_polyvec_mulcache_compute(&s_cache, &s);
  bmm_matvec_mul(&t, &a, &s, &s_cache);
  mlk_polyvec_tomont(&t);
  mlk_polyvec_add(&t, &e);
  mlk_polyvec_reduce(&t);
  mlk_polyvec_reduce(&s);
  bmm_pack_sk(sk, &s);

  /* r = t̂ − Ĥ(h_seed). */
  bmm_hhat(hv, seeds, 1);
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

int EMP_MLKEM_FN(bmm_sender_keys)(uint8_t *ek0, uint8_t *ek1,
                                  const uint8_t *r, const uint8_t *rho,
                                  const uint8_t *h_seed0,
                                  const uint8_t *h_seed1)
{
  MLK_ALIGN mlk_polyvec rv, h0, h1;
  mlk_polyvec *const hv[2] = {&h0, &h1};
  const uint8_t *const seeds[2] = {h_seed0, h_seed1};

  mlk_memcpy(ek0, r, MLKEM_POLYVECBYTES);
  mlk_memcpy(ek0 + MLKEM_POLYVECBYTES, rho, MLKEM_SYMBYTES);
  if (mlk_kem_check_pk(ek0, 0) != 0)
  {
    return -1;
  }
  mlk_polyvec_frombytes(&rv, r);

  bmm_hhat(hv, seeds, 2);
  mlk_polyvec_add(&h0, &rv);
  mlk_polyvec_add(&h1, &rv);
  mlk_polyvec_reduce(&h0);
  mlk_polyvec_reduce(&h1);
  bmm_pack_pk(ek0, &h0, rho);
  bmm_pack_pk(ek1, &h1, rho);
  return 0;
}

int EMP_MLKEM_FN(encrypt)(uint8_t *ct, const uint8_t *m, const uint8_t *ek,
                          const uint8_t *coins)
{
  return mlk_indcpa_enc(ct, m, ek, coins, 0);
}

int EMP_MLKEM_FN(decrypt)(uint8_t *m, const uint8_t *ct, const uint8_t *sk)
{
  return mlk_indcpa_dec(m, ct, sk, 0);
}
