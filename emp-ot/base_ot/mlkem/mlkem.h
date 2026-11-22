#ifndef EMP_OT_MLKEM_H__
#define EMP_OT_MLKEM_H__

/* Internal header: the ML-KEM operations the BMM base OT runs, at each of
 * FIPS 203's three parameter sets, on the vendored mlkem-native
 * (mlkem_level.h). Included only by bmm.cpp and the level files.
 *
 * Polynomial vectors cross this interface in FIPS 203's ByteEncode12 encoding
 * of the NTT domain, the encoding of an ML-KEM public key's t̂. That encoding
 * is the same on every mlkem-native backend. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EMP_MLKEM_SYMBYTES 32  /* seeds and coins */
#define EMP_MLKEM_MSGBYTES 32  /* K-PKE plaintext */

/* Per level: an element of R_q^K in the NTT domain, the K-PKE public key
 * (t̂, rho), the K-PKE secret key ŝ, and the K-PKE ciphertext (u, v). */
#define EMP_MLKEM512_POLYVECBYTES 768
#define EMP_MLKEM512_PKBYTES 800
#define EMP_MLKEM512_SKBYTES 768
#define EMP_MLKEM512_CTBYTES 768
#define EMP_MLKEM768_POLYVECBYTES 1152
#define EMP_MLKEM768_PKBYTES 1184
#define EMP_MLKEM768_SKBYTES 1152
#define EMP_MLKEM768_CTBYTES 1088
#define EMP_MLKEM1024_POLYVECBYTES 1536
#define EMP_MLKEM1024_PKBYTES 1568
#define EMP_MLKEM1024_SKBYTES 1536
#define EMP_MLKEM1024_CTBYTES 1568

/* SHAKE-256 from the vendored FIPS 202 code. */
void emp_mlkem_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                        size_t inlen);

/* For each level N in {512, 768, 1024}, with the sizes above:
 *
 * emp_mlkemN_bmm_receiver_key(r, sk, rho, noise, h_seed)
 *   The receiver's first message for one OT, with choice b. K-PKE.KeyGen
 *   under the matrix seed rho and the noise coins `noise`, with rho given
 *   instead of derived from the coins, gives (t̂, ŝ). Then
 *   r = t̂ − Ĥ(h_seed), where Ĥ(seed)[j] = SampleNTT(seed || j || 0).
 *   Writes r and the secret key ŝ.
 *
 * emp_mlkemN_bmm_sender_keys(ek0, ek1, r, rho, h_seed0, h_seed1)
 *   The sender's two public keys for one OT: ek_β = (r + Ĥ(h_seed_β), rho).
 *   Returns 0, or -1 if (r, rho) fails FIPS 203's modulus check, i.e. r is
 *   not the canonical encoding of an element of R_q^K.
 *
 * emp_mlkemN_encrypt(ct, m, ek, coins), emp_mlkemN_decrypt(m, ct, sk)
 *   K-PKE.Encrypt and K-PKE.Decrypt, mlkem-native's unchanged. Return 0. */
#define EMP_MLKEM_DECLARE_LEVEL(N)                                           \
  void emp_mlkem##N##_bmm_receiver_key(uint8_t *r, uint8_t *sk,              \
                                       const uint8_t *rho,                   \
                                       const uint8_t *noise,                 \
                                       const uint8_t *h_seed);               \
  int emp_mlkem##N##_bmm_sender_keys(uint8_t *ek0, uint8_t *ek1,             \
                                     const uint8_t *r, const uint8_t *rho,   \
                                     const uint8_t *h_seed0,                 \
                                     const uint8_t *h_seed1);                \
  int emp_mlkem##N##_encrypt(uint8_t *ct, const uint8_t *m,                  \
                             const uint8_t *ek, const uint8_t *coins);       \
  int emp_mlkem##N##_decrypt(uint8_t *m, const uint8_t *ct, const uint8_t *sk);

EMP_MLKEM_DECLARE_LEVEL(512)
EMP_MLKEM_DECLARE_LEVEL(768)
EMP_MLKEM_DECLARE_LEVEL(1024)

#undef EMP_MLKEM_DECLARE_LEVEL

#ifdef __cplusplus
}
#endif

#endif /* EMP_OT_MLKEM_H__ */
