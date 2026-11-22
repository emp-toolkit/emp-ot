#ifndef EMP_OT_MLKEM512_H__
#define EMP_OT_MLKEM512_H__

/* Internal header: the ML-KEM-512 operations the BMM base OT runs, on the
 * vendored mlkem-native (mlkem512.c). Included only by bmm.cpp.
 *
 * Polynomial vectors cross this interface in FIPS 203's ByteEncode12 encoding
 * of the NTT domain, the encoding of an ML-KEM public key's t̂. That encoding
 * is the same on every mlkem-native backend. */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EMP_MLKEM512_SYMBYTES     32   /* seeds and coins */
#define EMP_MLKEM512_POLYVECBYTES 768  /* an element of R_q^2, NTT domain */
#define EMP_MLKEM512_PKBYTES      800  /* K-PKE public key (t̂, ρ) */
#define EMP_MLKEM512_SKBYTES      768  /* K-PKE secret key ŝ */
#define EMP_MLKEM512_CTBYTES      768  /* K-PKE ciphertext (u: 640, v: 128) */
#define EMP_MLKEM512_MSGBYTES     32   /* K-PKE plaintext */

/* SHAKE-256 from the vendored FIPS 202 code. */
void emp_mlkem512_shake256(uint8_t *out, size_t outlen, const uint8_t *in,
                           size_t inlen);

/* The receiver's first message for one OT, with choice b.
 * K-PKE.KeyGen under the matrix seed rho and the noise coins `noise`, with rho
 * given instead of derived from the coins, gives (t̂, ŝ). Then
 * r = t̂ − Ĥ(h_seed), where Ĥ(seed)[j] = SampleNTT(seed || j || 0).
 * Writes r and the secret key ŝ. */
void emp_mlkem512_bmm_receiver_key(uint8_t r[EMP_MLKEM512_POLYVECBYTES],
                                   uint8_t sk[EMP_MLKEM512_SKBYTES],
                                   const uint8_t rho[EMP_MLKEM512_SYMBYTES],
                                   const uint8_t noise[EMP_MLKEM512_SYMBYTES],
                                   const uint8_t h_seed[EMP_MLKEM512_SYMBYTES]);

/* The sender's two public keys for one OT: ek_β = (r + Ĥ(h_seed_β), rho).
 * Returns 0, or -1 if (r, rho) fails FIPS 203's modulus check, i.e. r is not
 * the canonical encoding of an element of R_q^2. */
int emp_mlkem512_bmm_sender_keys(uint8_t ek0[EMP_MLKEM512_PKBYTES],
                                 uint8_t ek1[EMP_MLKEM512_PKBYTES],
                                 const uint8_t r[EMP_MLKEM512_POLYVECBYTES],
                                 const uint8_t rho[EMP_MLKEM512_SYMBYTES],
                                 const uint8_t h_seed0[EMP_MLKEM512_SYMBYTES],
                                 const uint8_t h_seed1[EMP_MLKEM512_SYMBYTES]);

/* K-PKE.Encrypt and K-PKE.Decrypt, mlkem-native's unchanged. Return 0. */
int emp_mlkem512_encrypt(uint8_t ct[EMP_MLKEM512_CTBYTES],
                         const uint8_t m[EMP_MLKEM512_MSGBYTES],
                         const uint8_t ek[EMP_MLKEM512_PKBYTES],
                         const uint8_t coins[EMP_MLKEM512_SYMBYTES]);
int emp_mlkem512_decrypt(uint8_t m[EMP_MLKEM512_MSGBYTES],
                         const uint8_t ct[EMP_MLKEM512_CTBYTES],
                         const uint8_t sk[EMP_MLKEM512_SKBYTES]);

#ifdef __cplusplus
}
#endif

#endif /* EMP_OT_MLKEM512_H__ */
