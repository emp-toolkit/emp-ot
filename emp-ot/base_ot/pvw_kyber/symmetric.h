#ifndef EMP_PVW_KYBER_SYMMETRIC_H
#define EMP_PVW_KYBER_SYMMETRIC_H

/*
 * SHAKE / Keccak surface for the Kyber-PVW base OT, implemented inline
 * atop OpenSSL EVP. Replaces what used to be three separate files
 * lifted from pq-crystals/kyber/ref (fips202.h, fips202.c,
 * symmetric-shake.c) with a single self-contained header.
 *
 * What survives, and why:
 *
 *   - Verbatim kyber/poly.c uses `prf(...)` (in poly_getnoise_eta1 /
 *     _eta2) for noise sampling. That's the only surface the lifted
 *     pq-crystals files actually consume from this header — everything
 *     else (xof_*, hash_h, hash_g, kyber_shake256_rkprf) only matters
 *     to indcpa.c / kem.c, which we don't lift.
 *
 *   - emp-ot/base_ot/pvw_kyber/crs.hpp (our CRS expander) needs streaming
 *     SHAKE-128: kyber_shake128_absorb + shake128_squeezeblocks, plus
 *     a release call for the heap-allocated state.
 *
 * Implementation notes:
 *
 *   - keccak_state holds an EVP_MD_CTX* lazily allocated on first use.
 *     Zero-initialise (`{0}`) every keccak_state before its first call;
 *     call shake_state_release before it leaves scope. We can't
 *     distinguish "freshly stack-allocated with garbage" from "live
 *     ctx", so the zero-init contract is mandatory.
 *
 *   - kyber_shake256_prf uses a per-thread persistent EVP_MD_CTX,
 *     reset via EVP_DigestInit_ex on each call. Mirrors emp-tool's
 *     Hash::hash_once amortization. Each TU including this header
 *     gets its own thread_local ctx (static-inline → internal
 *     linkage); fine — there are only two TUs (poly.c, crs.hpp).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "kyber/params.h"  /* KYBER_SYMBYTES */

#ifdef __cplusplus
extern "C" {
#endif

#define SHAKE128_RATE 168
#define XOF_BLOCKBYTES SHAKE128_RATE

typedef struct {
    void *opaque;  /* EVP_MD_CTX*, heap-allocated lazily on first init */
} keccak_state;

static inline EVP_MD_CTX *_emp_kst_ensure(keccak_state *s, const EVP_MD *md) {
    EVP_MD_CTX *c = (EVP_MD_CTX *)s->opaque;
    if (c == NULL) {
        c = EVP_MD_CTX_new();
        if (c == NULL) abort();
        s->opaque = (void *)c;
    }
    EVP_DigestInit_ex(c, md, NULL);
    return c;
}

static inline void shake_state_release(keccak_state *s) {
    EVP_MD_CTX *c = (EVP_MD_CTX *)s->opaque;
    if (c) {
        EVP_MD_CTX_free(c);
        s->opaque = NULL;
    }
}

/* Absorb (seed[KYBER_SYMBYTES] || x || y) into a fresh SHAKE-128 state.
 * Used by crs.hpp for matrix-A expansion (mirrors the pattern Kyber's
 * indcpa.c::gen_matrix uses, which we don't lift). */
static inline void kyber_shake128_absorb(keccak_state *s,
                                          const uint8_t seed[KYBER_SYMBYTES],
                                          uint8_t x, uint8_t y) {
    EVP_MD_CTX *c = _emp_kst_ensure(s, EVP_shake128());
    uint8_t extseed[KYBER_SYMBYTES + 2];
    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    EVP_DigestUpdate(c, extseed, sizeof(extseed));
}

static inline void shake128_squeezeblocks(uint8_t *out, size_t nblocks,
                                           keccak_state *s) {
    EVP_DigestSqueeze((EVP_MD_CTX *)s->opaque, out, nblocks * SHAKE128_RATE);
}

/* Per-thread persistent EVP_MD_CTX for the one-shot SHAKE-256 PRF.
 * Each TU including this header gets its own thread_local copy; that's
 * fine, only poly.c and crs.hpp include it. */
#if defined(__cplusplus)
  #define EMP_PVW_TLS thread_local
#elif __STDC_VERSION__ >= 201112L
  #define EMP_PVW_TLS _Thread_local
#elif defined(__GNUC__)
  #define EMP_PVW_TLS __thread
#else
  #define EMP_PVW_TLS
#endif

/* One-shot SHAKE-256 PRF: out = SHAKE256(key || nonce). Called from
 * verbatim kyber/poly.c via the `prf` macro below. Hot path —
 * thread-local ctx amortises EVP_MD_CTX_new/free across calls. */
static inline void kyber_shake256_prf(uint8_t *out, size_t outlen,
                                       const uint8_t key[KYBER_SYMBYTES],
                                       uint8_t nonce) {
    static EMP_PVW_TLS EVP_MD_CTX *ctx = NULL;
    if (ctx == NULL) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) abort();
    }
    uint8_t extkey[KYBER_SYMBYTES + 1];
    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, extkey, sizeof(extkey));
    EVP_DigestFinalXOF(ctx, out, outlen);
}

#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)

/* One-shot SHAKE-256: out = SHAKE256(in). Used by our own
 * derive_subseed / sid_to_session_seed for CRS expansion. */
static inline void shake256(uint8_t *out, size_t outlen,
                             const uint8_t *in, size_t inlen) {
    static EMP_PVW_TLS EVP_MD_CTX *ctx = NULL;
    if (ctx == NULL) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) abort();
    }
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinalXOF(ctx, out, outlen);
}

#ifdef __cplusplus
}
#endif

#endif  /* EMP_PVW_KYBER_SYMMETRIC_H */
