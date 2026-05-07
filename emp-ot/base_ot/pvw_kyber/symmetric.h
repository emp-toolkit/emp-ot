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
 *
 *   - shake128_squeezeblocks uses EVP_DigestSqueeze on OpenSSL ≥ 3.3.
 *     Older OpenSSL — including the 3.0.x shipped by Ubuntu 24.04 —
 *     has neither EVP_DigestSqueeze nor multi-call EVP_DigestFinalXOF,
 *     so we fall back to buffering the absorbed seed and
 *     re-init/re-absorb/finalize-XOF for cumulative output, returning
 *     only the trailing new bytes. O(n²) in bytes squeezed, but
 *     gen_matrix tops out at ~10 SHAKE-128 blocks per polynomial.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>  /* transitively pulls in OPENSSL_VERSION_NUMBER */

/* EVP_DigestSqueeze + multi-call EVP_DigestFinalXOF land in OpenSSL 3.3. */
#define EMP_PVW_HAVE_DIGEST_SQUEEZE (OPENSSL_VERSION_NUMBER >= 0x30300000L)

#include "kyber/params.h"  /* KYBER_SYMBYTES */

#ifdef __cplusplus
extern "C" {
#endif

#define SHAKE128_RATE 168
#define XOF_BLOCKBYTES SHAKE128_RATE

typedef struct {
    void *opaque;  /* EVP_MD_CTX*, heap-allocated lazily on first init */
#if !EMP_PVW_HAVE_DIGEST_SQUEEZE
    /* OpenSSL < 3.3 fallback: remember the absorbed seed and how many
     * bytes we have already produced, so each squeeze can re-derive the
     * cumulative XOF stream and return only the new tail. */
    uint8_t  absorbed[KYBER_SYMBYTES + 2];
    uint16_t absorbed_len;
    uint32_t produced;
#endif
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
#if EMP_PVW_HAVE_DIGEST_SQUEEZE
    EVP_MD_CTX *c = _emp_kst_ensure(s, EVP_shake128());
    uint8_t extseed[KYBER_SYMBYTES + 2];
    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    EVP_DigestUpdate(c, extseed, sizeof(extseed));
#else
    /* No live ctx yet — squeeze allocates one lazily and re-inits each
     * call, so we just stash the absorbed bytes. */
    memcpy(s->absorbed, seed, KYBER_SYMBYTES);
    s->absorbed[KYBER_SYMBYTES + 0] = x;
    s->absorbed[KYBER_SYMBYTES + 1] = y;
    s->absorbed_len = (uint16_t)(KYBER_SYMBYTES + 2);
    s->produced = 0;
#endif
}

static inline void shake128_squeezeblocks(uint8_t *out, size_t nblocks,
                                           keccak_state *s) {
#if EMP_PVW_HAVE_DIGEST_SQUEEZE
    EVP_DigestSqueeze((EVP_MD_CTX *)s->opaque, out, nblocks * SHAKE128_RATE);
#else
    const size_t need = nblocks * SHAKE128_RATE;
    const size_t total = (size_t)s->produced + need;
    EVP_MD_CTX *c = (EVP_MD_CTX *)s->opaque;
    if (c == NULL) {
        c = EVP_MD_CTX_new();
        if (c == NULL) abort();
        s->opaque = (void *)c;
    }
    uint8_t *tmp = (uint8_t *)malloc(total);
    if (tmp == NULL) abort();
    EVP_DigestInit_ex(c, EVP_shake128(), NULL);
    EVP_DigestUpdate(c, s->absorbed, s->absorbed_len);
    EVP_DigestFinalXOF(c, tmp, total);
    memcpy(out, tmp + s->produced, need);
    free(tmp);
    s->produced = (uint32_t)total;
#endif
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
