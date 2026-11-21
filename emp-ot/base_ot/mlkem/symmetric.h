#ifndef EMP_MLKEM_SYMMETRIC_H
#define EMP_MLKEM_SYMMETRIC_H

/*
 * SHAKE / Keccak surface for the ML-KEM (Kyber) base OT, implemented inline
 * atop OpenSSL EVP in a single self-contained header. Upstream provenance:
 * pq-crystals/kyber/ref (fips202.h, fips202.c, symmetric-shake.c).
 *
 * What survives, and why:
 *
 *   - Verbatim kyber/poly.c uses `prf(...)` (in poly_getnoise_eta1 /
 *     _eta2) for noise sampling. That's the only surface the lifted
 *     pq-crystals files actually consume from this header — everything
 *     else (xof_*, hash_h, hash_g, kyber_shake256_rkprf) only matters
 *     to indcpa.c / kem.c, which we don't lift.
 *
 *   - emp-ot/base_ot/mlkem/crs.hpp (our CRS expander) needs streaming
 *     SHAKE-128: kyber_shake128_absorb + shake128_squeezeblocks, plus
 *     a release call for the heap-allocated state.
 *
 * Implementation notes:
 *
 *   - Every context is initialized with an EVP_MD fetched once per
 *     thread (EVP_MD_fetch), not with the legacy EVP_shake128() /
 *     EVP_shake256() handles. OpenSSL 3 resolves a legacy handle to its
 *     provider implementation inside every EVP_DigestInit_ex; with a
 *     fetched MD, re-initializing a context that last ran the same MD
 *     only resets its Keccak state.
 *
 *   - keccak_state holds an EVP_MD_CTX* lazily allocated on first use
 *     and kept across absorbs, so one state can serve many squeezes.
 *     Zero-initialise (`{0}`) every keccak_state before its first call;
 *     call shake_state_release before it leaves scope. We can't
 *     distinguish "freshly stack-allocated with garbage" from "live
 *     ctx", so the zero-init contract is mandatory.
 *
 *   - kyber_shake256_prf and shake256 use a per-thread persistent
 *     EVP_MD_CTX, reset via EVP_DigestInit_ex on each call. Mirrors
 *     emp-tool's Hash::hash_once amortization. Each TU including this
 *     header gets its own thread_local ctxs and fetched MDs
 *     (static-inline → internal linkage); fine — there are only two TUs
 *     (poly.c, bmm.cpp). They are never freed: they live as long as
 *     their thread.
 *
 *   - shake128_squeezeblocks uses EVP_DigestSqueeze on OpenSSL ≥ 3.3.
 *     Older OpenSSL — including the 3.0.x shipped by Ubuntu 24.04 —
 *     has neither EVP_DigestSqueeze nor multi-call EVP_DigestFinalXOF,
 *     so we buffer the absorbed seed. The first squeeze after an absorb
 *     finalizes straight into the caller's buffer. A later squeeze
 *     re-inits, re-absorbs and finalizes the cumulative output,
 *     returning only the trailing new bytes: O(n²) in bytes squeezed,
 *     but the uniform sampler squeezes past its first three blocks for
 *     under 1% of polynomials, one block at a time.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>  /* transitively pulls in OPENSSL_VERSION_NUMBER */

/* C-callable die-with-diagnostic. emp-tool's error() is C++ only, but
 * this header is included by Kyber's poly.c (compiled as C), so we
 * stay on stderr + abort. */
#define EMP_MLKEM_DIE(msg) do { \
    fprintf(stderr, "emp-ot/mlkem: " msg "\n"); \
    abort(); \
} while (0)

/* A failed EVP digest call leaves its output unwritten: secret noise would
 * come from uninitialized memory and the CRS sampler might never finish. */
#define EMP_MLKEM_CHECK(call, what) do { \
    if ((call) != 1) EMP_MLKEM_DIE(what " failed"); \
} while (0)

/* EVP_DigestSqueeze + multi-call EVP_DigestFinalXOF land in OpenSSL 3.3. */
#define EMP_MLKEM_HAVE_DIGEST_SQUEEZE (OPENSSL_VERSION_NUMBER >= 0x30300000L)

#include "kyber/params.h"  /* KYBER_SYMBYTES */

#ifdef __cplusplus
extern "C" {
#endif

/* Per-thread persistent state (fetched MDs, one-shot contexts). Each TU
 * including this header gets its own thread_local copy; that's fine,
 * only poly.c and bmm.cpp include it. */
#if defined(__cplusplus)
  #define EMP_MLKEM_TLS thread_local
#elif __STDC_VERSION__ >= 201112L
  #define EMP_MLKEM_TLS _Thread_local
#elif defined(__GNUC__)
  #define EMP_MLKEM_TLS __thread
#else
  #define EMP_MLKEM_TLS
#endif

/* SHAKE-128 / SHAKE-256 implementations, fetched once per thread. */
static inline const EVP_MD *_emp_mlkem_shake128(void) {
    static EMP_MLKEM_TLS EVP_MD *md = NULL;
    if (md == NULL) {
        md = EVP_MD_fetch(NULL, "SHAKE128", NULL);
        if (md == NULL) EMP_MLKEM_DIE("EVP_MD_fetch(SHAKE128)");
    }
    return md;
}

static inline const EVP_MD *_emp_mlkem_shake256(void) {
    static EMP_MLKEM_TLS EVP_MD *md = NULL;
    if (md == NULL) {
        md = EVP_MD_fetch(NULL, "SHAKE256", NULL);
        if (md == NULL) EMP_MLKEM_DIE("EVP_MD_fetch(SHAKE256)");
    }
    return md;
}

#define SHAKE128_RATE 168
#define XOF_BLOCKBYTES SHAKE128_RATE

typedef struct {
    void *opaque;  /* EVP_MD_CTX*, heap-allocated lazily on first init, kept across absorbs */
#if !EMP_MLKEM_HAVE_DIGEST_SQUEEZE
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
        if (c == NULL) EMP_MLKEM_DIE("EVP_MD_CTX_new in _emp_kst_ensure");
        s->opaque = (void *)c;
    }
    EMP_MLKEM_CHECK(EVP_DigestInit_ex(c, md, NULL), "EVP_DigestInit_ex");
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
#if EMP_MLKEM_HAVE_DIGEST_SQUEEZE
    EVP_MD_CTX *c = _emp_kst_ensure(s, _emp_mlkem_shake128());
    uint8_t extseed[KYBER_SYMBYTES + 2];
    memcpy(extseed, seed, KYBER_SYMBYTES);
    extseed[KYBER_SYMBYTES + 0] = x;
    extseed[KYBER_SYMBYTES + 1] = y;
    EMP_MLKEM_CHECK(EVP_DigestUpdate(c, extseed, sizeof(extseed)), "EVP_DigestUpdate");
#else
    /* Squeeze (re-)initializes the ctx, allocating it lazily, so we
     * just stash the absorbed bytes. */
    memcpy(s->absorbed, seed, KYBER_SYMBYTES);
    s->absorbed[KYBER_SYMBYTES + 0] = x;
    s->absorbed[KYBER_SYMBYTES + 1] = y;
    s->absorbed_len = (uint16_t)(KYBER_SYMBYTES + 2);
    s->produced = 0;
#endif
}

static inline void shake128_squeezeblocks(uint8_t *out, size_t nblocks,
                                           keccak_state *s) {
#if EMP_MLKEM_HAVE_DIGEST_SQUEEZE
    EMP_MLKEM_CHECK(EVP_DigestSqueeze((EVP_MD_CTX *)s->opaque, out, nblocks * SHAKE128_RATE), "EVP_DigestSqueeze");
#else
    const size_t need = nblocks * SHAKE128_RATE;
    const size_t total = (size_t)s->produced + need;
    EVP_MD_CTX *c = _emp_kst_ensure(s, _emp_mlkem_shake128());
    EMP_MLKEM_CHECK(EVP_DigestUpdate(c, s->absorbed, s->absorbed_len), "EVP_DigestUpdate");
    if (s->produced == 0) {
        /* The stream starts here: no earlier bytes to skip. */
        EMP_MLKEM_CHECK(EVP_DigestFinalXOF(c, out, need), "EVP_DigestFinalXOF");
    } else {
        uint8_t *tmp = (uint8_t *)malloc(total);
        if (tmp == NULL) EMP_MLKEM_DIE("malloc in shake128_squeezeblocks");
        EMP_MLKEM_CHECK(EVP_DigestFinalXOF(c, tmp, total), "EVP_DigestFinalXOF");
        memcpy(out, tmp + s->produced, need);
        free(tmp);
    }
    s->produced = (uint32_t)total;
#endif
}

/* One-shot SHAKE-256 PRF: out = SHAKE256(key || nonce). Called from
 * verbatim kyber/poly.c via the `prf` macro below. Hot path —
 * thread-local ctx amortises EVP_MD_CTX_new/free across calls. */
static inline void kyber_shake256_prf(uint8_t *out, size_t outlen,
                                       const uint8_t key[KYBER_SYMBYTES],
                                       uint8_t nonce) {
    static EMP_MLKEM_TLS EVP_MD_CTX *ctx = NULL;
    if (ctx == NULL) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) EMP_MLKEM_DIE("EVP_MD_CTX_new in kyber_shake256_prf");
    }
    uint8_t extkey[KYBER_SYMBYTES + 1];
    memcpy(extkey, key, KYBER_SYMBYTES);
    extkey[KYBER_SYMBYTES] = nonce;
    EMP_MLKEM_CHECK(EVP_DigestInit_ex(ctx, _emp_mlkem_shake256(), NULL), "EVP_DigestInit_ex");
    EMP_MLKEM_CHECK(EVP_DigestUpdate(ctx, extkey, sizeof(extkey)), "EVP_DigestUpdate");
    EMP_MLKEM_CHECK(EVP_DigestFinalXOF(ctx, out, outlen), "EVP_DigestFinalXOF");
}

#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)

/* One-shot SHAKE-256: out = SHAKE256(in). Used by our own
 * derive_subseed, sid_index_to_matrix_seed and hash_to_polyvec. */
static inline void shake256(uint8_t *out, size_t outlen,
                             const uint8_t *in, size_t inlen) {
    static EMP_MLKEM_TLS EVP_MD_CTX *ctx = NULL;
    if (ctx == NULL) {
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) EMP_MLKEM_DIE("EVP_MD_CTX_new in shake256");
    }
    EMP_MLKEM_CHECK(EVP_DigestInit_ex(ctx, _emp_mlkem_shake256(), NULL), "EVP_DigestInit_ex");
    EMP_MLKEM_CHECK(EVP_DigestUpdate(ctx, in, inlen), "EVP_DigestUpdate");
    EMP_MLKEM_CHECK(EVP_DigestFinalXOF(ctx, out, outlen), "EVP_DigestFinalXOF");
}

#ifdef __cplusplus
}
#endif

#endif  /* EMP_MLKEM_SYMMETRIC_H */
