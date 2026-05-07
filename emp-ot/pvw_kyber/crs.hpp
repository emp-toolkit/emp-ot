#ifndef EMP_OT_PVW_KYBER_CRS_HPP__
#define EMP_OT_PVW_KYBER_CRS_HPP__

// Common reference string (CRS) for the PVW-Kyber base OT.
//
// Inputs:  32-byte session_seed (shared by sender and receiver, e.g.
//          carried via the OT class's `block sid`).
// Outputs: A (resp. A^T) — a polyvec[K] sampled uniformly from R_q^{KxK}
//          V_b for b in {0,1} — a polyvec sampled uniformly from R_q^K
//
// All three are derived from session_seed via SHAKE-256 with one-byte
// domain-separation tags 0x01 (A), 0x02 (V_0), 0x03 (V_1). Within each
// uniform-sampling routine we reuse Kyber's own kyber_shake128_absorb
// + shake128_squeezeblocks + rejection-sampling pattern (mirroring
// indcpa.c::gen_matrix, which we don't lift).
//
// Outputs are in *coefficient* domain (not NTT). Callers apply
// polyvec_ntt before doing polyvec_basemul_acc_montgomery, and they
// only NTT once per CRS expansion.

#include "emp-ot/pvw_kyber/params.hpp"
#include <cstdint>
#include <cstring>

namespace emp { namespace pvw_kyber {

namespace crs_detail {

// Rejection-sample 12-bit values from `buf` into `r[0..n)`. Returns the
// number of values written (≤ n). Lifted in shape from indcpa.c, but
// kept local so we don't depend on indcpa.c at all.
inline int rej_uniform(int16_t *r, int n, const uint8_t *buf, int buflen) {
    int ctr = 0, pos = 0;
    while (ctr < n && pos + 3 <= buflen) {
        const uint16_t v0 = ((uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x0FFF;
        const uint16_t v1 = ((uint16_t)buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4);
        pos += 3;
        if (v0 < kQ) r[ctr++] = (int16_t)v0;
        if (ctr < n && v1 < kQ) r[ctr++] = (int16_t)v1;
    }
    return ctr;
}

// One uniform polynomial in R_q from (seed, x, y). Matches the per-cell
// shape Kyber uses in gen_matrix.
inline void poly_uniform_from_seed(poly *p,
                                   const uint8_t seed[kSymBytes],
                                   uint8_t x, uint8_t y) {
    keccak_state state;
    kyber_shake128_absorb(&state, seed, x, y);

    constexpr int kBlocks = (12 * kN / 8 + XOF_BLOCKBYTES) / XOF_BLOCKBYTES;
    uint8_t buf[kBlocks * XOF_BLOCKBYTES + 2];
    shake128_squeezeblocks(buf, kBlocks, &state);
    int buflen = kBlocks * XOF_BLOCKBYTES;
    int ctr = rej_uniform(p->coeffs, kN, buf, buflen);

    while (ctr < kN) {
        // Carry the trailing 0..2 bytes of `buf` so we don't lose state
        // bits across the squeeze boundary; squeeze one more block and
        // resume rejection sampling.
        const int off = buflen - (buflen / 3) * 3;
        for (int k = 0; k < off; ++k) buf[k] = buf[buflen - off + k];
        shake128_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(p->coeffs + ctr, kN - ctr, buf, buflen);
    }
}

// Derive a sub-seed from session_seed via SHAKE-256(session_seed || tag).
inline void derive_subseed(uint8_t out[kSymBytes],
                            const uint8_t session_seed[kSymBytes],
                            uint8_t tag) {
    uint8_t input[kSymBytes + 1];
    std::memcpy(input, session_seed, kSymBytes);
    input[kSymBytes] = tag;
    shake256(out, kSymBytes, input, sizeof(input));
}

}  // namespace crs_detail

// Expand A (or A^T) from session_seed. `transposed=true` swaps the
// (i, j) coordinate before calling the per-cell sampler — matches
// Kyber's gen_matrix flag.
inline void crs_expand_matrix(polyvec a[kK],
                               const uint8_t session_seed[kSymBytes],
                               bool transposed) {
    uint8_t seed_A[kSymBytes];
    crs_detail::derive_subseed(seed_A, session_seed, 0x01);
    for (int i = 0; i < kK; ++i) {
        for (int j = 0; j < kK; ++j) {
            const uint8_t x = transposed ? (uint8_t)i : (uint8_t)j;
            const uint8_t y = transposed ? (uint8_t)j : (uint8_t)i;
            crs_detail::poly_uniform_from_seed(&a[i].vec[j], seed_A, x, y);
        }
    }
}

// Expand V_b from session_seed (b ∈ {0, 1}; tag = 0x02 for b=0, 0x03
// for b=1). Both parties run this for both b's.
inline void crs_expand_v(polyvec *V_b,
                          const uint8_t session_seed[kSymBytes],
                          int b) {
    uint8_t seed_V[kSymBytes];
    crs_detail::derive_subseed(seed_V, session_seed, (uint8_t)(0x02 + b));
    for (int j = 0; j < kK; ++j) {
        crs_detail::poly_uniform_from_seed(&V_b->vec[j], seed_V,
                                            (uint8_t)j, (uint8_t)0);
    }
}

}}  // namespace emp::pvw_kyber

#endif  // EMP_OT_PVW_KYBER_CRS_HPP__
