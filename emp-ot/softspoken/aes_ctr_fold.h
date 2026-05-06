#ifndef EMP_SOFTSPOKEN_AES_CTR_FOLD_H__
#define EMP_SOFTSPOKEN_AES_CTR_FOLD_H__

// Fused AES-CTR + multi-target XOR-fold kernel for SoftSpoken's small-
// field VOLE inner loop. Computes
//   for j in [0, n_blocks):
//     ct = AES_K(makeBlock(0, base_ctr + j) ⊕ tweak)
//     for t in [0, N_TARGETS): tgts[t][j] ^= ct
// keeping `ct` in SIMD registers from AES last-round through the
// multi-target XOR-store — no intermediate r_x[bs] scratch is ever
// materialized in memory.
//
// `key` is a session-shared fixed AES schedule (caller hoists out of
// the per-leaf loop). `tweak` is the per-leaf input that distinguishes
// leaves and session — typically `leaves[x] ⊕ session_xor`. Treats
// AES_K as a random permutation, matching the PRP/CCRH model in
// emp-tool.
//
// Replaces the older
//   {fill r_x with counters; ParaEnc(r_x); for t: tgts[t] ^= r_x;}
// pattern, which round-tripped r_x through L1 four times per leaf
// (CTR fill, AES read, AES write, fold reads). For SoftSpoken's k=8
// chunk this saves ~128 KB of L1 traffic per leaf.
//
// Specific to SoftSpoken: the multi-target shape (N_TARGETS up to 1+k
// = 9 at k=8) only makes sense for the v_planes / w_planes fold of
// small-field VOLE. Lives next to softspoken_ot.h rather than in
// emp-tool aes.h for that reason.

#include <emp-tool/emp-tool.h>
#include <cstdint>

namespace emp { namespace softspoken {

#ifdef __x86_64__
namespace detail {

// AES-CTR plaintext blocks: each 128-bit block has high-64 = 0,
// low-64 = sequential counter starting at base.
EMP_AES_TARGET_ATTR static inline block       ctr_x1(int64_t base) {
    return _mm_set_epi64x(0, base);
}
#if EMP_AES_HAS_VAES256
EMP_AES_TARGET_ATTR static inline __m256i     ctr_x2(int64_t base) {
    return _mm256_set_epi64x(0, base + 1, 0, base);
}
#endif
#if EMP_AES_HAS_VAES512
EMP_AES_TARGET_ATTR static inline __m512i     ctr_x4(int64_t base) {
    return _mm512_set_epi64(0, base + 3, 0, base + 2,
                            0, base + 1, 0, base);
}
#endif

// Tile-loop parameterized by lane width W ∈ {1, 2, 4} and target count.
// The W tiles match the VAES512 / VAES256 / AES-NI tier widths.
template <int N_TARGETS>
EMP_AES_TARGET_ATTR
static inline void fold_tiles_x1(block* const tgts[N_TARGETS],
                                 int n_tiles, int64_t base_ctr,
                                 const AES_KEY* kk, block tweak) {
    block rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = kk->rd_key[r];
    const block tw = tweak;
    for (int t = 0; t < n_tiles; ++t) {
        block pt = _mm_xor_si128(ctr_x1(base_ctr + t), tw);
        pt = _mm_xor_si128(pt, rk[0]);
        for (int r = 1; r < 10; ++r) pt = _mm_aesenc_si128(pt, rk[r]);
        pt = _mm_aesenclast_si128(pt, rk[10]);
        for (int j = 0; j < N_TARGETS; ++j) {
            block v = _mm_loadu_si128((const __m128i*)(tgts[j] + t));
            v = _mm_xor_si128(v, pt);
            _mm_storeu_si128((__m128i*)(tgts[j] + t), v);
        }
    }
}

#if EMP_AES_HAS_VAES256
template <int N_TARGETS>
EMP_AES_TARGET_ATTR
static inline void fold_tiles_x2(block* const tgts[N_TARGETS],
                                 int n_tiles, int64_t base_ctr,
                                 const AES_KEY* kk, block tweak) {
    __m256i rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = _mm256_broadcastsi128_si256(kk->rd_key[r]);
    const __m256i tw = _mm256_broadcastsi128_si256(tweak);
    for (int t = 0; t < n_tiles; ++t) {
        __m256i pt = _mm256_xor_si256(ctr_x2(base_ctr + (int64_t)t * 2), tw);
        pt = _mm256_xor_si256(pt, rk[0]);
        for (int r = 1; r < 10; ++r) pt = _mm256_aesenc_epi128(pt, rk[r]);
        pt = _mm256_aesenclast_epi128(pt, rk[10]);
        const size_t off = (size_t)t * 2;
        for (int j = 0; j < N_TARGETS; ++j) {
            __m256i v = _mm256_loadu_si256((const __m256i*)(tgts[j] + off));
            v = _mm256_xor_si256(v, pt);
            _mm256_storeu_si256((__m256i*)(tgts[j] + off), v);
        }
    }
}
#endif

#if EMP_AES_HAS_VAES512
template <int N_TARGETS>
EMP_AES_TARGET_ATTR
static inline void fold_tiles_x4(block* const tgts[N_TARGETS],
                                 int n_tiles, int64_t base_ctr,
                                 const AES_KEY* kk, block tweak) {
    __m512i rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = _mm512_broadcast_i32x4(kk->rd_key[r]);
    const __m512i tw = _mm512_broadcast_i32x4(tweak);
    for (int t = 0; t < n_tiles; ++t) {
        __m512i pt = _mm512_xor_si512(ctr_x4(base_ctr + (int64_t)t * 4), tw);
        pt = _mm512_xor_si512(pt, rk[0]);
        for (int r = 1; r < 10; ++r) pt = _mm512_aesenc_epi128(pt, rk[r]);
        pt = _mm512_aesenclast_epi128(pt, rk[10]);
        const size_t off = (size_t)t * 4;
        for (int j = 0; j < N_TARGETS; ++j) {
            __m512i v = _mm512_loadu_si512((const __m512i*)(tgts[j] + off));
            v = _mm512_xor_si512(v, pt);
            _mm512_storeu_si512((__m512i*)(tgts[j] + off), v);
        }
    }
}
#endif

}  // namespace detail

// Public entry point. Per-call tile schedule mirrors ParaEnc<1, N>:
// VAES512 4-tiles → VAES256 2-tiles → AES-NI 1-tiles.
template <int N_TARGETS>
EMP_AES_TARGET_ATTR
inline void aes_ctr_fold(block* const tgts_in[N_TARGETS], int n_blocks,
                         int64_t base_ctr, const AES_KEY* key, block tweak) {
    block* tgts[N_TARGETS];
    for (int j = 0; j < N_TARGETS; ++j) tgts[j] = tgts_in[j];
    int64_t ctr = base_ctr;

#if EMP_AES_HAS_VAES512
    {
        const int n4 = n_blocks / 4;
        if (n4 > 0) {
            detail::fold_tiles_x4<N_TARGETS>(tgts, n4, ctr, key, tweak);
            const int b = n4 * 4;
            for (int j = 0; j < N_TARGETS; ++j) tgts[j] += b;
            ctr += b; n_blocks -= b;
        }
    }
#endif
#if EMP_AES_HAS_VAES256
    {
        const int n2 = n_blocks / 2;
        if (n2 > 0) {
            detail::fold_tiles_x2<N_TARGETS>(tgts, n2, ctr, key, tweak);
            const int b = n2 * 2;
            for (int j = 0; j < N_TARGETS; ++j) tgts[j] += b;
            ctr += b; n_blocks -= b;
        }
    }
#endif
    if (n_blocks > 0) {
        detail::fold_tiles_x1<N_TARGETS>(tgts, n_blocks, ctr, key, tweak);
    }
}

#elif __aarch64__

// NEON path: hold T=4 plaintexts in registers across the round loop,
// then fold into N_TARGETS destinations. Tail (n_blocks % 4) handled
// per-block.
template <int N_TARGETS>
inline void aes_ctr_fold(block* const tgts_in[N_TARGETS], int n_blocks,
                         int64_t base_ctr, const AES_KEY* key, block tweak) {
    constexpr int T = 4;
    const int n_full = n_blocks / T;
    const int tail   = n_blocks - n_full * T;
    const uint8x16_t tw = vreinterpretq_u8_m128i(tweak);

    for (int t = 0; t < n_full; ++t) {
        const int64_t base = base_ctr + (int64_t)t * T;
        uint8x16_t pt[T];
        for (int j = 0; j < T; ++j) {
            uint64_t lo = (uint64_t)(base + j);
            const uint8x16_t ctr =
                vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
            pt[j] = veorq_u8(ctr, tw);
        }
        for (unsigned int r = 0; r < 9; ++r) {
            uint8x16_t K = vreinterpretq_u8_m128i(key->rd_key[r]);
            for (int j = 0; j < T; ++j) pt[j] = vaesmcq_u8(vaeseq_u8(pt[j], K));
        }
        {
            uint8x16_t K  = vreinterpretq_u8_m128i(key->rd_key[9]);
            uint8x16_t K2 = vreinterpretq_u8_m128i(key->rd_key[10]);
            for (int j = 0; j < T; ++j) pt[j] = veorq_u8(vaeseq_u8(pt[j], K), K2);
        }
        for (int n = 0; n < N_TARGETS; ++n) {
            uint8_t* dst = (uint8_t*)(tgts_in[n] + (size_t)t * T);
            for (int j = 0; j < T; ++j) {
                uint8x16_t cur = vld1q_u8(dst + j * 16);
                cur = veorq_u8(cur, pt[j]);
                vst1q_u8(dst + j * 16, cur);
            }
        }
    }
    for (int t = 0; t < tail; ++t) {
        const int64_t off = (int64_t)n_full * T + t;
        uint64_t lo = (uint64_t)(base_ctr + off);
        const uint8x16_t ctr =
            vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
        uint8x16_t pt = veorq_u8(ctr, tw);
        for (unsigned int r = 0; r < 9; ++r) {
            uint8x16_t K = vreinterpretq_u8_m128i(key->rd_key[r]);
            pt = vaesmcq_u8(vaeseq_u8(pt, K));
        }
        uint8x16_t K  = vreinterpretq_u8_m128i(key->rd_key[9]);
        uint8x16_t K2 = vreinterpretq_u8_m128i(key->rd_key[10]);
        pt = veorq_u8(vaeseq_u8(pt, K), K2);
        for (int n = 0; n < N_TARGETS; ++n) {
            uint8_t* dst = (uint8_t*)(tgts_in[n] + off);
            uint8x16_t cur = vld1q_u8(dst);
            cur = veorq_u8(cur, pt);
            vst1q_u8(dst, cur);
        }
    }
}

#endif

// Dispatch on runtime target count `n` into the compile-time-N
// aes_ctr_fold<N> instantiation. n ∈ [1, 1+k]; cases past 1+k are
// discarded via `if constexpr` so unused instantiations aren't emitted
// for low-k builds. SoftSpoken's k ∈ {2, 4, 8} ⇒ N_MAX ∈ {3, 5, 9}.
template <int k>
EMP_AES_TARGET_ATTR
inline void dispatch_ctr_fold(block** tgts, int n, int n_blocks,
                              int64_t base_ctr, const AES_KEY* key,
                              block tweak) {
    constexpr int N_MAX = 1 + k;
    switch (n) {
        case 1: aes_ctr_fold<1>(tgts, n_blocks, base_ctr, key, tweak); return;
        case 2: aes_ctr_fold<2>(tgts, n_blocks, base_ctr, key, tweak); return;
        case 3: if constexpr (N_MAX >= 3) { aes_ctr_fold<3>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 4: if constexpr (N_MAX >= 4) { aes_ctr_fold<4>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 5: if constexpr (N_MAX >= 5) { aes_ctr_fold<5>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 6: if constexpr (N_MAX >= 6) { aes_ctr_fold<6>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 7: if constexpr (N_MAX >= 7) { aes_ctr_fold<7>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 8: if constexpr (N_MAX >= 8) { aes_ctr_fold<8>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 9: if constexpr (N_MAX >= 9) { aes_ctr_fold<9>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
    }
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_AES_CTR_FOLD_H__
