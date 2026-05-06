#ifndef EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
#define EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__

// Recursive O(q) butterfly fold for the SoftSpoken small-field VOLE
// inner loop. Replaces the leaf-major aes_ctr_fold<N_TARGETS> +
// per-target memory-RMW pattern with a register-only XOR halving.
// Cross-platform: NEON on Apple M, AES-NI / VAES-256 / VAES-512 on x86,
// each picking the widest SIMD tier the build can emit.
//
// Algorithm (Roy '22 §VOLE, "Efficient Computation"):
//   r_x = AES_K(b0+j ⊕ leaves[x] ⊕ session_xor)   for x ∈ [0, q), j ∈ [0, bs).
//   u   = ⊕_x r_x
//   v_b = ⊕_{x : bit_b(x) = 1} r_x          for b ∈ [0, k)   (sender)
//   w_b = ⊕_{x ≠ α : bit_b(α⊕x) = 1} r_x    for b ∈ [0, k)   (receiver)
//
// Recursive halving: round b ∈ [0, k):
//   A_{b+1}[y] = A_b[2y] ⊕ A_b[2y+1];   v_b += ⊕_y A_b[2y+1]
// After k rounds: A_k[0] = u.
//
// Receiver uses the substitution y = α ⊕ x: w_b is the v_b of the
// permuted r_y = AES_K(b0+j ⊕ leaves[α⊕y] ⊕ session_xor). The y=0 slot
// reads leaves[α] (= zero_block from pprf_eval_receiver) — its bogus
// AES output never appears in any w_b output because bit_b(0) = 0 for
// all b.
//
// Tile size T=8 (j-axis): picked from a sweep on Apple M at k=8
// bs=1024. T=8 fits the q×T scratch in L1 (32 KB at k=8) and the
// 8-block v_acc within NEON's 32-reg budget. Re-checked post leaf-as-
// tweak switch: T=12 is ~+4% slower (butterfly_halve's v_acc[T] is
// still the dominant register-pressure term, not the round keys);
// T=16 spills catastrophically (~2.1×). T=8 stays.
//
// On x86: T=8 fits comfortably under VAES-512 (2 zmm of plaintext + 11
// zmm round-key broadcasts = 13 / 32 zmm) and VAES-256 (4 ymm + 11
// ymm = 15 / 32 ymm in AVX-512 builds, 15 / 16 in plain AVX).

#include <emp-tool/emp-tool.h>
#include <cstdint>

namespace emp { namespace softspoken {

namespace bfly_detail {

// Generate T AES blocks at plaintext (counter ⊕ tweak) for counters
// (b0..b0+T-1) under a session-shared fixed AES_KEY, writing the
// outputs directly to dst[0..T).
//
// `kk` is the session-shared fixed-key AES schedule (caller hoists
// out of the per-leaf loop). `tweak` is the per-leaf input that
// distinguishes leaves and session — typically `leaves[x] ^ session_xor`.
// The fixed-key AES + leaf-tweak shape mirrors libOTe's MultiKeyAES and
// the `PRP`/`CCRH` model elsewhere in emp-tool: AES_K is treated as a
// random permutation, and (counter ⊕ leaf ⊕ session) is the input.
template <int T>
EMP_AES_TARGET_ATTR
inline void aes_T_blocks_to(block* dst, int64_t b0,
                            const AES_KEY* kk, block tweak) {
#if defined(__aarch64__)
    // NEON: raw vaeseq_u8 / vaesmcq_u8 (one less instruction per round
    // than _mm_aesenc_si128 via sse2neon).
    uint8x16_t v[T];
    const uint8x16_t tw = vreinterpretq_u8_m128i(tweak);
    for (int jj = 0; jj < T; ++jj) {
        const uint64_t lo = (uint64_t)(b0 + jj);
        const uint8x16_t ctr =
            vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
        v[jj] = veorq_u8(ctr, tw);
    }
    #pragma GCC unroll 9
    for (int r = 0; r < 9; ++r) {
        const uint8x16_t K = vreinterpretq_u8_m128i(kk->rd_key[r]);
        for (int jj = 0; jj < T; ++jj)
            v[jj] = vaesmcq_u8(vaeseq_u8(v[jj], K));
    }
    const uint8x16_t K9  = vreinterpretq_u8_m128i(kk->rd_key[9]);
    const uint8x16_t K10 = vreinterpretq_u8_m128i(kk->rd_key[10]);
    for (int jj = 0; jj < T; ++jj) {
        const uint8x16_t out = veorq_u8(vaeseq_u8(v[jj], K9), K10);
        vst1q_u8((uint8_t*)&dst[jj], out);
    }
#elif defined(__x86_64__)
    // x86: pick the widest VAES tier that divides T evenly.
  #if EMP_AES_HAS_VAES512
    if constexpr (T >= 4 && (T % 4) == 0) {
        constexpr int W = T / 4;
        const __m512i tw512 = _mm512_broadcast_i32x4(tweak);
        __m512i rk[11];
        for (int r = 0; r < 11; ++r)
            rk[r] = _mm512_broadcast_i32x4(kk->rd_key[r]);
        __m512i v[W];
        for (int w = 0; w < W; ++w) {
            const int64_t base = b0 + (int64_t)w * 4;
            v[w] = _mm512_set_epi64(0, base + 3, 0, base + 2,
                                    0, base + 1, 0, base);
            v[w] = _mm512_xor_si512(v[w], tw512);
            v[w] = _mm512_xor_si512(v[w], rk[0]);
        }
        for (int r = 1; r < 10; ++r)
            for (int w = 0; w < W; ++w)
                v[w] = _mm512_aesenc_epi128(v[w], rk[r]);
        for (int w = 0; w < W; ++w) {
            v[w] = _mm512_aesenclast_epi128(v[w], rk[10]);
            _mm512_storeu_si512((__m512i*)&dst[w * 4], v[w]);
        }
        return;
    }
  #endif
  #if EMP_AES_HAS_VAES256
    if constexpr (T >= 2 && (T % 2) == 0) {
        constexpr int W = T / 2;
        const __m256i tw256 = _mm256_broadcastsi128_si256(tweak);
        __m256i rk[11];
        for (int r = 0; r < 11; ++r)
            rk[r] = _mm256_broadcastsi128_si256(kk->rd_key[r]);
        __m256i v[W];
        for (int w = 0; w < W; ++w) {
            const int64_t base = b0 + (int64_t)w * 2;
            v[w] = _mm256_set_epi64x(0, base + 1, 0, base);
            v[w] = _mm256_xor_si256(v[w], tw256);
            v[w] = _mm256_xor_si256(v[w], rk[0]);
        }
        for (int r = 1; r < 10; ++r)
            for (int w = 0; w < W; ++w)
                v[w] = _mm256_aesenc_epi128(v[w], rk[r]);
        for (int w = 0; w < W; ++w) {
            v[w] = _mm256_aesenclast_epi128(v[w], rk[10]);
            _mm256_storeu_si256((__m256i*)&dst[w * 2], v[w]);
        }
        return;
    }
  #endif
    // AES-NI baseline: 1 block per xmm.
    block rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = kk->rd_key[r];
    block v[T];
    for (int jj = 0; jj < T; ++jj) {
        v[jj] = _mm_set_epi64x(0, b0 + jj);
        v[jj] = _mm_xor_si128(v[jj], tweak);
        v[jj] = _mm_xor_si128(v[jj], rk[0]);
    }
    for (int r = 1; r < 10; ++r)
        for (int jj = 0; jj < T; ++jj)
            v[jj] = _mm_aesenc_si128(v[jj], rk[r]);
    for (int jj = 0; jj < T; ++jj) {
        v[jj] = _mm_aesenclast_si128(v[jj], rk[10]);
        _mm_storeu_si128((__m128i*)&dst[jj], v[jj]);
    }
#else
    #error "sfvole_butterfly: unsupported architecture"
#endif
}

// In-place butterfly halving over A[Q][T]. Writes v_b for b ∈ [0, k)
// into v_dst[b * v_stride + 0..n_valid) (n_valid block stores per b).
// After the call A[0][0..T) holds u (caller may copy out the first
// n_valid; the rest are stale by-products).
//
// `n_valid` ≤ T: number of j-positions in this tile that are real
// chunk positions (== T for full tiles, < T for the bs-mod-T tail).
// Caller-side AES generation always fills A[..][0..T) — the v_acc
// halve still runs over all T j-positions to keep the inner loop
// shape stable; only the count of stores per plane shrinks.
template <int k, int T>
EMP_AES_TARGET_ATTR
inline void butterfly_halve(block A[][T],
                            block* v_dst, int64_t v_stride,
                            int n_valid) {
    constexpr int Q = 1 << k;
    int n = Q;
    for (int b = 0; b < k; ++b) {
        block v_acc[T];
        for (int jj = 0; jj < T; ++jj) v_acc[jj] = zero_block;
        const int half = n >> 1;
        for (int y = 0; y < half; ++y) {
            for (int jj = 0; jj < T; ++jj) {
                const block L = A[2 * y    ][jj];
                const block R = A[2 * y + 1][jj];
                v_acc[jj] = v_acc[jj] ^ R;
                A[y][jj]  = L ^ R;
            }
        }
        block* dst = v_dst + (size_t)b * v_stride;
        for (int jj = 0; jj < n_valid; ++jj)
            dst[jj] = v_acc[jj];
        n = half;
    }
}

}  // namespace bfly_detail

// Sender. T=8 is the production default. Caller-provided u_chunk[bs]
// and v_planes_chunk[k * bs] (plane-major: v_planes_chunk[d*bs + j]).
template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_butterfly(const block leaves[1 << k],
                                     uint64_t session,
                                     int64_t b0, int64_t bs,
                                     block* u_chunk,
                                     block* v_planes_chunk) {
    constexpr int Q = 1 << k;

    // Pre-fold session into per-leaf tweaks (4 KB scratch at k=8 vs the
    // 44 KB AES_KEY array the per-leaf-keyed version used). One
    // session-shared fixed AES schedule covers all leaf encryptions.
    alignas(16) block tweaks[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x) tweaks[x] = leaves[x] ^ session_xor;

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);

    alignas(16) block A[Q][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        for (int x = 0; x < Q; ++x)
            bfly_detail::aes_T_blocks_to<T>(A[x], b0 + t0, &fixed_K, tweaks[x]);
        bfly_detail::butterfly_halve<k, T>(
            A, v_planes_chunk + t0, /*v_stride=*/bs, n_valid);
        for (int jj = 0; jj < n_valid; ++jj)
            u_chunk[t0 + jj] = A[0][jj];
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

// Receiver. Substitution y = α ⊕ x: r_α (from leaves[α] = zero_block,
// pinned by pprf_eval_receiver) lands at A[0][..] and is harmlessly
// absorbed into u (which the receiver discards).
template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_butterfly(int alpha,
                                       const block leaves[1 << k],
                                       uint64_t session,
                                       int64_t b0, int64_t bs,
                                       block* w_planes_chunk) {
    constexpr int Q = 1 << k;

    alignas(16) block tweaks[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int y = 0; y < Q; ++y) tweaks[y] = leaves[alpha ^ y] ^ session_xor;

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);

    alignas(16) block A[Q][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        for (int y = 0; y < Q; ++y)
            bfly_detail::aes_T_blocks_to<T>(A[y], b0 + t0, &fixed_K, tweaks[y]);
        bfly_detail::butterfly_halve<k, T>(
            A, w_planes_chunk + t0, /*v_stride=*/bs, n_valid);
        // u (= A[0][..]) is not output for receiver.
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
