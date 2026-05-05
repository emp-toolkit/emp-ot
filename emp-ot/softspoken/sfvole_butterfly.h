#ifndef EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
#define EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__

// Recursive O(q) butterfly fold for the SoftSpoken small-field VOLE
// inner loop, NEON specialization. Replaces the leaf-major
// aes_ctr_fold<N_TARGETS> + per-target memory-RMW pattern with a
// register-only XOR halving, halving the chunk-time on Apple M at k=8.
//
// Algorithm (Roy '22 §VOLE, "Efficient Computation"):
//   r_x = AES_{leaves[x] ⊕ session_xor}(b0+j) for x ∈ [0, q), j ∈ [0, bs).
//   u   = ⊕_x r_x
//   v_b = ⊕_{x : bit_b(x) = 1} r_x          for b ∈ [0, k)   (sender)
//   w_b = ⊕_{x ≠ α : bit_b(α⊕x) = 1} r_x    for b ∈ [0, k)   (receiver)
//
// Recursive halving: round b ∈ [0, k):
//   A_{b+1}[y] = A_b[2y] ⊕ A_b[2y+1];   v_b += ⊕_y A_b[2y+1]
// After k rounds: A_k[0] = u.
//
// Receiver uses the substitution y = α ⊕ x: w_b is the v_b of the
// permuted r_y = AES_{leaves[α ⊕ y]}. The y=0 slot reads leaves[α]
// (= zero_block from pprf_eval_receiver) — its bogus AES output never
// appears in any w_b output because bit_b(0) = 0 for all b.
//
// Tile size T=8 (j-axis): picked from a sweep on Apple M at k=8
// bs=1024. Larger T amortizes the per-tile butterfly setup over more
// outputs; T=8 fits the q×T scratch in L1 (32 KB at k=8) and the
// 8-block v_acc within NEON's 32-reg budget.

#include <emp-tool/emp-tool.h>
#include <cstdint>
#include <cstring>

#if defined(__aarch64__)

namespace emp { namespace softspoken {

namespace bfly_detail {

// Generate T AES blocks at counters (b0..b0+T-1) from a pre-expanded
// AES_KEY into pt[T] NEON registers. Caller's responsibility to write
// pt[] back to memory if it wants to retain them.
template <int T>
EMP_AES_TARGET_ATTR
inline void aes_T_blocks(uint8x16_t pt[T], int64_t b0, const AES_KEY* kk) {
    for (int jj = 0; jj < T; ++jj) {
        const uint64_t lo = (uint64_t)(b0 + jj);
        pt[jj] = vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
    }
    #pragma GCC unroll 9
    for (int r = 0; r < 9; ++r) {
        const uint8x16_t K = vreinterpretq_u8_m128i(kk->rd_key[r]);
        for (int jj = 0; jj < T; ++jj)
            pt[jj] = vaesmcq_u8(vaeseq_u8(pt[jj], K));
    }
    const uint8x16_t K9  = vreinterpretq_u8_m128i(kk->rd_key[9]);
    const uint8x16_t K10 = vreinterpretq_u8_m128i(kk->rd_key[10]);
    for (int jj = 0; jj < T; ++jj)
        pt[jj] = veorq_u8(vaeseq_u8(pt[jj], K9), K10);
}

// In-place butterfly halving over A[Q][T]. Writes v_b for b ∈ [0, k)
// into v_dst[b * v_stride + 0..T) (T 16-byte stores per b). After
// the call A[0][0..T) holds u (caller may copy out).
template <int k, int T>
EMP_AES_TARGET_ATTR
inline void butterfly_halve(block A[][T],
                            block* v_dst, int64_t v_stride) {
    constexpr int Q = 1 << k;
    int n = Q;
    for (int b = 0; b < k; ++b) {
        uint8x16_t v_acc[T];
        for (int jj = 0; jj < T; ++jj) v_acc[jj] = vdupq_n_u8(0);
        const int half = n >> 1;
        for (int y = 0; y < half; ++y) {
            for (int jj = 0; jj < T; ++jj) {
                const uint8x16_t L = vld1q_u8((uint8_t*)&A[2*y    ][jj]);
                const uint8x16_t R = vld1q_u8((uint8_t*)&A[2*y + 1][jj]);
                v_acc[jj] = veorq_u8(v_acc[jj], R);
                vst1q_u8((uint8_t*)&A[y][jj], veorq_u8(L, R));
            }
        }
        block* dst = v_dst + (size_t)b * v_stride;
        for (int jj = 0; jj < T; ++jj)
            vst1q_u8((uint8_t*)&dst[jj], v_acc[jj]);
        n = half;
    }
}

}  // namespace bfly_detail

// Sender. T=8 is the production default — tuned on Apple M at k=8.
// Caller-provided u_chunk[bs] and v_planes_chunk[k * bs] (plane-major).
template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_butterfly(const block leaves[1 << k],
                                     uint64_t session,
                                     int64_t b0, int64_t bs,
                                     block* u_chunk,
                                     block* v_planes_chunk) {
    constexpr int Q = 1 << k;

    // Hoist AES key expansion. ~44 KB at k=8 stack — comfortable.
    alignas(16) AES_KEY keys[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x)
        AES_set_encrypt_key(leaves[x] ^ session_xor, &keys[x]);

    alignas(16) block A[Q][T];

    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        for (int x = 0; x < Q; ++x) {
            uint8x16_t pt[T];
            bfly_detail::aes_T_blocks<T>(pt, b0 + t0, &keys[x]);
            for (int jj = 0; jj < T; ++jj)
                vst1q_u8((uint8_t*)&A[x][jj], pt[jj]);
        }

        bfly_detail::butterfly_halve<k, T>(
            A, v_planes_chunk + t0, /*v_stride=*/bs);

        // u = A[0][0..T-1].
        for (int jj = 0; jj < T; ++jj) {
            const uint8x16_t u_val = vld1q_u8((uint8_t*)&A[0][jj]);
            vst1q_u8((uint8_t*)&u_chunk[t0 + jj], u_val);
        }
    }
}

// Receiver. Substitution y = α ⊕ x: r_α (= AES_{zero_block} since
// pprf_eval_receiver pinned leaves[α] to zero_block) lands at A[0][..]
// and is harmlessly absorbed into u (which we discard).
template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_butterfly(int alpha,
                                       const block leaves[1 << k],
                                       uint64_t session,
                                       int64_t b0, int64_t bs,
                                       block* w_planes_chunk) {
    constexpr int Q = 1 << k;

    // Hoist α-permuted AES key expansion: keys[y] = expanded leaves[α ⊕ y].
    alignas(16) AES_KEY keys[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int y = 0; y < Q; ++y)
        AES_set_encrypt_key(leaves[alpha ^ y] ^ session_xor, &keys[y]);

    alignas(16) block A[Q][T];

    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        for (int y = 0; y < Q; ++y) {
            uint8x16_t pt[T];
            bfly_detail::aes_T_blocks<T>(pt, b0 + t0, &keys[y]);
            for (int jj = 0; jj < T; ++jj)
                vst1q_u8((uint8_t*)&A[y][jj], pt[jj]);
        }

        bfly_detail::butterfly_halve<k, T>(
            A, w_planes_chunk + t0, /*v_stride=*/bs);
        // u (= A[0][..]) is not output for receiver.
    }
}

}}  // namespace emp::softspoken

#endif  // __aarch64__

#if defined(__x86_64__)

namespace emp { namespace softspoken {

namespace bfly_detail {

// AES-NI scalar tile: one AES key, T plaintext blocks per call.
// EMP_AES_TARGET_ATTR widens function-level ISA to at least aes+sse2;
// callers may run on hardware supporting VAES512 / VAES256 too — the
// AES-NI scalar instruction is compatible with all AVX tiers, so the
// kernel works everywhere a VAES path would.
template <int T>
EMP_AES_TARGET_ATTR
inline void aes_T_blocks_x86(__m128i pt[T], int64_t b0, const AES_KEY* kk) {
    for (int jj = 0; jj < T; ++jj)
        pt[jj] = _mm_set_epi64x(0, b0 + jj);

    const __m128i K0 = kk->rd_key[0];
    for (int jj = 0; jj < T; ++jj) pt[jj] = _mm_xor_si128(pt[jj], K0);

    #pragma GCC unroll 9
    for (int r = 1; r < 10; ++r) {
        const __m128i K = kk->rd_key[r];
        for (int jj = 0; jj < T; ++jj) pt[jj] = _mm_aesenc_si128(pt[jj], K);
    }
    const __m128i Klast = kk->rd_key[10];
    for (int jj = 0; jj < T; ++jj) pt[jj] = _mm_aesenclast_si128(pt[jj], Klast);
}

// Same butterfly halve as NEON, with SSE intrinsics.
template <int k, int T>
EMP_AES_TARGET_ATTR
inline void butterfly_halve_x86(block A[][T],
                                 block* v_dst, int64_t v_stride) {
    constexpr int Q = 1 << k;
    int n = Q;
    for (int b = 0; b < k; ++b) {
        __m128i v_acc[T];
        for (int jj = 0; jj < T; ++jj) v_acc[jj] = _mm_setzero_si128();
        const int half = n >> 1;
        for (int y = 0; y < half; ++y) {
            for (int jj = 0; jj < T; ++jj) {
                const __m128i L = _mm_load_si128((const __m128i*)&A[2*y    ][jj]);
                const __m128i R = _mm_load_si128((const __m128i*)&A[2*y + 1][jj]);
                v_acc[jj] = _mm_xor_si128(v_acc[jj], R);
                _mm_store_si128((__m128i*)&A[y][jj], _mm_xor_si128(L, R));
            }
        }
        block* dst = v_dst + (size_t)b * v_stride;
        for (int jj = 0; jj < T; ++jj)
            _mm_store_si128((__m128i*)&dst[jj], v_acc[jj]);
        n = half;
    }
}

}  // namespace bfly_detail

template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_butterfly(const block leaves[1 << k],
                                     uint64_t session,
                                     int64_t b0, int64_t bs,
                                     block* u_chunk,
                                     block* v_planes_chunk) {
    constexpr int Q = 1 << k;

    alignas(16) AES_KEY keys[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x)
        AES_set_encrypt_key(leaves[x] ^ session_xor, &keys[x]);

    alignas(16) block A[Q][T];

    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        for (int x = 0; x < Q; ++x) {
            __m128i pt[T];
            bfly_detail::aes_T_blocks_x86<T>(pt, b0 + t0, &keys[x]);
            for (int jj = 0; jj < T; ++jj)
                _mm_store_si128((__m128i*)&A[x][jj], pt[jj]);
        }

        bfly_detail::butterfly_halve_x86<k, T>(
            A, v_planes_chunk + t0, /*v_stride=*/bs);

        for (int jj = 0; jj < T; ++jj) {
            const __m128i u_val = _mm_load_si128((const __m128i*)&A[0][jj]);
            _mm_store_si128((__m128i*)&u_chunk[t0 + jj], u_val);
        }
    }
}

template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_butterfly(int alpha,
                                       const block leaves[1 << k],
                                       uint64_t session,
                                       int64_t b0, int64_t bs,
                                       block* w_planes_chunk) {
    constexpr int Q = 1 << k;

    alignas(16) AES_KEY keys[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int y = 0; y < Q; ++y)
        AES_set_encrypt_key(leaves[alpha ^ y] ^ session_xor, &keys[y]);

    alignas(16) block A[Q][T];

    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        for (int y = 0; y < Q; ++y) {
            __m128i pt[T];
            bfly_detail::aes_T_blocks_x86<T>(pt, b0 + t0, &keys[y]);
            for (int jj = 0; jj < T; ++jj)
                _mm_store_si128((__m128i*)&A[y][jj], pt[jj]);
        }

        bfly_detail::butterfly_halve_x86<k, T>(
            A, w_planes_chunk + t0, /*v_stride=*/bs);
    }
}

}}  // namespace emp::softspoken

#endif  // __x86_64__

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
