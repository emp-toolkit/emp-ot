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
// 8-block v_acc within NEON's 32-reg budget. Re-checked post leaf-as-
// tweak switch: T=12 is ~+4% slower (butterfly_halve's v_acc[T] is
// still the dominant register-pressure term, not the round keys);
// T=16 spills catastrophically (~2.1×). T=8 stays.

#include <emp-tool/emp-tool.h>
#include <cstdint>

#if defined(__aarch64__)

namespace emp { namespace softspoken {

namespace bfly_detail {

// Generate T AES blocks at plaintext (counter ⊕ tweak) for counters
// (b0..b0+T-1) under a pre-expanded fixed AES_KEY into pt[T] NEON
// registers. Caller's responsibility to write pt[] back to memory if
// it wants to retain them.
//
// `kk` is the session-shared fixed-key AES schedule (caller hoists out
// of the per-leaf loop). `tweak` is the per-leaf input that
// distinguishes leaves and session — typically `leaves[x] ^ session_xor`.
// The fixed-key AES + leaf-tweak shape mirrors libOTe's MultiKeyAES and
// the `PRP`/`CCRH` model elsewhere in emp-tool: AES_K is treated as a
// random permutation, and (counter ⊕ leaf ⊕ session) is the input.
template <int T>
EMP_AES_TARGET_ATTR
inline void aes_T_blocks(uint8x16_t pt[T], int64_t b0,
                         const AES_KEY* kk, block tweak) {
    const uint8x16_t tw = vreinterpretq_u8_m128i(tweak);
    for (int jj = 0; jj < T; ++jj) {
        const uint64_t lo = (uint64_t)(b0 + jj);
        const uint8x16_t ctr =
            vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
        pt[jj] = veorq_u8(ctr, tw);
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
// into v_dst[b * v_stride + 0..n_valid) (n_valid 16-byte stores per b).
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
        for (int jj = 0; jj < n_valid; ++jj)
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

    // Pre-fold session into per-leaf tweaks. 4 KB scratch at k=8 (vs the
    // 44 KB AES_KEY array the per-leaf-keyed version used). Round keys
    // come from a single fixed-key AES schedule built once below; that
    // schedule lives in registers across the entire chunk.
    alignas(16) block tweaks[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x) tweaks[x] = leaves[x] ^ session_xor;

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);

    alignas(16) block A[Q][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        for (int x = 0; x < Q; ++x) {
            uint8x16_t pt[T];
            bfly_detail::aes_T_blocks<T>(pt, b0 + t0, &fixed_K, tweaks[x]);
            for (int jj = 0; jj < T; ++jj)
                vst1q_u8((uint8_t*)&A[x][jj], pt[jj]);
        }

        bfly_detail::butterfly_halve<k, T>(
            A, v_planes_chunk + t0, /*v_stride=*/bs, n_valid);

        for (int jj = 0; jj < n_valid; ++jj) {
            const uint8x16_t u_val = vld1q_u8((uint8_t*)&A[0][jj]);
            vst1q_u8((uint8_t*)&u_chunk[t0 + jj], u_val);
        }
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
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

    // α-permuted tweaks: tweaks[y] = leaves[α ⊕ y] ⊕ session_xor.
    // Same fixed-key AES + leaf-tweak shape as the sender; see notes
    // there. y=0 uses leaves[α] = zero_block (set by pprf_eval_receiver),
    // so r_α lands at A[0][..] — bogus AES output, but it's absorbed
    // into u which the receiver discards.
    alignas(16) block tweaks[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int y = 0; y < Q; ++y) tweaks[y] = leaves[alpha ^ y] ^ session_xor;

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);

    alignas(16) block A[Q][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        for (int y = 0; y < Q; ++y) {
            uint8x16_t pt[T];
            bfly_detail::aes_T_blocks<T>(pt, b0 + t0, &fixed_K, tweaks[y]);
            for (int jj = 0; jj < T; ++jj)
                vst1q_u8((uint8_t*)&A[y][jj], pt[jj]);
        }
        bfly_detail::butterfly_halve<k, T>(
            A, w_planes_chunk + t0, /*v_stride=*/bs, n_valid);
        // u (= A[0][..]) is not output for receiver.
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

}}  // namespace emp::softspoken

#endif  // __aarch64__

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
