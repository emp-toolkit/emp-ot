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
// Tile size T=8 (j-axis). Sized so the q×T scratch fits in L1 and
// butterfly_halve's v_acc[T] (the dominant register-pressure term)
// stays within the SIMD register budget on every backend — NEON's
// 32 q-regs as well as x86 VAES-512 / VAES-256 zmm/ymm pools. T much
// past 8 spills.

#include <emp-tool/emp-tool.h>
#include <cstdint>

namespace emp { namespace softspoken {

namespace bfly_detail {

// Generate T AES blocks at plaintext (counter ⊕ tweak) for counters
// (b0..b0+T-1) under a session-shared fixed AES_KEY, writing the
// outputs directly to dst[0..T).
//
// `kk` is the session-shared fixed-key AES schedule (caller hoists out
// of the per-leaf loop). `tweak` is the per-leaf input that
// distinguishes leaves and session — typically `leaves[x] ^ session_xor`.
// The fixed-key AES + leaf-tweak shape mirrors libOTe's MultiKeyAES and
// the `PRP`/`CCRH` model elsewhere in emp-tool: AES_K is treated as a
// random permutation, and (counter ⊕ leaf ⊕ session) is the input.
//
// One platform body per build, picked by the widest available SIMD
// tier: NEON / VAES-512 (4 blocks/zmm) / VAES-256 (2 blocks/ymm) /
// AES-NI baseline (1 block/xmm). T must divide evenly into the chosen
// lane width — production T=8 satisfies all of them.
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
    // x86: pick the widest Lane the build can emit, encrypt T/L::N tiles
    // via emp-tool's aes_tiles_src using L::ctr_xor_tweak as the source.
  #if EMP_AES_HAS_VAES512
    using L = emp::detail::Lane512;
  #elif EMP_AES_HAS_VAES256
    using L = emp::detail::Lane256;
  #else
    using L = emp::detail::Lane128;
  #endif
    static_assert(T % L::N == 0,
                  "aes_T_blocks_to: T must be a multiple of L::N");
    const typename L::vec_t tw = L::broadcast(tweak);
    emp::detail::aes_tiles_src<L, T / L::N>(
        dst, [&](int t) { return L::ctr_xor_tweak(b0, t, tw); }, kk);
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

    // Pre-fold session into per-leaf tweaks; one session-shared fixed
    // AES schedule covers all leaf encryptions.
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
