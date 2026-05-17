#ifndef EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
#define EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__

// Recursive O(q) butterfly fold for the SoftSpoken small-field VOLE
// inner loop. Q AES outputs materialize into a tile-local stack scratch
// A[Q][T]; a k-round in-place XOR halving over the leaf axis then emits
// the v_planes (sender) or w_planes (receiver) and u using only register
// XOR work (no per-leaf plane memory RMW). AES generation goes through
// emp-tool's emp::aes_ctr_fill_dm<T> — Davies–Meyer / CRH under a public
// session key, with the XOR-back done in-register inside aes_tiles_src.
//
// Algorithm (Roy '22 §VOLE, "Efficient Computation"):
//   r_x = AES_K(b0+j ⊕ leaves[x]) ⊕ b0+j ⊕ leaves[x]    where K = session
//   u   = ⊕_x r_x
//   v_b = ⊕_{x : bit_b(x) = 1} r_x          for b ∈ [0, k)   (sender)
//   w_b = ⊕_{x ≠ α : bit_b(α⊕x) = 1} r_x    for b ∈ [0, k)   (receiver)
//
// Recursive halving: round b ∈ [0, k):
//   A_{b+1}[y] = A_b[2y] ⊕ A_b[2y+1];   v_b += ⊕_y A_b[2y+1]
// After k rounds: A_k[0] = u.
//
// Receiver uses the substitution y = α ⊕ x: w_b is the v_b of the
// permuted r_y = AES_K(b0+j ⊕ leaves[α⊕y]) ⊕ b0+j ⊕ leaves[α⊕y]. The
// y=0 slot reads leaves[α] (= zero_block from pprf_eval_receiver) — its
// bogus output is folded only into u (the receiver discards it) because
// bit_b(0) = 0 for all b, so the v_b / w_b outputs are unaffected.
//
// Tile size T=8 (j-axis). Sized so the q×T scratch fits in L1 and
// butterfly_halve's v_acc[T] (the dominant register-pressure term)
// stays within the SIMD register budget on every backend — NEON's
// 32 q-regs as well as x86 VAES-512 / VAES-256 zmm/ymm pools. T much
// past 8 spills.

#include <emp-tool/emp-tool.h>
#include <cstdint>

namespace emp { namespace softspoken {

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

    // Session domain-separation lives in the AES key (session_K), so
    // the per-leaf plaintext tweak is just leaves[x] directly.
    AES_KEY session_K;
    AES_set_encrypt_key(makeBlock(0LL, (int64_t)session), &session_K);

    alignas(16) block A[Q][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        for (int x = 0; x < Q; ++x)
            emp::aes_ctr_fill_dm<T>(A[x], b0 + t0, &session_K, leaves[x]);
        butterfly_halve<k, T>(
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

    // tweaks[] is leaves rearranged into y-order so the inner loop has
    // sequential access. Session domain-separation lives in the AES
    // key, not the plaintext.
    alignas(16) block tweaks[Q];
    for (int y = 0; y < Q; ++y) tweaks[y] = leaves[alpha ^ y];

    AES_KEY session_K;
    AES_set_encrypt_key(makeBlock(0LL, (int64_t)session), &session_K);

    alignas(16) block A[Q][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        for (int y = 0; y < Q; ++y)
            emp::aes_ctr_fill_dm<T>(A[y], b0 + t0, &session_K, tweaks[y]);
        butterfly_halve<k, T>(
            A, w_planes_chunk + t0, /*v_stride=*/bs, n_valid);
        // u (= A[0][..]) is not output for receiver.
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
