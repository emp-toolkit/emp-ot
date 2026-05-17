#ifndef EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
#define EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__

// Recursive O(q) butterfly fold for the SoftSpoken small-field VOLE
// inner loop. Rounds 0 + 1 are fused into the AES kernel
// (sfvole_fuse_round01_quad): four leaves' Davies–Meyer outputs are
// generated under one AES key in interleaved rounds; their two-level
// XOR fold lands directly in A_round1[Q/4][T], and the v_0 / v_1
// planes are accumulated in tile-local scratch — Q leaf outputs never
// spill to memory as a full A[Q][T] scratch. The remaining k-2 halving
// rounds (none for k=2) run in-place on A_round1[Q/4][T].
//
// Algorithm (Roy '22 §VOLE, "Efficient Computation"):
//   r_x = AES_K(b0+j ⊕ leaves[x]) ⊕ b0+j ⊕ leaves[x]    where K = session
//   u   = ⊕_x r_x
//   v_b = ⊕_{x : bit_b(x) = 1} r_x          for b ∈ [0, k)   (sender)
//   w_b = ⊕_{x ≠ α : bit_b(α⊕x) = 1} r_x    for b ∈ [0, k)   (receiver)
//
// Fused quad: for each y ∈ [0, Q/4) the kernel produces
//   A_round1[y][j] = r_{4y} ⊕ r_{4y+1} ⊕ r_{4y+2} ⊕ r_{4y+3}
// and accumulates
//   v_0 ^= r_{4y+1} ⊕ r_{4y+3}      (round-0 "second-of-pair" sum)
//   v_1 ^= r_{4y+2} ⊕ r_{4y+3}      (round-1 "second-of-pair")
// All four r_N stay in registers across AES rounds and the two fold
// levels.
//
// Remaining halving for rounds 2..k-1: butterfly_halve<k-2, T> runs in
// place on A_round1[Q/4][T]; round b ∈ [2, k):
//   A_b[y] = A_{b-1}[2y] ⊕ A_{b-1}[2y+1];   v_b += ⊕_y A_{b-1}[2y+1]
// After all rounds: A_round_{k-1}[0] = u. For k=2 the quad fully
// consumes the q-axis (Q/4 = 1); no butterfly_halve call is needed.
//
// Receiver uses the substitution y = α ⊕ x: w_b is the v_b of the
// permuted r_y = AES_K(b0+j ⊕ leaves[α⊕y]) ⊕ b0+j ⊕ leaves[α⊕y]. The
// y=0 slot reads leaves[α] (= zero_block, pinned by pprf_eval_receiver)
// — its bogus r_0 lands in A_round1[0]'s L-chain only (via the
// pair0 = r_0 ⊕ r_1 path) and never accumulates into any w_b plane;
// it propagates into u only, which the receiver discards.
//
// Tile size T=8 (j-axis). Sized so the (Q/4)×T scratch fits in L1 and
// the kernel's per-iter working set (4 ptN + 4 xN + 11 broadcast round
// keys = 19 vec regs) stays within VAES-512 / VAES-256 / AES-NI / NEON
// register budgets (round-key spills to L1 are tolerated on narrow
// lanes; L1-hot, ~1 cycle per round per stream).

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

// Fused rounds 0 + 1: produce T Davies–Meyer outputs for each of four
// leaves under the same AES_KEY, fold them through two halving levels
// in-register, and accumulate v_0 / v_1 plane updates. Both halving
// levels' state lives in registers from AES output through final fold
// — no per-tile A[Q][T] scratch.
//
// Interleaved AES rounds (x0..x3 walking through aesenc together)
// share one round-key broadcast. Per-iter live: 4 ptN + 4 xN +
// 11 round keys ≈ 19 vec regs. Fits comfortably on VAES-512 (32 zmm)
// and NEON (32 q-regs); narrower lanes (VAES-256 ymm / AES-NI xmm)
// spill round keys to L1-resident stack — ~1 cycle per round-key load
// per stream, amortized over the AES throughput.
template <int T>
EMP_AES_TARGET_ATTR
inline void sfvole_fuse_round01_quad(block* A_round1_y,
                                     block* v0_acc,
                                     block* v1_acc,
                                     int64_t counter,
                                     const AES_KEY* kk,
                                     block tweak0, block tweak1,
                                     block tweak2, block tweak3) {
#if EMP_HAS_VAES512
    using L = emp::AesLane<4>;
#elif EMP_HAS_VAES256
    using L = emp::AesLane<2>;
#else
    using L = emp::AesLane<1>;
#endif
    static_assert(T % L::N == 0,
                  "sfvole_fuse_round01_quad: T must be a multiple of L::N");

    typename L::vec_t rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = L::broadcast(kk->rd_key[r]);

    const auto tw0 = L::broadcast(tweak0);
    const auto tw1 = L::broadcast(tweak1);
    const auto tw2 = L::broadcast(tweak2);
    const auto tw3 = L::broadcast(tweak3);

    constexpr int n_tiles = T / L::N;
    for (int t = 0; t < n_tiles; ++t) {
        auto pt0 = L::ctr_xor_tweak(counter, t, tw0);
        auto pt1 = L::ctr_xor_tweak(counter, t, tw1);
        auto pt2 = L::ctr_xor_tweak(counter, t, tw2);
        auto pt3 = L::ctr_xor_tweak(counter, t, tw3);
        auto x0 = L::xorv(pt0, rk[0]);
        auto x1 = L::xorv(pt1, rk[0]);
        auto x2 = L::xorv(pt2, rk[0]);
        auto x3 = L::xorv(pt3, rk[0]);
        for (int r = 1; r < 10; ++r) {
            x0 = L::aesenc(x0, rk[r]);
            x1 = L::aesenc(x1, rk[r]);
            x2 = L::aesenc(x2, rk[r]);
            x3 = L::aesenc(x3, rk[r]);
        }
        x0 = L::aesenclast(x0, rk[10]);
        x1 = L::aesenclast(x1, rk[10]);
        x2 = L::aesenclast(x2, rk[10]);
        x3 = L::aesenclast(x3, rk[10]);
        // DM XOR-back in-register: r_N = AES(pt_N) ⊕ pt_N.
        auto r0 = L::xorv(x0, pt0);
        auto r1 = L::xorv(x1, pt1);
        auto r2 = L::xorv(x2, pt2);
        auto r3 = L::xorv(x3, pt3);
        // Round-0 fold (in-register, not stored):
        //   pair0 = r0 ⊕ r1  = A_round0[2y]
        //   pair1 = r2 ⊕ r3  = A_round0[2y+1]
        auto pair0 = L::xorv(r0, r1);
        auto pair1 = L::xorv(r2, r3);
        // Round-0 v_0 plane update: v_0 ^= r1 ⊕ r3 (second of each pair).
        {
            auto v0 = L::load(v0_acc + (size_t)t * L::N);
            L::store(v0_acc + (size_t)t * L::N,
                     L::xorv(v0, L::xorv(r1, r3)));
        }
        // Round-1 v_1 plane update: v_1 ^= pair1 (second of the round-0 pair).
        {
            auto v1 = L::load(v1_acc + (size_t)t * L::N);
            L::store(v1_acc + (size_t)t * L::N, L::xorv(v1, pair1));
        }
        // Round-1 fold: A_round1[y][t-slot] = pair0 ⊕ pair1.
        L::store(A_round1_y + (size_t)t * L::N, L::xorv(pair0, pair1));
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
    static_assert(k >= 2, "sfvole_sender_butterfly: k must be >= 2");

    AES_KEY session_K;
    AES_set_encrypt_key(makeBlock(0LL, (int64_t)session), &session_K);

    // A_round1[Q/4][T]: post-quad scratch. butterfly_halve<k-2> runs
    // the remaining k-2 halving rounds in place. For k=2 (Q/4=1), one
    // quad call lands u directly in A_round1[0] and no halving runs.
    alignas(16) block A_round1[Q/4][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        alignas(16) block v0_acc[T];
        alignas(16) block v1_acc[T];
        for (int jj = 0; jj < T; ++jj) {
            v0_acc[jj] = zero_block;
            v1_acc[jj] = zero_block;
        }

        for (int y = 0; y < Q/4; ++y)
            sfvole_fuse_round01_quad<T>(A_round1[y], v0_acc, v1_acc,
                                         b0 + t0, &session_K,
                                         leaves[4*y    ], leaves[4*y + 1],
                                         leaves[4*y + 2], leaves[4*y + 3]);

        // Planes 0 and 1 from the quad's in-register accumulators.
        block* v_dst_0 = v_planes_chunk + t0;
        block* v_dst_1 = v_planes_chunk + (size_t)bs + t0;
        for (int jj = 0; jj < n_valid; ++jj) {
            v_dst_0[jj] = v0_acc[jj];
            v_dst_1[jj] = v1_acc[jj];
        }

        if constexpr (k > 2) {
            // Planes 2..k-1 via the remaining halving rounds.
            butterfly_halve<k - 2, T>(A_round1,
                                       v_planes_chunk + 2*(size_t)bs + t0,
                                       /*v_stride=*/bs, n_valid);
        }

        // u = A_round1[0] (final entry after k-2 rounds; or directly
        // for k=2 since Q/4 = 1).
        for (int jj = 0; jj < n_valid; ++jj)
            u_chunk[t0 + jj] = A_round1[0][jj];
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

// Receiver. Substitution y = α ⊕ x: the y=0 slot's tweak reads
// leaves[α] (= zero_block, pinned by pprf_eval_receiver). Its bogus
// r_0 lands in pair0 = r_0 ⊕ r_1 and thus in A_round1[0]; it
// propagates only through the L-chain of subsequent halving rounds to
// u (which the receiver discards), never into any w_b plane.
template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_butterfly(int alpha,
                                       const block leaves[1 << k],
                                       uint64_t session,
                                       int64_t b0, int64_t bs,
                                       block* w_planes_chunk) {
    constexpr int Q = 1 << k;
    static_assert(k >= 2, "sfvole_receiver_butterfly: k must be >= 2");

    // tweaks[] is leaves rearranged into y-order so the inner loop has
    // sequential access. Session domain-separation lives in the AES
    // key, not the plaintext.
    alignas(16) block tweaks[Q];
    for (int y = 0; y < Q; ++y) tweaks[y] = leaves[alpha ^ y];

    AES_KEY session_K;
    AES_set_encrypt_key(makeBlock(0LL, (int64_t)session), &session_K);

    alignas(16) block A_round1[Q/4][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        alignas(16) block w0_acc[T];
        alignas(16) block w1_acc[T];
        for (int jj = 0; jj < T; ++jj) {
            w0_acc[jj] = zero_block;
            w1_acc[jj] = zero_block;
        }

        for (int y = 0; y < Q/4; ++y)
            sfvole_fuse_round01_quad<T>(A_round1[y], w0_acc, w1_acc,
                                         b0 + t0, &session_K,
                                         tweaks[4*y    ], tweaks[4*y + 1],
                                         tweaks[4*y + 2], tweaks[4*y + 3]);

        // Planes 0 (= w_0) and 1 (= w_1) from the quad's accumulators.
        block* w_dst_0 = w_planes_chunk + t0;
        block* w_dst_1 = w_planes_chunk + (size_t)bs + t0;
        for (int jj = 0; jj < n_valid; ++jj) {
            w_dst_0[jj] = w0_acc[jj];
            w_dst_1[jj] = w1_acc[jj];
        }

        if constexpr (k > 2) {
            butterfly_halve<k - 2, T>(A_round1,
                                       w_planes_chunk + 2*(size_t)bs + t0,
                                       /*v_stride=*/bs, n_valid);
        }

        // u (= A_round1[0]) is not output for receiver.
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
