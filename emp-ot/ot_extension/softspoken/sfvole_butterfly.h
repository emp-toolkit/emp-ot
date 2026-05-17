#ifndef EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
#define EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__

// Recursive O(q) butterfly fold for the SoftSpoken small-field VOLE
// inner loop. Per-k kernel selection:
//
//   k = 8: rounds 0+1+2 fused via sfvole_fuse_round012_oct (8 leaves,
//          three halving levels in-register). butterfly_halve<5, T>
//          runs the remaining five rounds on A_round2[32][T].
//   k = 2, 4: rounds 0+1 fused via sfvole_fuse_round01_quad (4 leaves,
//          two halving levels in-register). butterfly_halve<k-2, T>
//          runs the remaining k-2 rounds on A_round1[Q/4][T] (zero
//          rounds for k=2; two for k=4).
//
// The oct kernel only pays off when there are enough oct calls per
// tile to amortize its bigger basic block + 27-vec-reg working set —
// concretely k=8 (32 oct calls / tile). For k=4 (only 2 oct calls /
// tile) the quad kernel measures faster on Intel SPR and ties on AMD
// Zen 4. For k=2 (1 quad call / tile) the oct kernel can't run at all
// (Q=4 < 8).
//
// Algorithm (Roy '22 §VOLE, "Efficient Computation"):
//   r_x = AES_K(b0+j ⊕ leaves[x]) ⊕ b0+j ⊕ leaves[x]    where K = session
//   u   = ⊕_x r_x
//   v_b = ⊕_{x : bit_b(x) = 1} r_x          for b ∈ [0, k)   (sender)
//   w_b = ⊕_{x ≠ α : bit_b(α⊕x) = 1} r_x    for b ∈ [0, k)   (receiver)
//
// Oct kernel emits per y ∈ [0, Q/8):
//   A_round2[y][j] = ⊕_{x=8y..8y+7} r_x
//   v_0 ^= r_{8y+1} ⊕ r_{8y+3} ⊕ r_{8y+5} ⊕ r_{8y+7}
//   v_1 ^= (r_{8y+2} ⊕ r_{8y+3}) ⊕ (r_{8y+6} ⊕ r_{8y+7})
//   v_2 ^= (r_{8y+4} ⊕ r_{8y+5}) ⊕ (r_{8y+6} ⊕ r_{8y+7})
// All eight r_N stay in registers across AES rounds and the three fold
// levels.
//
// Quad kernel (for k=2) emits per y ∈ [0, Q/4):
//   A_round1[y][j] = r_{4y} ⊕ r_{4y+1} ⊕ r_{4y+2} ⊕ r_{4y+3}
//   v_0 ^= r_{4y+1} ⊕ r_{4y+3}
//   v_1 ^= r_{4y+2} ⊕ r_{4y+3}
//
// Remaining halving for rounds k-2 (oct) or k-1 (quad): butterfly_halve
// runs in place on the post-fuse scratch.
//
// Receiver uses the substitution y = α ⊕ x: the y=0 slot of the
// permuted tweaks[] reads leaves[α] (= zero_block, pinned by
// pprf_eval_receiver). Its bogus r_0 lands in the A_round? entry for
// the first oct-or-quad and propagates only through L-chains to u
// (which receiver discards), never into any w_b plane.
//
// Tile size T=8 (j-axis). Per-iter live state during AES: 8 ptN +
// 8 xN + 11 broadcast round keys = 27 vec regs (oct). Fits with 5
// spare on VAES-512 (32 zmm) and NEON (32 q); narrower lanes (VAES-256
// ymm / AES-NI xmm) spill round keys to L1-hot stack (~1 cycle per
// round per stream extra, amortized over AES throughput).

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
        block* dst = v_dst + b * v_stride;
        for (int jj = 0; jj < n_valid; ++jj)
            dst[jj] = v_acc[jj];
        n = half;
    }
}

// Fused rounds 0 + 1 + 2: produce T Davies–Meyer outputs for each of
// eight leaves under the same AES_KEY, fold through three halving
// levels in-register, and accumulate v_0 / v_1 / v_2 plane updates.
template <int T>
EMP_AES_TARGET_ATTR
inline void sfvole_fuse_round012_oct(block* A_round2_y,
                                     block* v0_acc,
                                     block* v1_acc,
                                     block* v2_acc,
                                     int64_t counter,
                                     const AES_KEY* kk,
                                     block tweak0, block tweak1,
                                     block tweak2, block tweak3,
                                     block tweak4, block tweak5,
                                     block tweak6, block tweak7) {
#if EMP_HAS_VAES512
    using L = emp::AesLane<4>;
#elif EMP_HAS_VAES256
    using L = emp::AesLane<2>;
#else
    using L = emp::AesLane<1>;
#endif
    static_assert(T % L::N == 0,
                  "sfvole_fuse_round012_oct: T must be a multiple of L::N");

    typename L::vec_t rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = L::broadcast(kk->rd_key[r]);

    const auto tw0 = L::broadcast(tweak0);
    const auto tw1 = L::broadcast(tweak1);
    const auto tw2 = L::broadcast(tweak2);
    const auto tw3 = L::broadcast(tweak3);
    const auto tw4 = L::broadcast(tweak4);
    const auto tw5 = L::broadcast(tweak5);
    const auto tw6 = L::broadcast(tweak6);
    const auto tw7 = L::broadcast(tweak7);

    constexpr int n_tiles = T / L::N;
    for (int t = 0; t < n_tiles; ++t) {
        auto pt0 = L::ctr_xor_tweak(counter, t, tw0);
        auto pt1 = L::ctr_xor_tweak(counter, t, tw1);
        auto pt2 = L::ctr_xor_tweak(counter, t, tw2);
        auto pt3 = L::ctr_xor_tweak(counter, t, tw3);
        auto pt4 = L::ctr_xor_tweak(counter, t, tw4);
        auto pt5 = L::ctr_xor_tweak(counter, t, tw5);
        auto pt6 = L::ctr_xor_tweak(counter, t, tw6);
        auto pt7 = L::ctr_xor_tweak(counter, t, tw7);
        auto x0 = L::xorv(pt0, rk[0]);
        auto x1 = L::xorv(pt1, rk[0]);
        auto x2 = L::xorv(pt2, rk[0]);
        auto x3 = L::xorv(pt3, rk[0]);
        auto x4 = L::xorv(pt4, rk[0]);
        auto x5 = L::xorv(pt5, rk[0]);
        auto x6 = L::xorv(pt6, rk[0]);
        auto x7 = L::xorv(pt7, rk[0]);
        for (int r = 1; r < 10; ++r) {
            x0 = L::aesenc(x0, rk[r]);
            x1 = L::aesenc(x1, rk[r]);
            x2 = L::aesenc(x2, rk[r]);
            x3 = L::aesenc(x3, rk[r]);
            x4 = L::aesenc(x4, rk[r]);
            x5 = L::aesenc(x5, rk[r]);
            x6 = L::aesenc(x6, rk[r]);
            x7 = L::aesenc(x7, rk[r]);
        }
        x0 = L::aesenclast(x0, rk[10]);
        x1 = L::aesenclast(x1, rk[10]);
        x2 = L::aesenclast(x2, rk[10]);
        x3 = L::aesenclast(x3, rk[10]);
        x4 = L::aesenclast(x4, rk[10]);
        x5 = L::aesenclast(x5, rk[10]);
        x6 = L::aesenclast(x6, rk[10]);
        x7 = L::aesenclast(x7, rk[10]);
        // DM XOR-back in-register.
        auto r0 = L::xorv(x0, pt0);
        auto r1 = L::xorv(x1, pt1);
        auto r2 = L::xorv(x2, pt2);
        auto r3 = L::xorv(x3, pt3);
        auto r4 = L::xorv(x4, pt4);
        auto r5 = L::xorv(x5, pt5);
        auto r6 = L::xorv(x6, pt6);
        auto r7 = L::xorv(x7, pt7);

        // Round-0 v_0 update: v_0 ^= r_{1,3,5,7} (second of each pair).
        {
            auto v0 = L::load(v0_acc + t * L::N);
            auto sum_odd = L::xorv(L::xorv(r1, r3), L::xorv(r5, r7));
            L::store(v0_acc + t * L::N, L::xorv(v0, sum_odd));
        }
        // Round-0 fold:
        //   p0 = r0 ⊕ r1    p1 = r2 ⊕ r3
        //   p2 = r4 ⊕ r5    p3 = r6 ⊕ r7
        auto p0 = L::xorv(r0, r1);
        auto p1 = L::xorv(r2, r3);
        auto p2 = L::xorv(r4, r5);
        auto p3 = L::xorv(r6, r7);

        // Round-1 v_1 update: v_1 ^= p1 ⊕ p3 (second of each pair).
        {
            auto v1 = L::load(v1_acc + t * L::N);
            L::store(v1_acc + t * L::N,
                     L::xorv(v1, L::xorv(p1, p3)));
        }
        // Round-1 fold:
        //   q0 = p0 ⊕ p1    q1 = p2 ⊕ p3
        auto q0 = L::xorv(p0, p1);
        auto q1 = L::xorv(p2, p3);

        // Round-2 v_2 update: v_2 ^= q1.
        {
            auto v2 = L::load(v2_acc + t * L::N);
            L::store(v2_acc + t * L::N, L::xorv(v2, q1));
        }
        // Round-2 fold: A_round2[y][t-slot] = q0 ⊕ q1.
        L::store(A_round2_y + t * L::N, L::xorv(q0, q1));
    }
}

// Fused rounds 0 + 1 (4-leaf quad). Used by k=2 only (Q=4 too short
// for the octet kernel). Same shape as the oct above, dropped to two
// fold levels.
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
        auto r0 = L::xorv(x0, pt0);
        auto r1 = L::xorv(x1, pt1);
        auto r2 = L::xorv(x2, pt2);
        auto r3 = L::xorv(x3, pt3);
        auto pair0 = L::xorv(r0, r1);
        auto pair1 = L::xorv(r2, r3);
        {
            auto v0 = L::load(v0_acc + t * L::N);
            L::store(v0_acc + t * L::N,
                     L::xorv(v0, L::xorv(r1, r3)));
        }
        {
            auto v1 = L::load(v1_acc + t * L::N);
            L::store(v1_acc + t * L::N, L::xorv(v1, pair1));
        }
        L::store(A_round1_y + t * L::N, L::xorv(pair0, pair1));
    }
}

// Sender. T=8 is the production default. Caller-provided u_chunk[bs]
// and v_planes_chunk[k * bs] (plane-major: v_planes_chunk[d*bs + j]).
//
// Kernel selection: k=8 uses the 8-leaf oct kernel (fuses rounds
// 0+1+2) — the win compounds with the L1 footprint reduction at
// Q=256. k=2 and k=4 use the 4-leaf quad kernel (fuses rounds 0+1)
// — the oct kernel's larger basic block + 27-vec-reg working set
// hurts the small-Q cases (only 1 or 2 oct calls per tile, not
// enough to amortize the µop-cache pressure).
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

    if constexpr (k <= 4) {
        // Quad path. A_round1[Q/4][T]: post-quad scratch.
        // butterfly_halve<k-2, T> runs the remaining k-2 rounds
        // (zero rounds for k=2, two for k=4).
        block A_round1[Q/4][T];

        auto run_tile = [&](int64_t t0, int n_valid) {
            block v0_acc[T];
            block v1_acc[T];
            for (int jj = 0; jj < T; ++jj) {
                v0_acc[jj] = zero_block;
                v1_acc[jj] = zero_block;
            }

            for (int y = 0; y < Q/4; ++y)
                sfvole_fuse_round01_quad<T>(A_round1[y], v0_acc, v1_acc,
                                             b0 + t0, &session_K,
                                             leaves[4*y    ], leaves[4*y + 1],
                                             leaves[4*y + 2], leaves[4*y + 3]);

            block* v_dst_0 = v_planes_chunk + t0;
            block* v_dst_1 = v_planes_chunk + bs + t0;
            for (int jj = 0; jj < n_valid; ++jj) {
                v_dst_0[jj] = v0_acc[jj];
                v_dst_1[jj] = v1_acc[jj];
            }

            if constexpr (k > 2) {
                butterfly_halve<k - 2, T>(A_round1,
                                           v_planes_chunk + 2*bs + t0,
                                           /*v_stride=*/bs, n_valid);
            }
            for (int jj = 0; jj < n_valid; ++jj)
                u_chunk[t0 + jj] = A_round1[0][jj];
        };

        const int64_t bs_full = (bs / T) * T;
        for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
        if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
        return;
    } else {
        // k >= 8: oct path. A_round2[Q/8][T] is post-octet scratch;
        // butterfly_halve<k-3, T> runs the remaining k-3 halving rounds.
        block A_round2[Q/8][T];

        auto run_tile = [&](int64_t t0, int n_valid) {
            block v0_acc[T];
            block v1_acc[T];
            block v2_acc[T];
            for (int jj = 0; jj < T; ++jj) {
                v0_acc[jj] = zero_block;
                v1_acc[jj] = zero_block;
                v2_acc[jj] = zero_block;
            }

            for (int y = 0; y < Q/8; ++y)
                sfvole_fuse_round012_oct<T>(A_round2[y], v0_acc, v1_acc, v2_acc,
                                             b0 + t0, &session_K,
                                             leaves[8*y    ], leaves[8*y + 1],
                                             leaves[8*y + 2], leaves[8*y + 3],
                                             leaves[8*y + 4], leaves[8*y + 5],
                                             leaves[8*y + 6], leaves[8*y + 7]);

            // Planes 0, 1, 2 from the oct's in-register accumulators.
            block* v_dst_0 = v_planes_chunk + t0;
            block* v_dst_1 = v_planes_chunk + bs + t0;
            block* v_dst_2 = v_planes_chunk + 2*bs + t0;
            for (int jj = 0; jj < n_valid; ++jj) {
                v_dst_0[jj] = v0_acc[jj];
                v_dst_1[jj] = v1_acc[jj];
                v_dst_2[jj] = v2_acc[jj];
            }

            butterfly_halve<k - 3, T>(A_round2,
                                       v_planes_chunk + 3*bs + t0,
                                       /*v_stride=*/bs, n_valid);
            for (int jj = 0; jj < n_valid; ++jj)
                u_chunk[t0 + jj] = A_round2[0][jj];
        };

        const int64_t bs_full = (bs / T) * T;
        for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
        if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
    }
}

// Receiver. Substitution y = α ⊕ x: the y=0 slot's tweak reads
// leaves[α] (= zero_block). Its bogus r_0 lands in A_round?[0]'s
// L-chain only and propagates into u (which receiver discards), never
// into any w_b plane.
template <int k, int T = 8>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_butterfly(int alpha,
                                       const block leaves[1 << k],
                                       uint64_t session,
                                       int64_t b0, int64_t bs,
                                       block* w_planes_chunk) {
    constexpr int Q = 1 << k;
    static_assert(k >= 2, "sfvole_receiver_butterfly: k must be >= 2");

    block tweaks[Q];
    for (int y = 0; y < Q; ++y) tweaks[y] = leaves[alpha ^ y];

    AES_KEY session_K;
    AES_set_encrypt_key(makeBlock(0LL, (int64_t)session), &session_K);

    if constexpr (k <= 4) {
        // Quad path. A_round1[Q/4][T] post-quad scratch.
        block A_round1[Q/4][T];

        auto run_tile = [&](int64_t t0, int n_valid) {
            block w0_acc[T];
            block w1_acc[T];
            for (int jj = 0; jj < T; ++jj) {
                w0_acc[jj] = zero_block;
                w1_acc[jj] = zero_block;
            }

            for (int y = 0; y < Q/4; ++y)
                sfvole_fuse_round01_quad<T>(A_round1[y], w0_acc, w1_acc,
                                             b0 + t0, &session_K,
                                             tweaks[4*y    ], tweaks[4*y + 1],
                                             tweaks[4*y + 2], tweaks[4*y + 3]);

            block* w_dst_0 = w_planes_chunk + t0;
            block* w_dst_1 = w_planes_chunk + bs + t0;
            for (int jj = 0; jj < n_valid; ++jj) {
                w_dst_0[jj] = w0_acc[jj];
                w_dst_1[jj] = w1_acc[jj];
            }

            if constexpr (k > 2) {
                butterfly_halve<k - 2, T>(A_round1,
                                           w_planes_chunk + 2*bs + t0,
                                           /*v_stride=*/bs, n_valid);
            }
            // u (= A_round1[0]) discarded.
        };

        const int64_t bs_full = (bs / T) * T;
        for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
        if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
        return;
    } else {
        // k >= 8: oct path.
        block A_round2[Q/8][T];

        auto run_tile = [&](int64_t t0, int n_valid) {
            block w0_acc[T];
            block w1_acc[T];
            block w2_acc[T];
            for (int jj = 0; jj < T; ++jj) {
                w0_acc[jj] = zero_block;
                w1_acc[jj] = zero_block;
                w2_acc[jj] = zero_block;
            }

            for (int y = 0; y < Q/8; ++y)
                sfvole_fuse_round012_oct<T>(A_round2[y], w0_acc, w1_acc, w2_acc,
                                             b0 + t0, &session_K,
                                             tweaks[8*y    ], tweaks[8*y + 1],
                                             tweaks[8*y + 2], tweaks[8*y + 3],
                                             tweaks[8*y + 4], tweaks[8*y + 5],
                                             tweaks[8*y + 6], tweaks[8*y + 7]);

            block* w_dst_0 = w_planes_chunk + t0;
            block* w_dst_1 = w_planes_chunk + bs + t0;
            block* w_dst_2 = w_planes_chunk + 2*bs + t0;
            for (int jj = 0; jj < n_valid; ++jj) {
                w_dst_0[jj] = w0_acc[jj];
                w_dst_1[jj] = w1_acc[jj];
                w_dst_2[jj] = w2_acc[jj];
            }

            butterfly_halve<k - 3, T>(A_round2,
                                       w_planes_chunk + 3*bs + t0,
                                       /*v_stride=*/bs, n_valid);
            // u (= A_round2[0]) discarded.
        };

        const int64_t bs_full = (bs / T) * T;
        for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
        if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
    }
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
