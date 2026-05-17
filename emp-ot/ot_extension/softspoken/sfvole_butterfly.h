#ifndef EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
#define EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__

// Recursive O(q) butterfly fold for the SoftSpoken small-field VOLE
// inner loop. Round 0 is fused into the AES kernel
// (sfvole_fuse_round0_pair): two leaves' Davies–Meyer outputs are
// generated under one AES key in interleaved rounds, their pairwise
// XOR lands directly in A_round0[Q/2][T], and the v_0 plane is
// accumulated in tile-local scratch — Q leaf outputs never spill to
// memory as a full A[Q][T] scratch. The remaining k−1 halving rounds
// run in-place on A_round0[Q/2][T] via butterfly_halve<k-1, T>.
//
// Algorithm (Roy '22 §VOLE, "Efficient Computation"):
//   r_x = AES_K(b0+j ⊕ leaves[x]) ⊕ b0+j ⊕ leaves[x]    where K = session
//   u   = ⊕_x r_x
//   v_b = ⊕_{x : bit_b(x) = 1} r_x          for b ∈ [0, k)   (sender)
//   w_b = ⊕_{x ≠ α : bit_b(α⊕x) = 1} r_x    for b ∈ [0, k)   (receiver)
//
// Fused round 0 emits A_round0[y][j] = r_{2y} ⊕ r_{2y+1} and accumulates
// v_0 ^= r_{2y+1} (the "second of each pair"); both r_{2y} and r_{2y+1}
// stay in registers across the AES rounds and the fold.
//
// Recursive halving for rounds 1..k-1: round b ∈ [1, k):
//   A_b[y] = A_{b-1}[2y] ⊕ A_{b-1}[2y+1];   v_b += ⊕_y A_{b-1}[2y+1]
// After all rounds: A_round_{k-1}[0] = u.
//
// Receiver uses the substitution y = α ⊕ x: w_b is the v_b of the
// permuted r_y = AES_K(b0+j ⊕ leaves[α⊕y]) ⊕ b0+j ⊕ leaves[α⊕y]. The
// y=0 slot reads leaves[α] (= zero_block from pprf_eval_receiver) — its
// bogus output propagates only into u (which the receiver discards)
// because A_round0[0] only ever feeds the L-side of subsequent rounds.
//
// Tile size T=8 (j-axis). Sized so the (Q/2)×T scratch fits in L1 and
// butterfly_halve's v_acc[T] (the dominant register-pressure term)
// stays within the SIMD register budget on every backend.

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

// Fused round-0: produce T Davies–Meyer outputs for each of two leaves
// under the same AES_KEY, fold them pairwise into A_round0_y, and
// accumulate the second leaf's r_R into the v_0 plane accumulator.
// Both r_L and r_R stay in SIMD registers from the start of the AES
// rounds through the final fold — no per-tile A[Q][T] memory.
//
// Interleaved AES rounds (xL and xR walking through aesenc together)
// share one round-key broadcast and overlap latency.
template <int T>
EMP_AES_TARGET_ATTR
inline void sfvole_fuse_round0_pair(block* A_round0_y,
                                    block* v0_acc,
                                    int64_t counter,
                                    const AES_KEY* kk,
                                    block tweakL, block tweakR) {
#if EMP_HAS_VAES512
    using L = emp::AesLane<4>;
#elif EMP_HAS_VAES256
    using L = emp::AesLane<2>;
#else
    using L = emp::AesLane<1>;
#endif
    static_assert(T % L::N == 0,
                  "sfvole_fuse_round0_pair: T must be a multiple of L::N");

    typename L::vec_t rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = L::broadcast(kk->rd_key[r]);

    const auto twL = L::broadcast(tweakL);
    const auto twR = L::broadcast(tweakR);

    constexpr int n_tiles = T / L::N;
    for (int t = 0; t < n_tiles; ++t) {
        auto ptL = L::ctr_xor_tweak(counter, t, twL);
        auto ptR = L::ctr_xor_tweak(counter, t, twR);
        auto xL = L::xorv(ptL, rk[0]);
        auto xR = L::xorv(ptR, rk[0]);
        for (int r = 1; r < 10; ++r) {
            xL = L::aesenc(xL, rk[r]);
            xR = L::aesenc(xR, rk[r]);
        }
        xL = L::aesenclast(xL, rk[10]);
        xR = L::aesenclast(xR, rk[10]);
        // DM XOR-back in-register: r = AES(pt) ^ pt.
        auto rL = L::xorv(xL, ptL);
        auto rR = L::xorv(xR, ptR);
        // Round-0 fold: A_round0[y][t-slot] = r_L ^ r_R.
        L::store(A_round0_y + (size_t)t * L::N, L::xorv(rL, rR));
        // v_0 plane accumulator: v0_acc[t-slot] ^= r_R.
        auto v0 = L::load(v0_acc + (size_t)t * L::N);
        L::store(v0_acc + (size_t)t * L::N, L::xorv(v0, rR));
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

    // Round-0-fold output scratch: (Q/2)×T blocks. butterfly_halve runs
    // the remaining k-1 halving rounds in place on this.
    alignas(16) block A_round0[Q/2][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        alignas(16) block v0_acc[T];
        for (int jj = 0; jj < T; ++jj) v0_acc[jj] = zero_block;

        for (int y = 0; y < Q/2; ++y)
            sfvole_fuse_round0_pair<T>(A_round0[y], v0_acc,
                                        b0 + t0, &session_K,
                                        leaves[2*y], leaves[2*y + 1]);

        // Plane 0 = v_0 (the fused round's accumulator).
        block* v_dst_0 = v_planes_chunk + t0;
        for (int jj = 0; jj < n_valid; ++jj) v_dst_0[jj] = v0_acc[jj];

        // Planes 1..k-1 via the remaining halving rounds.
        butterfly_halve<k - 1, T>(A_round0,
                                   v_planes_chunk + (size_t)bs + t0,
                                   /*v_stride=*/bs, n_valid);

        // u = A_round0[0] after butterfly_halve's k-1 rounds complete.
        for (int jj = 0; jj < n_valid; ++jj)
            u_chunk[t0 + jj] = A_round0[0][jj];
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

// Receiver. Substitution y = α ⊕ x: the y=0 slot reads leaves[α]
// (= zero_block, pinned by pprf_eval_receiver). Its bogus r_L lands in
// A_round0[0]'s L-side and only ever feeds u via the L-chain of
// subsequent rounds — never accumulated into any w_b plane.
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

    alignas(16) block A_round0[Q/2][T];

    auto run_tile = [&](int64_t t0, int n_valid) {
        alignas(16) block w0_acc[T];
        for (int jj = 0; jj < T; ++jj) w0_acc[jj] = zero_block;

        for (int y = 0; y < Q/2; ++y)
            sfvole_fuse_round0_pair<T>(A_round0[y], w0_acc,
                                        b0 + t0, &session_K,
                                        tweaks[2*y], tweaks[2*y + 1]);

        // Plane 0 = w_0.
        block* w_dst_0 = w_planes_chunk + t0;
        for (int jj = 0; jj < n_valid; ++jj) w_dst_0[jj] = w0_acc[jj];

        butterfly_halve<k - 1, T>(A_round0,
                                   w_planes_chunk + (size_t)bs + t0,
                                   /*v_stride=*/bs, n_valid);

        // u (= A_round0[0] after the halving) is not output for receiver.
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) run_tile(t0, T);
    if (bs > bs_full) run_tile(bs_full, (int)(bs - bs_full));
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_BUTTERFLY_H__
