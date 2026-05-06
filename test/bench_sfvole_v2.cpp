// Microbench sfvole-fold strategies for the SoftSpoken small-field
// VOLE inner loop (sender side, k=8). All variants compute the same
// (u, v_planes) from the same (leaves, session, b0, bs) inputs via
// different reduction strategies:
//
//   Current:   existing aes_ctr_fold<N_TARGETS> per leaf — narrow
//              memory-RMW XOR-stores (1 + popcount(x) per (leaf, j)).
//   View B:    lift + wide masked XOR: per-leaf wide register-
//              resident accumulator, one masked XOR per (leaf, j).
//   View A:    transpose + parallel inner products: 128 parallel
//              length-Q dot products against precomputed plane masks.
//   Butterfly: register-only XOR halving, no memory RMW in the leaf
//              inner loop (NEON Apple M k=8 path; production kernel
//              lives in emp-ot/softspoken/sfvole_butterfly.h).
//
// All variants share the same output shape (plane-major v_planes_chunk)
// and are byte-equality checked against `variant_current`.

#include <emp-tool/emp-tool.h>
#include "emp-ot/softspoken/aes_ctr_fold.h"
#include "emp-ot/softspoken/softspoken_ot.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace emp;

namespace {

double now_us() {
    using clk = std::chrono::high_resolution_clock;
    return std::chrono::duration<double, std::micro>(
               clk::now().time_since_epoch())
        .count();
}

// ---------------------------------------------------------------------
// Variant Current: dispatched kernel (whatever softspoken_ot.h selects
// for this (k, arch) — on Apple M k=8 = NEON butterfly; on x86 k=8
// with VAES-512 = View B AVX-512; otherwise = leaf-major aes_ctr_fold).
// ---------------------------------------------------------------------
template <int k>
void variant_current(const block* leaves,
                     uint64_t session, int64_t b0, int64_t bs,
                     block* u_chunk, block* v_planes_chunk) {
    softspoken::sfvole_sender_compute_chunk<k>(
        leaves, session, b0, bs, u_chunk, v_planes_chunk);
}

// ---------------------------------------------------------------------
// Variant "old aes_ctr_fold path": the pre-View-B / pre-butterfly
// leaf-major baseline. Replicates softspoken_ot.h's fallback body
// (memset → per-leaf rekey → dispatch_ctr_fold) without the dispatch.
// On AVX-512 hosts this is the apples-to-apples baseline against
// variant_b_avx512_*.
// ---------------------------------------------------------------------
template <int k>
void variant_old_path_sender(const block* leaves,
                              uint64_t session, int64_t b0, int64_t bs,
                              block* u_chunk, block* v_planes_chunk) {
    constexpr int Q = 1 << k;
    std::memset(u_chunk,         0, sizeof(block) * (size_t)bs);
    std::memset(v_planes_chunk,  0, sizeof(block) * (size_t)k * bs);

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x) {
        const block tweak = leaves[x] ^ session_xor;
        block* tgts[1 + k];
        int n = 0;
        tgts[n++] = u_chunk;
        for (int b = 0; b < k; ++b)
            if ((x >> b) & 1) tgts[n++] = v_planes_chunk + (size_t)b * bs;
        softspoken::dispatch_ctr_fold<k>(tgts, n, (int)bs, b0, &fixed_K, tweak);
    }
}

template <int k>
void variant_old_path_recv(int alpha,
                            const block* leaves,
                            uint64_t session, int64_t b0, int64_t bs,
                            block* w_planes_chunk) {
    constexpr int Q = 1 << k;
    std::memset(w_planes_chunk, 0, sizeof(block) * (size_t)k * bs);

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x) {
        if (x == alpha) continue;
        const block tweak = leaves[x] ^ session_xor;
        const int coeff = alpha ^ x;
        block* tgts[k > 0 ? k : 1];
        int n = 0;
        for (int b = 0; b < k; ++b)
            if ((coeff >> b) & 1) tgts[n++] = w_planes_chunk + (size_t)b * bs;
        softspoken::dispatch_ctr_fold<k>(tgts, n, (int)bs, b0, &fixed_K, tweak);
    }
}

// ---------------------------------------------------------------------
// Variant View B AVX-512: directly calls the View B kernel from
// sfvole_view_b.h. The production dispatcher gates this kernel on
// GenuineIntel only (AMD Zen 5 regressed on it — see sfvole_view_b.h);
// this variant exposes the kernel unconditionally for bench comparison.
// ---------------------------------------------------------------------
#if EMP_AES_HAS_VAES512
template <int k>
void variant_b_avx512_sender(const block* leaves,
                              uint64_t session, int64_t b0, int64_t bs,
                              block* u_chunk, block* v_planes_chunk) {
    softspoken::sfvole_sender_view_b<k>(
        leaves, session, b0, bs, u_chunk, v_planes_chunk);
}

template <int k>
void variant_b_avx512_recv(int alpha,
                            const block* leaves,
                            uint64_t session, int64_t b0, int64_t bs,
                            block* w_planes_chunk) {
    softspoken::sfvole_receiver_view_b<k>(
        alpha, leaves, session, b0, bs, w_planes_chunk);
}
#endif

// ---------------------------------------------------------------------
// Generate q × bs PRG outputs into a flat (q, bs) block array.
// Used by View A (and as a building block for the portable View B).
// R[x * bs + j] = AES_K(makeBlock(0, b0 + j) ⊕ leaves[x] ⊕ session_xor).
// ---------------------------------------------------------------------
template <int k>
void gen_prg_block(const block* leaves,
                   uint64_t session, int64_t b0, int64_t bs,
                   block* R) {
    constexpr int Q = 1 << k;
    const block session_xor = makeBlock(0LL, (int64_t)session);
    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);
    for (int x = 0; x < Q; ++x) {
        const block tweak = leaves[x] ^ session_xor;
        block* row = R + (size_t)x * bs;
        for (int64_t j = 0; j < bs; ++j) row[j] = makeBlock(0LL, b0 + j) ^ tweak;
        AES_ecb_encrypt_blks(row, (unsigned)bs, &fixed_K);
    }
}

// ---------------------------------------------------------------------
// View C — Recursive butterfly (Roy '22 §VOLE, "Efficient Computation").
// Algorithm:
//   Given r_x for x ∈ [0, q), output u = ⊕_x r_x and
//   v_b = ⊕_{x: bit_b(x)=1} r_x for b ∈ [0, k).
//
//   Round b=0: pair-merge A0 → A1, where A1[y] = A0[2y] ⊕ A0[2y+1].
//              v_0 = ⊕_y A0[2y+1]   (right children at this round).
//   Round b=1: pair-merge A1 → A2.
//              v_1 = ⊕_z A1[2z+1].
//   …
//   Round b=k-1: A_{k-1} has 2 entries; A_k[0] = u.
//              v_{k-1} = A_{k-1}[1].
//
// Cost per j (k=8, q=256):
//   q-1 = 255  pair-merge XORs   (halve from q to 1, register-only).
//   Σ q/2^b for b ∈ [1,k] = 255  v_b extraction XORs.
//   Total ~510 reg-XORs per j vs current's ~1280 narrow memory RMWs
//   per j (q × avg(1+k/2)).
//
// Storage: A[q][T] = q × T × 16 bytes; q=256, T=4 → 16 KB scratch
// per tile, comfortably L1-resident.
// ---------------------------------------------------------------------
#if defined(__aarch64__)
template <int k, int T>
inline void variant_butterfly_neon_sender_T(
    const block* leaves, uint64_t session, int64_t b0, int64_t bs,
    block* u_chunk, block* v_planes_chunk,
    AES_KEY* keys_scratch /* sized Q = 1<<k */) {
    constexpr int Q = 1 << k;

    // 1) Hoist AES key expansion (leaf loop is inner; per-tile re-expand
    //    would be Q*(bs/T) calls — too many).
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x)
        AES_set_encrypt_key(leaves[x] ^ session_xor, &keys_scratch[x]);

    // Tile-resident scratch for A[Q][T]. 16 KB at Q=256, T=4.
    alignas(16) block A[Q][T];

    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        // 2) AES generation: A[x][jj] = AES_x(b0 + t0 + jj).
        for (int x = 0; x < Q; ++x) {
            const AES_KEY* kk = &keys_scratch[x];
            uint8x16_t pt[T];
            for (int jj = 0; jj < T; ++jj) {
                const uint64_t lo = (uint64_t)(b0 + t0 + jj);
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
            for (int jj = 0; jj < T; ++jj) {
                pt[jj] = veorq_u8(vaeseq_u8(pt[jj], K9), K10);
                vst1q_u8((uint8_t*)&A[x][jj], pt[jj]);
            }
        }

        // 3) Butterfly: in-place halve A; v_b is XOR of right children
        //    at round b.
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
            block* vb_dst = v_planes_chunk + (size_t)b * bs + t0;
            for (int jj = 0; jj < T; ++jj)
                vst1q_u8((uint8_t*)&vb_dst[jj], v_acc[jj]);
            n = half;
        }
        // u = A[0][..]: the single remaining halved value across the T j's.
        for (int jj = 0; jj < T; ++jj) {
            const uint8x16_t u_val = vld1q_u8((uint8_t*)&A[0][jj]);
            vst1q_u8((uint8_t*)&u_chunk[t0 + jj], u_val);
        }
    }
}

// Default butterfly kernel for the bench: the production
// sfvole_sender_butterfly from emp-ot/softspoken/sfvole_butterfly.h
// (T=8 default, with bs-tail handling). The earlier in-bench duplicate
// variant_butterfly_neon_sender_T was kept for T-sweep experimentation
// (T ∈ {2, 4, 8}); T=8 won and the duplicate's missing tail-handling
// triggered spurious bench MISMATCH at bs ∈ {3, 5, 6, 7}.
template <int k>
inline void variant_butterfly_neon_sender(
    const block* leaves, uint64_t session, int64_t b0, int64_t bs,
    block* u_chunk, block* v_planes_chunk, AES_KEY* keys_scratch) {
    (void)keys_scratch;  // production kernel hoists keys internally
    softspoken::sfvole_sender_butterfly<k>(leaves, session, b0, bs,
                                            u_chunk, v_planes_chunk);
}

// Backwards-compat alias for the existing call sites.
inline void variant_butterfly_neon_k8(
    const block* leaves, uint64_t session, int64_t b0, int64_t bs,
    block* u_chunk, block* v_planes_chunk, AES_KEY* keys_scratch) {
    variant_butterfly_neon_sender<8>(leaves, session, b0, bs,
                                      u_chunk, v_planes_chunk, keys_scratch);
}

// ---------------------------------------------------------------------
// Receiver-side butterfly. The receiver wants:
//   w_b = ⊕_{x ≠ α : bit_b(α ⊕ x)=1} r_x
// Substitute y = α ⊕ x → r_x = r_{α ⊕ y}, condition is bit_b(y)=1:
//   w_b = ⊕_{y : bit_b(y)=1} r_{α ⊕ y}
// (y=0 has bit_b(0)=0 for all b, so the missing leaf x=α at y=0 never
//  contributes — which is fortunate, since the receiver doesn't know
//  leaves[α]; it's set to zero_block by pprf_eval_receiver.)
//
// Implementation: same butterfly, just permute the leaf access. We
// fill A[y] = AES_{leaves[α ⊕ y] ⊕ session_xor}(b0+t0+jj). The y=0
// position uses leaves[α] = zero_block, which produces a bogus AES
// stream — but it never appears in any w_b output (bit_b(0)=0), so
// it's harmless. We discard u (sender-only).
// ---------------------------------------------------------------------
template <int k, int T>
inline void variant_butterfly_neon_recv_T(
    int alpha,
    const block* leaves, uint64_t session, int64_t b0, int64_t bs,
    block* w_planes_chunk,
    AES_KEY* keys_scratch /* sized Q = 1<<k */) {
    constexpr int Q = 1 << k;

    // Hoist AES key expansion at the *permuted* indices: for y ∈ [0, Q),
    // expand leaves[α ⊕ y]. After this, accessing keys_scratch[y] in the
    // tile loop gets the right key for the y-indexed butterfly slot.
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int y = 0; y < Q; ++y)
        AES_set_encrypt_key(leaves[alpha ^ y] ^ session_xor, &keys_scratch[y]);

    alignas(16) block A[Q][T];

    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        // AES generation: A[y][jj] = AES_{leaves[α ⊕ y]}(b0 + t0 + jj).
        for (int y = 0; y < Q; ++y) {
            const AES_KEY* kk = &keys_scratch[y];
            uint8x16_t pt[T];
            for (int jj = 0; jj < T; ++jj) {
                const uint64_t lo = (uint64_t)(b0 + t0 + jj);
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
            for (int jj = 0; jj < T; ++jj) {
                pt[jj] = veorq_u8(vaeseq_u8(pt[jj], K9), K10);
                vst1q_u8((uint8_t*)&A[y][jj], pt[jj]);
            }
        }

        // Butterfly (no u output — receiver doesn't need it).
        int n = Q;
        for (int b = 0; b < k; ++b) {
            uint8x16_t v_acc[T];
            for (int jj = 0; jj < T; ++jj) v_acc[jj] = vdupq_n_u8(0);
            const int half = n >> 1;
            for (int yy = 0; yy < half; ++yy) {
                for (int jj = 0; jj < T; ++jj) {
                    const uint8x16_t L = vld1q_u8((uint8_t*)&A[2*yy    ][jj]);
                    const uint8x16_t R = vld1q_u8((uint8_t*)&A[2*yy + 1][jj]);
                    v_acc[jj] = veorq_u8(v_acc[jj], R);
                    vst1q_u8((uint8_t*)&A[yy][jj], veorq_u8(L, R));
                }
            }
            block* wb_dst = w_planes_chunk + (size_t)b * bs + t0;
            for (int jj = 0; jj < T; ++jj)
                vst1q_u8((uint8_t*)&wb_dst[jj], v_acc[jj]);
            n = half;
        }
    }
}

template <int k>
inline void variant_butterfly_neon_recv(
    int alpha,
    const block* leaves, uint64_t session, int64_t b0, int64_t bs,
    block* w_planes_chunk, AES_KEY* keys_scratch) {
    (void)keys_scratch;
    softspoken::sfvole_receiver_butterfly<k>(alpha, leaves, session, b0, bs,
                                              w_planes_chunk);
}
#endif  // __aarch64__

// ---------------------------------------------------------------------
// View B (NEON, k=8): tile-outer / leaf-inner.
// Holds (u, v_0..v_{k-1}) accumulators reg-resident for a tile of T=2 j's
// across all Q leaves; flushes at end of tile. Requires AES_KEY hoisting
// since the leaf loop is inner — per-tile re-expansion would balloon
// to Q*(bs/T) AES_set_encrypt_key calls.
// Per leaf, per j: 1 broadcast(x) + 8 (vshl/vshr derive masks once per
// leaf) + 1 (u XOR) + 8 (plane vand+veor).  Versus current's ~5 narrow
// memory RMWs per (leaf,j).
// ---------------------------------------------------------------------
#if defined(__aarch64__)
inline void variant_b_neon_k8(const block* leaves,
                               uint64_t session, int64_t b0, int64_t bs,
                               block* u_chunk, block* v_planes_chunk,
                               AES_KEY* keys_scratch /* unused, kept for ABI */) {
    (void)keys_scratch;
    constexpr int k = 8;
    constexpr int Q = 1 << k;   // 256
    constexpr int T = 2;        // outputs per tile in j-axis

    // Pre-fold session into per-leaf tweaks (4 KB at k=8, vs the 44 KB
    // AES_KEY array the per-leaf-keyed version used). One session-shared
    // fixed AES schedule covers all leaf encryptions.
    alignas(16) block tweaks[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x) tweaks[x] = leaves[x] ^ session_xor;

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);

    // 2) Tile-outer loop. Per tile: reg-resident accumulators across all leaves.
    for (int64_t t0 = 0; t0 < bs; t0 += T) {
        uint8x16_t u0 = vdupq_n_u8(0), u1 = vdupq_n_u8(0);
        uint8x16_t v0_0 = vdupq_n_u8(0), v0_1 = vdupq_n_u8(0);
        uint8x16_t v1_0 = vdupq_n_u8(0), v1_1 = vdupq_n_u8(0);
        uint8x16_t v2_0 = vdupq_n_u8(0), v2_1 = vdupq_n_u8(0);
        uint8x16_t v3_0 = vdupq_n_u8(0), v3_1 = vdupq_n_u8(0);
        uint8x16_t v4_0 = vdupq_n_u8(0), v4_1 = vdupq_n_u8(0);
        uint8x16_t v5_0 = vdupq_n_u8(0), v5_1 = vdupq_n_u8(0);
        uint8x16_t v6_0 = vdupq_n_u8(0), v6_1 = vdupq_n_u8(0);
        uint8x16_t v7_0 = vdupq_n_u8(0), v7_1 = vdupq_n_u8(0);

        for (int x = 0; x < Q; ++x) {
            const uint8x16_t tw = vreinterpretq_u8_m128i(tweaks[x]);

            // Generate pt[T] = AES_K(counter ⊕ tweaks[x]).
            uint8x16_t pt0, pt1;
            {
                const uint64_t lo0 = (uint64_t)(b0 + t0);
                const uint64_t lo1 = (uint64_t)(b0 + t0 + 1);
                const uint8x16_t c0 =
                    vreinterpretq_u8_u64(vsetq_lane_u64(lo0, vdupq_n_u64(0), 0));
                const uint8x16_t c1 =
                    vreinterpretq_u8_u64(vsetq_lane_u64(lo1, vdupq_n_u64(0), 0));
                pt0 = veorq_u8(c0, tw);
                pt1 = veorq_u8(c1, tw);
            }
            #pragma GCC unroll 9
            for (int r = 0; r < 9; ++r) {
                const uint8x16_t K = vreinterpretq_u8_m128i(fixed_K.rd_key[r]);
                pt0 = vaesmcq_u8(vaeseq_u8(pt0, K));
                pt1 = vaesmcq_u8(vaeseq_u8(pt1, K));
            }
            {
                const uint8x16_t K9  = vreinterpretq_u8_m128i(fixed_K.rd_key[9]);
                const uint8x16_t K10 = vreinterpretq_u8_m128i(fixed_K.rd_key[10]);
                pt0 = veorq_u8(vaeseq_u8(pt0, K9), K10);
                pt1 = veorq_u8(vaeseq_u8(pt1, K9), K10);
            }

            // Derive plane masks from x: mask_b = all-1 if bit_b(x) else all-0.
            // vshlq_n_s8(_, n) needs immediate; unroll across the 8 bits.
            const int8x16_t x_b = vreinterpretq_s8_u8(vdupq_n_u8((uint8_t)x));
            const uint8x16_t m0 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 7), 7));
            const uint8x16_t m1 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 6), 7));
            const uint8x16_t m2 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 5), 7));
            const uint8x16_t m3 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 4), 7));
            const uint8x16_t m4 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 3), 7));
            const uint8x16_t m5 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 2), 7));
            const uint8x16_t m6 = vreinterpretq_u8_s8(vshrq_n_s8(vshlq_n_s8(x_b, 1), 7));
            const uint8x16_t m7 = vreinterpretq_u8_s8(vshrq_n_s8(x_b, 7));

            // Fold pt0/pt1 into u and per-plane v accumulators.
            u0 = veorq_u8(u0, pt0); u1 = veorq_u8(u1, pt1);
            v0_0 = veorq_u8(v0_0, vandq_u8(pt0, m0));
            v0_1 = veorq_u8(v0_1, vandq_u8(pt1, m0));
            v1_0 = veorq_u8(v1_0, vandq_u8(pt0, m1));
            v1_1 = veorq_u8(v1_1, vandq_u8(pt1, m1));
            v2_0 = veorq_u8(v2_0, vandq_u8(pt0, m2));
            v2_1 = veorq_u8(v2_1, vandq_u8(pt1, m2));
            v3_0 = veorq_u8(v3_0, vandq_u8(pt0, m3));
            v3_1 = veorq_u8(v3_1, vandq_u8(pt1, m3));
            v4_0 = veorq_u8(v4_0, vandq_u8(pt0, m4));
            v4_1 = veorq_u8(v4_1, vandq_u8(pt1, m4));
            v5_0 = veorq_u8(v5_0, vandq_u8(pt0, m5));
            v5_1 = veorq_u8(v5_1, vandq_u8(pt1, m5));
            v6_0 = veorq_u8(v6_0, vandq_u8(pt0, m6));
            v6_1 = veorq_u8(v6_1, vandq_u8(pt1, m6));
            v7_0 = veorq_u8(v7_0, vandq_u8(pt0, m7));
            v7_1 = veorq_u8(v7_1, vandq_u8(pt1, m7));
        }

        // Flush.
        vst1q_u8((uint8_t*)&u_chunk[t0 + 0], u0);
        vst1q_u8((uint8_t*)&u_chunk[t0 + 1], u1);
        block* vp = v_planes_chunk;
        vst1q_u8((uint8_t*)&vp[0 * bs + t0 + 0], v0_0);
        vst1q_u8((uint8_t*)&vp[0 * bs + t0 + 1], v0_1);
        vst1q_u8((uint8_t*)&vp[1 * bs + t0 + 0], v1_0);
        vst1q_u8((uint8_t*)&vp[1 * bs + t0 + 1], v1_1);
        vst1q_u8((uint8_t*)&vp[2 * bs + t0 + 0], v2_0);
        vst1q_u8((uint8_t*)&vp[2 * bs + t0 + 1], v2_1);
        vst1q_u8((uint8_t*)&vp[3 * bs + t0 + 0], v3_0);
        vst1q_u8((uint8_t*)&vp[3 * bs + t0 + 1], v3_1);
        vst1q_u8((uint8_t*)&vp[4 * bs + t0 + 0], v4_0);
        vst1q_u8((uint8_t*)&vp[4 * bs + t0 + 1], v4_1);
        vst1q_u8((uint8_t*)&vp[5 * bs + t0 + 0], v5_0);
        vst1q_u8((uint8_t*)&vp[5 * bs + t0 + 1], v5_1);
        vst1q_u8((uint8_t*)&vp[6 * bs + t0 + 0], v6_0);
        vst1q_u8((uint8_t*)&vp[6 * bs + t0 + 1], v6_1);
        vst1q_u8((uint8_t*)&vp[7 * bs + t0 + 0], v7_0);
        vst1q_u8((uint8_t*)&vp[7 * bs + t0 + 1], v7_1);
    }
}
#endif  // __aarch64__

// ---------------------------------------------------------------------
// View B (portable): per-leaf, generate r_x[bs], then for each plane d
// XOR r_x into v_planes[d] iff bit_d(x) = 1, plus into u always.
//
// This portable expression IS what the current kernel does — the win
// only materializes when the per-plane "if bit_d(x) then XOR else
// nothing" is replaced by a single wide masked XOR (vpternlogd on
// AVX-512). For correctness check only.
// ---------------------------------------------------------------------
template <int k>
void variant_b_portable(const block* leaves,
                        uint64_t session, int64_t b0, int64_t bs,
                        block* u_chunk, block* v_planes_chunk) {
    constexpr int Q = 1 << k;
    std::memset(u_chunk, 0, sizeof(block) * bs);
    std::memset(v_planes_chunk, 0, sizeof(block) * (size_t)k * bs);

    const block session_xor = makeBlock(0LL, (int64_t)session);
    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);
    std::vector<block> r_x((size_t)bs);

    for (int x = 0; x < Q; ++x) {
        const block tweak = leaves[x] ^ session_xor;
        for (int64_t j = 0; j < bs; ++j) r_x[j] = makeBlock(0LL, b0 + j) ^ tweak;
        AES_ecb_encrypt_blks(r_x.data(), (unsigned)bs, &fixed_K);

        // Always fold into u.
        for (int64_t j = 0; j < bs; ++j) u_chunk[j] = u_chunk[j] ^ r_x[j];

        // For each plane d, fold iff bit_d(x) = 1.
        // (The wide-mask SIMD path replaces this k-loop with one fused op.)
        for (int d = 0; d < k; ++d) {
            if (((x >> d) & 1) == 0) continue;
            block* dst = v_planes_chunk + (size_t)d * bs;
            for (int64_t j = 0; j < bs; ++j) dst[j] = dst[j] ^ r_x[j];
        }
    }
}

// ---------------------------------------------------------------------
// View A (portable): generate full (q, bs) PRG block, then per j ∈ [0, bs):
//   - For each output bit i ∈ [0, 128), build l[i] = q-bit vector
//     where l[i][x] = bit_i(r_x[j]).
//   - For each plane d ∈ [0, k): bit_i(v_d[j]) = parity(l[i] AND M_d)
//     where M_d ∈ {0,1}^q has M_d[x] = bit_d(x).
//   - For u: bit_i(u[j]) = parity(l[i]).
//
// Portable version uses popcount per (j, i, d). The SIMD path replaces
// this with vectorized parity-AND (AVX-512: gfni vgf2p8affineqb folds
// all k planes per byte into one instruction).
// ---------------------------------------------------------------------
template <int k>
void variant_a_portable(const block* leaves,
                        uint64_t session, int64_t b0, int64_t bs,
                        block* u_chunk, block* v_planes_chunk) {
    constexpr int Q = 1 << k;
    static_assert(Q <= 256, "portable View A reference assumes q ≤ 256");

    // 1) Generate the full per-leaf PRG block array.
    std::vector<block> R((size_t)Q * bs);
    gen_prg_block<k>(leaves, session, b0, bs, R.data());

    // 2) Precompute the M_d masks: M_d ∈ {0,1}^Q, M_d[x] = bit_d(x).
    //    Stored as a Q-bit value packed into uint64_t halves
    //    (Q ≤ 256 → at most 4 × uint64).
    constexpr int Q_words = (Q + 63) / 64;
    uint64_t M[k][Q_words] = {{0}};
    for (int d = 0; d < k; ++d) {
        for (int x = 0; x < Q; ++x) {
            if ((x >> d) & 1) M[d][x >> 6] |= (1ULL << (x & 63));
        }
    }

    // 3) For each j, build l[128] (128 length-Q bit vectors); then for
    //    each (i, d) compute parity(l[i] AND M_d). Pack bits of v_d[j]
    //    and u[j] back into the 128-bit blocks.
    for (int64_t j = 0; j < bs; ++j) {
        // Build l[i] for i ∈ [0, 128): l[i] is Q bits, packed Q_words
        // uint64s. l[i][x] = bit_i(r_x[j]).
        uint64_t l[128][Q_words] = {{0}};
        for (int x = 0; x < Q; ++x) {
            const block r = R[(size_t)x * bs + j];
            // Extract 128 bits of r as two uint64.
            uint64_t r_lo, r_hi;
            std::memcpy(&r_lo, (const char*)&r + 0, 8);
            std::memcpy(&r_hi, (const char*)&r + 8, 8);
            const int xw = x >> 6;
            const uint64_t xbit = 1ULL << (x & 63);
            // For each bit i of r, set l[i][xw] |= xbit if bit_i(r) == 1.
            for (int i = 0; i < 64; ++i)
                if ((r_lo >> i) & 1) l[i][xw] |= xbit;
            for (int i = 0; i < 64; ++i)
                if ((r_hi >> i) & 1) l[64 + i][xw] |= xbit;
        }

        // Compute v_d[j] and u[j] from l[].
        // bit_i(v_d[j]) = parity(l[i] AND M_d).
        // bit_i(u[j])   = parity(l[i]).
        uint64_t v_lo[k] = {0}, v_hi[k] = {0};
        uint64_t u_lo = 0, u_hi = 0;
        for (int i = 0; i < 128; ++i) {
            // Parity(l[i]).
            int u_bit = 0;
            for (int w = 0; w < Q_words; ++w) u_bit ^= __builtin_popcountll(l[i][w]) & 1;
            if (i < 64) u_lo |= (uint64_t)u_bit << i;
            else        u_hi |= (uint64_t)u_bit << (i - 64);

            // Parity(l[i] AND M_d) per plane d.
            for (int d = 0; d < k; ++d) {
                int p = 0;
                for (int w = 0; w < Q_words; ++w)
                    p ^= __builtin_popcountll(l[i][w] & M[d][w]) & 1;
                if (i < 64) v_lo[d] |= (uint64_t)p << i;
                else        v_hi[d] |= (uint64_t)p << (i - 64);
            }
        }

        // Pack back into 128-bit blocks.
        block u_blk;
        std::memcpy((char*)&u_blk + 0, &u_lo, 8);
        std::memcpy((char*)&u_blk + 8, &u_hi, 8);
        u_chunk[j] = u_blk;
        for (int d = 0; d < k; ++d) {
            block v_blk;
            std::memcpy((char*)&v_blk + 0, &v_lo[d], 8);
            std::memcpy((char*)&v_blk + 8, &v_hi[d], 8);
            v_planes_chunk[(size_t)d * bs + j] = v_blk;
        }
    }
}

// ---------------------------------------------------------------------
// Equality check helpers.
// ---------------------------------------------------------------------
bool blocks_equal(const block* a, const block* b, int64_t n) {
    return std::memcmp(a, b, sizeof(block) * (size_t)n) == 0;
}

// ---------------------------------------------------------------------
// Bench harness: run `iters` calls of `fn`, return median microseconds.
// ---------------------------------------------------------------------
template <typename F>
double bench_median_us(int iters, int trials, F&& fn) {
    std::vector<double> samples((size_t)trials);
    for (int t = 0; t < trials; ++t) {
        double t0 = now_us();
        for (int i = 0; i < iters; ++i) fn();
        samples[(size_t)t] = (now_us() - t0) / iters;
    }
    std::sort(samples.begin(), samples.end());
    return samples[(size_t)trials / 2];
}

// =====================================================================
// Receiver-side bench. The current kernel is sfvole_receiver_compute_chunk;
// the butterfly variant is variant_butterfly_neon_recv. Compare against
// the current at k ∈ {2, 4, 8}.
// =====================================================================
template <int k>
void run_one_k_recv(int64_t bs, bool include_neon) {
    constexpr int Q = 1 << k;

    PRG seed_prg(fix_key);
    std::vector<block> leaves((size_t)Q);
    seed_prg.random_block(leaves.data(), Q);
    // Pretend a punctured leaf: emulate eval_receiver by zeroing leaves[α].
    const int alpha = 13 % Q;
    leaves[alpha] = zero_block;
    const uint64_t session = 0x12345678abcdULL;
    const int64_t b0 = 0;

    std::vector<block> w_cur((size_t)k * bs);
    std::vector<block> w_old((size_t)k * bs);
    std::vector<block> w_bfly((size_t)k * bs);
    std::vector<block> w_avx((size_t)k * bs);
    std::vector<AES_KEY> keys_scratch((size_t)Q);

    softspoken::sfvole_receiver_compute_chunk<k>(
        alpha, leaves.data(), session, b0, bs, w_cur.data());
    variant_old_path_recv<k>(alpha, leaves.data(), session, b0, bs, w_old.data());
    bool eq_old = blocks_equal(w_cur.data(), w_old.data(), (int64_t)k * bs);

#if defined(__aarch64__)
    bool eq_recv = true;
    if (include_neon) {
        variant_butterfly_neon_recv<k>(alpha, leaves.data(), session, b0, bs,
                                        w_bfly.data(), keys_scratch.data());
        eq_recv = blocks_equal(w_cur.data(), w_bfly.data(), (int64_t)k * bs);
    }
#else
    (void)include_neon; (void)w_bfly; (void)keys_scratch;
    bool eq_recv = true;
#endif
#if EMP_AES_HAS_VAES512
    bool eq_avx = true;
    if constexpr (k == 8) {
        variant_b_avx512_recv<k>(alpha, leaves.data(), session, b0, bs,
                                  w_avx.data());
        eq_avx = blocks_equal(w_cur.data(), w_avx.data(), (int64_t)k * bs);
    }
#else
    (void)w_avx;
#endif

    std::printf("RECV k=%d bs=%lld   old: w=%s   bfly: w=%s",
                k, (long long)bs,
                eq_old ? "OK" : "MISMATCH",
                eq_recv ? "OK" : "MISMATCH");
#if EMP_AES_HAS_VAES512
    if (k == 8) std::printf("   B-avx512: w=%s", eq_avx ? "OK" : "MISMATCH");
#endif
    std::printf("\n");
    if (!eq_old || !eq_recv) {
        std::fprintf(stderr, "RECV byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }
#if EMP_AES_HAS_VAES512
    if (k == 8 && !eq_avx) {
        std::fprintf(stderr, "RECV B-avx512 byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }
#endif

#ifdef NDEBUG
    const int iters  = std::max(1, (int)(2'000'000 / std::max<int64_t>(1, bs * Q)));
    const int trials = 5;
#else
    const int iters  = 1;
    const int trials = 1;
#endif
    auto fn_cur = [&]() {
        softspoken::sfvole_receiver_compute_chunk<k>(
            alpha, leaves.data(), session, b0, bs, w_cur.data());
    };
    auto fn_old = [&]() {
        variant_old_path_recv<k>(alpha, leaves.data(), session, b0, bs, w_old.data());
    };
    double cur_us = bench_median_us(iters, trials, fn_cur);
    double old_us = bench_median_us(iters, trials, fn_old);
    double bfly_us = -1, avx_us = -1;
#if defined(__aarch64__)
    if (include_neon) {
        auto fn_bfly = [&]() {
            variant_butterfly_neon_recv<k>(alpha, leaves.data(), session, b0, bs,
                                            w_bfly.data(), keys_scratch.data());
        };
        bfly_us = bench_median_us(iters, trials, fn_bfly);
    }
#endif
#if EMP_AES_HAS_VAES512
    if constexpr (k == 8) {
        auto fn_avx = [&]() {
            variant_b_avx512_recv<k>(alpha, leaves.data(), session, b0, bs, w_avx.data());
        };
        avx_us = bench_median_us(iters, trials, fn_avx);
    }
#endif

    std::printf("RECV k=%d bs=%lld iters=%d   current=%9.2f us   old=%9.2f us (%.2fx)",
                k, (long long)bs, iters, cur_us,
                old_us, old_us / cur_us);
    if (bfly_us > 0)
        std::printf("   bfly=%9.2f us (%.2fx)", bfly_us, bfly_us / cur_us);
    if (avx_us > 0)
        std::printf("   B-avx512=%9.2f us (%.2fx vs current; %.2fx vs old)",
                    avx_us, avx_us / cur_us, avx_us / old_us);
    std::printf("\n");
}

template <int k>
void run_one_k(int64_t bs, bool include_neon) {
    constexpr int Q = 1 << k;

    // Inputs.
    PRG seed_prg(fix_key);
    std::vector<block> leaves((size_t)Q);
    seed_prg.random_block(leaves.data(), Q);
    const uint64_t session = 0x12345678abcdULL;
    const int64_t b0 = 0;

    // Outputs (one buffer per variant).
    std::vector<block> u_cur((size_t)bs), u_b((size_t)bs), u_a((size_t)bs);
    std::vector<block> v_cur((size_t)k * bs), v_b((size_t)k * bs), v_a((size_t)k * bs);
    std::vector<block> u_old((size_t)bs), v_old((size_t)k * bs);
    std::vector<block> u_neon((size_t)bs), v_neon((size_t)k * bs);
    std::vector<block> u_bfly((size_t)bs), v_bfly((size_t)k * bs);
    std::vector<block> u_avx((size_t)bs), v_avx((size_t)k * bs);
    std::vector<AES_KEY> keys_scratch((size_t)Q);

    // 1) Run portable variants once and compare.
    variant_current<k>(leaves.data(), session, b0, bs, u_cur.data(), v_cur.data());
    variant_old_path_sender<k>(leaves.data(), session, b0, bs, u_old.data(), v_old.data());
    variant_b_portable<k>(leaves.data(), session, b0, bs, u_b.data(),   v_b.data());
    variant_a_portable<k>(leaves.data(), session, b0, bs, u_a.data(),   v_a.data());

    bool eq_old_u = blocks_equal(u_cur.data(), u_old.data(), bs);
    bool eq_old_v = blocks_equal(v_cur.data(), v_old.data(), (int64_t)k * bs);
    bool eq_b_u = blocks_equal(u_cur.data(), u_b.data(), bs);
    bool eq_b_v = blocks_equal(v_cur.data(), v_b.data(), (int64_t)k * bs);
    bool eq_a_u = blocks_equal(u_cur.data(), u_a.data(), bs);
    bool eq_a_v = blocks_equal(v_cur.data(), v_a.data(), (int64_t)k * bs);

#if defined(__aarch64__)
    bool eq_bfly_u = true, eq_bfly_v = true;
    if (include_neon) {
        variant_butterfly_neon_sender<k>(leaves.data(), session, b0, bs,
                                          u_bfly.data(), v_bfly.data(), keys_scratch.data());
        eq_bfly_u = blocks_equal(u_cur.data(), u_bfly.data(), bs);
        eq_bfly_v = blocks_equal(v_cur.data(), v_bfly.data(), (int64_t)k * bs);
    }
    bool eq_neon_u = true, eq_neon_v = true;
    // variant_b_neon_k8 is bench-only and uses T=2 without tail handling;
    // skip it for odd bs to avoid spurious MISMATCH from buffer-end spillover.
    const bool run_neon_b = (include_neon && k == 8 && (bs % 2) == 0);
    if (run_neon_b) {
        variant_b_neon_k8(leaves.data(), session, b0, bs,
                          u_neon.data(), v_neon.data(), keys_scratch.data());
        eq_neon_u = blocks_equal(u_cur.data(), u_neon.data(), bs);
        eq_neon_v = blocks_equal(v_cur.data(), v_neon.data(), (int64_t)k * bs);
    }
#else
    (void)include_neon; (void)u_neon; (void)v_neon; (void)u_bfly; (void)v_bfly; (void)keys_scratch;
#endif

#if EMP_AES_HAS_VAES512
    bool eq_avx_u = true, eq_avx_v = true;
    if constexpr (k == 8) {
        variant_b_avx512_sender<k>(leaves.data(), session, b0, bs,
                                    u_avx.data(), v_avx.data());
        eq_avx_u = blocks_equal(u_cur.data(), u_avx.data(), bs);
        eq_avx_v = blocks_equal(v_cur.data(), v_avx.data(), (int64_t)k * bs);
    }
#else
    (void)u_avx; (void)v_avx;
#endif

    std::printf("k=%d bs=%lld   old: u=%s v=%s   B-port: u=%s v=%s   A-port: u=%s v=%s",
                k, (long long)bs,
                eq_old_u ? "OK" : "MISMATCH", eq_old_v ? "OK" : "MISMATCH",
                eq_b_u ? "OK" : "MISMATCH", eq_b_v ? "OK" : "MISMATCH",
                eq_a_u ? "OK" : "MISMATCH", eq_a_v ? "OK" : "MISMATCH");
#if defined(__aarch64__)
    if (include_neon) {
        std::printf("   bfly: u=%s v=%s",
                    eq_bfly_u ? "OK" : "MISMATCH", eq_bfly_v ? "OK" : "MISMATCH");
        if (run_neon_b)
            std::printf("   B-neon: u=%s v=%s",
                        eq_neon_u ? "OK" : "MISMATCH", eq_neon_v ? "OK" : "MISMATCH");
    }
#endif
#if EMP_AES_HAS_VAES512
    if (k == 8)
        std::printf("   B-avx512: u=%s v=%s",
                    eq_avx_u ? "OK" : "MISMATCH", eq_avx_v ? "OK" : "MISMATCH");
#endif
    std::printf("\n");

    if (!(eq_old_u && eq_old_v && eq_b_u && eq_b_v && eq_a_u && eq_a_v)) {
        std::fprintf(stderr, "portable byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }
#if defined(__aarch64__)
    if (include_neon && !(eq_bfly_u && eq_bfly_v)) {
        std::fprintf(stderr, "NEON butterfly byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }
    if (run_neon_b && !(eq_neon_u && eq_neon_v)) {
        std::fprintf(stderr, "NEON View B byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }
#endif
#if EMP_AES_HAS_VAES512
    if (k == 8 && !(eq_avx_u && eq_avx_v)) {
        std::fprintf(stderr, "AVX-512 View B byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }
#endif

    // 2) Time each (median of 5 trials × `iters` per trial).
#ifdef NDEBUG
    const int iters  = std::max(1, (int)(2'000'000 / std::max<int64_t>(1, bs * Q)));
    const int trials = 5;
#else
    const int iters  = 1;
    const int trials = 1;
#endif
    auto fn_cur = [&]() {
        variant_current<k>(leaves.data(), session, b0, bs, u_cur.data(), v_cur.data());
    };
    auto fn_old = [&]() {
        variant_old_path_sender<k>(leaves.data(), session, b0, bs,
                                    u_old.data(), v_old.data());
    };
    auto fn_b = [&]() {
        variant_b_portable<k>(leaves.data(), session, b0, bs, u_b.data(), v_b.data());
    };
    auto fn_a = [&]() {
        variant_a_portable<k>(leaves.data(), session, b0, bs, u_a.data(), v_a.data());
    };
    double cur_us = bench_median_us(iters, trials, fn_cur);
    double old_us = bench_median_us(iters, trials, fn_old);
    double b_us   = bench_median_us(iters, trials, fn_b);
    double a_us   = bench_median_us(iters, trials, fn_a);
    double neon_us = -1, bfly_us = -1, avx_us = -1;
#if defined(__aarch64__)
    if (include_neon) {
        auto fn_bfly = [&]() {
            variant_butterfly_neon_sender<k>(leaves.data(), session, b0, bs,
                                              u_bfly.data(), v_bfly.data(),
                                              keys_scratch.data());
        };
        bfly_us = bench_median_us(iters, trials, fn_bfly);
        if (run_neon_b) {
            auto fn_neon = [&]() {
                variant_b_neon_k8(leaves.data(), session, b0, bs,
                                  u_neon.data(), v_neon.data(), keys_scratch.data());
            };
            neon_us = bench_median_us(iters, trials, fn_neon);
        }
    }
#endif

#if EMP_AES_HAS_VAES512
    if constexpr (k == 8) {
        auto fn_avx = [&]() {
            variant_b_avx512_sender<k>(leaves.data(), session, b0, bs,
                                        u_avx.data(), v_avx.data());
        };
        avx_us = bench_median_us(iters, trials, fn_avx);
    }
#endif

    std::printf("k=%d bs=%lld iters=%d   current=%9.2f us   old=%9.2f us (%.2fx)   B-port=%9.2f us (%.2fx)   A-port=%9.2f us (%.2fx)",
                k, (long long)bs, iters,
                cur_us,
                old_us, old_us / cur_us,
                b_us, b_us / cur_us,
                a_us, a_us / cur_us);
    if (bfly_us > 0)
        std::printf("   bfly=%9.2f us (%.2fx)", bfly_us, bfly_us / cur_us);
    if (neon_us > 0)
        std::printf("   B-neon=%9.2f us (%.2fx)", neon_us, neon_us / cur_us);
    if (avx_us > 0)
        std::printf("   B-avx512=%9.2f us (%.2fx vs current; %.2fx vs old)",
                    avx_us, avx_us / cur_us, avx_us / old_us);
    std::printf("\n");
}

}  // namespace

int main() {
    std::printf("# bench_sfvole_v2 — sender side, portable A/B reference impls\n");
    std::printf("# Apple M numbers are baseline only; the win for A/B requires\n");
    std::printf("# AVX-512+GFNI/vpternlogd specializations (separate AWS bench).\n\n");

    run_one_k<8>(1024, /*include_neon=*/true);
    run_one_k<8>(128,  /*include_neon=*/true);
    run_one_k<4>(1024, /*include_neon=*/true);
    run_one_k<4>(128,  /*include_neon=*/true);
    run_one_k<2>(1024, /*include_neon=*/true);
    run_one_k<2>(128,  /*include_neon=*/true);

    // Tail-handling correctness: AVX-512 View B kernel processes 4
    // j-positions per tile; SoftSpokenOT calls compute_chunk with
    // bs=1 (malicious sacrificial chunk) and any positive value, so
    // bs not divisible by 4 must work. These extra k=8 sweeps catch
    // tail-overrun bugs that the larger-bs runs miss.
    std::printf("\n# Tail-bs sweep (k=8) for AVX-512 View B correctness:\n");
    run_one_k<8>(1, /*include_neon=*/true);
    run_one_k<8>(2, /*include_neon=*/true);
    run_one_k<8>(3, /*include_neon=*/true);
    run_one_k<8>(5, /*include_neon=*/true);
    run_one_k<8>(7, /*include_neon=*/true);

    std::printf("\n# Receiver-side bench:\n");
    run_one_k_recv<8>(1024, /*include_neon=*/true);
    run_one_k_recv<8>(128,  /*include_neon=*/true);
    run_one_k_recv<4>(1024, /*include_neon=*/true);
    run_one_k_recv<4>(128,  /*include_neon=*/true);
    run_one_k_recv<2>(1024, /*include_neon=*/true);
    run_one_k_recv<2>(128,  /*include_neon=*/true);

    std::printf("\n# Tail-bs sweep (k=8) for AVX-512 View B receiver:\n");
    run_one_k_recv<8>(1, /*include_neon=*/true);
    run_one_k_recv<8>(2, /*include_neon=*/true);
    run_one_k_recv<8>(3, /*include_neon=*/true);
    run_one_k_recv<8>(5, /*include_neon=*/true);
    run_one_k_recv<8>(7, /*include_neon=*/true);

    return 0;
}
