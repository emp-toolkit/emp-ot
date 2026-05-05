// Microbench three sfvole-fold strategies for the SoftSpoken small-
// field VOLE inner loop (sender side, k=8). All variants compute the
// same (u, v_planes) from the same (leaves, session, b0, bs) inputs
// via different reduction strategies — see
// /Users/wangxiao/.claude/plans/if-i-implement-libc-agile-cosmos.md.
//
//   Current: existing aes_ctr_fold<N_TARGETS> per leaf — narrow
//            memory-RMW XOR-stores (1 + popcount(x) per (leaf, j)).
//   View B   (lift + wide masked XOR): per-leaf wide register-
//            resident accumulator, one masked XOR per (leaf, j).
//            Output: v_planes (plane-major), still feeds Conv.
//   View A   (transpose + parallel IPs): generate q PRG outputs →
//            q×128 bit transpose per j → 128 parallel inner products
//            of length q with the identity vector (0,1,…,q-1) over
//            F_{2^k}^k. Output is *post-Conv shape*.
//
// First cut: portable C++ for all 3 variants. Byte-equality verified;
// timing on Apple M is just a baseline (the win is on AVX-512+GFNI).
// SIMD-specialized A/B kernels (vpternlogd / vgf2p8affineqb) land in
// a follow-up before the AWS bench.

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
// Variant Current: thin wrapper around the existing kernel.
// ---------------------------------------------------------------------
template <int k>
void variant_current(const block* leaves,
                     uint64_t session, int64_t b0, int64_t bs,
                     block* u_chunk, block* v_planes_chunk) {
    softspoken::sfvole_sender_compute_chunk<k>(
        leaves, session, b0, bs, u_chunk, v_planes_chunk);
}

// ---------------------------------------------------------------------
// Generate q × bs PRG outputs into a flat (q, bs) block array.
// Used by View A (and as a building block for the portable View B).
// R[x * bs + j] = AES_{leaves[x] ^ session_xor}(makeBlock(0, b0 + j)).
// ---------------------------------------------------------------------
template <int k>
void gen_prg_block(const block* leaves,
                   uint64_t session, int64_t b0, int64_t bs,
                   block* R) {
    constexpr int Q = 1 << k;
    const block session_xor = makeBlock(0LL, (int64_t)session);
    AES_KEY aes_local;
    for (int x = 0; x < Q; ++x) {
        AES_set_encrypt_key(leaves[x] ^ session_xor, &aes_local);
        block* row = R + (size_t)x * bs;
        for (int64_t j = 0; j < bs; ++j) row[j] = makeBlock(0LL, b0 + j);
        AES_ecb_encrypt_blks(row, (unsigned)bs, &aes_local);
    }
}

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
    AES_KEY aes_local;
    std::vector<block> r_x((size_t)bs);

    for (int x = 0; x < Q; ++x) {
        AES_set_encrypt_key(leaves[x] ^ session_xor, &aes_local);
        for (int64_t j = 0; j < bs; ++j) r_x[j] = makeBlock(0LL, b0 + j);
        AES_ecb_encrypt_blks(r_x.data(), (unsigned)bs, &aes_local);

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

template <int k>
void run_one_k(int64_t bs) {
    constexpr int Q = 1 << k;
    constexpr int kHashSize = 32;
    (void)kHashSize;

    // Inputs.
    PRG seed_prg(fix_key);
    std::vector<block> leaves((size_t)Q);
    seed_prg.random_block(leaves.data(), Q);
    const uint64_t session = 0x12345678abcdULL;
    const int64_t b0 = 0;

    // Outputs (one buffer per variant).
    std::vector<block> u_cur((size_t)bs), u_b((size_t)bs), u_a((size_t)bs);
    std::vector<block> v_cur((size_t)k * bs), v_b((size_t)k * bs), v_a((size_t)k * bs);

    // 1) Run all three once and compare.
    variant_current<k>(leaves.data(), session, b0, bs, u_cur.data(), v_cur.data());
    variant_b_portable<k>(leaves.data(), session, b0, bs, u_b.data(),   v_b.data());
    variant_a_portable<k>(leaves.data(), session, b0, bs, u_a.data(),   v_a.data());

    bool eq_b_u = blocks_equal(u_cur.data(), u_b.data(), bs);
    bool eq_b_v = blocks_equal(v_cur.data(), v_b.data(), (int64_t)k * bs);
    bool eq_a_u = blocks_equal(u_cur.data(), u_a.data(), bs);
    bool eq_a_v = blocks_equal(v_cur.data(), v_a.data(), (int64_t)k * bs);
    std::printf("k=%d bs=%lld   B vs current: u=%s v=%s   A vs current: u=%s v=%s\n",
                k, (long long)bs,
                eq_b_u ? "OK" : "MISMATCH", eq_b_v ? "OK" : "MISMATCH",
                eq_a_u ? "OK" : "MISMATCH", eq_a_v ? "OK" : "MISMATCH");
    if (!(eq_b_u && eq_b_v && eq_a_u && eq_a_v)) {
        std::fprintf(stderr, "byte-equality FAILED — aborting bench\n");
        std::exit(1);
    }

    // 2) Time each (median of 5 trials × `iters` per trial).
    const int iters  = std::max(1, (int)(2'000'000 / std::max<int64_t>(1, bs * Q)));
    const int trials = 5;
    auto fn_cur = [&]() {
        variant_current<k>(leaves.data(), session, b0, bs, u_cur.data(), v_cur.data());
    };
    auto fn_b = [&]() {
        variant_b_portable<k>(leaves.data(), session, b0, bs, u_b.data(), v_b.data());
    };
    auto fn_a = [&]() {
        variant_a_portable<k>(leaves.data(), session, b0, bs, u_a.data(), v_a.data());
    };
    double cur_us = bench_median_us(iters, trials, fn_cur);
    double b_us   = bench_median_us(iters, trials, fn_b);
    double a_us   = bench_median_us(iters, trials, fn_a);

    std::printf("k=%d bs=%lld iters=%d   current=%9.2f us   B(portable)=%9.2f us (%.2fx)   A(portable)=%9.2f us (%.2fx)\n",
                k, (long long)bs, iters,
                cur_us,
                b_us, b_us / cur_us,
                a_us, a_us / cur_us);
}

}  // namespace

int main() {
    std::printf("# bench_sfvole_v2 — sender side, portable A/B reference impls\n");
    std::printf("# Apple M numbers are baseline only; the win for A/B requires\n");
    std::printf("# AVX-512+GFNI/vpternlogd specializations (separate AWS bench).\n\n");

    run_one_k<8>(1024);
    run_one_k<8>(128);
    run_one_k<4>(1024);
    run_one_k<2>(1024);

    return 0;
}
