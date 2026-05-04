// Microbench for the multi-key AES-CTR + XOR-fold primitive that would
// underpin a fused subspace-VOLE inner loop:
//
//     out[N]  =  XOR over i in [0, K)  of  AES_keys[i](ctr + j)     for j in [0, N)
//
// Compares three implementations of the same operation and characterizes
// the upper-bound speedup over the current SoftSpoken sequential pattern.
//
//   (a) Sequential:    K calls of ParaEnc<1, N>, fold-per-call.  This is what
//                      sfvole_*_compute_chunk does today (per leaf x).
//   (b) Tiled fused:   T keys at a time via ParaEnc<T, N>.       T ∈ {2, 4, 8}
//   (c) Fully fused:   ParaEnc<K, N> + single XOR-fold pass.     K small only.
//
// Sweep K ∈ {4..256}, N ∈ {64, 256, 1024}.

#include "emp-tool/emp-tool.h"
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <algorithm>
#include <cstring>
using namespace emp;

static double now_us() {
    using clk = std::chrono::high_resolution_clock;
    auto t = clk::now().time_since_epoch();
    return std::chrono::duration<double, std::micro>(t).count();
}

// 16-byte aligned heap allocation for intermediates beyond the stack budget.
static block* aligned_blocks(size_t n) {
    void* p = nullptr;
    if (posix_memalign(&p, 16, sizeof(block) * n) != 0) std::abort();
    return (block*)p;
}

// (a) Sequential: K calls of ParaEnc<1, N>, fold per call.
// `tmp` is N blocks, reused across all K iterations.
template <int N>
static inline void seq_xor_fold(const AES_KEY* keys, int K, uint64_t ctr,
                                block* tmp, block* out) {
    std::memset(out, 0, sizeof(block) * N);
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < N; ++j) tmp[j] = makeBlock(0LL, (int64_t)(ctr + j));
        ParaEnc<1, N>(tmp, keys + i);
        for (int j = 0; j < N; ++j) out[j] = out[j] ^ tmp[j];
    }
}

// (b) Tiled fused. T keys at a time via ParaEnc<T, N>.
// `tmp` is T*N blocks.
template <int T, int N>
static inline void tiled_xor_fold(const AES_KEY* keys, int K, uint64_t ctr,
                                  block* tmp, block* out) {
    std::memset(out, 0, sizeof(block) * N);
    for (int batch = 0; batch < K; batch += T) {
        for (int i = 0; i < T; ++i)
            for (int j = 0; j < N; ++j)
                tmp[i*N + j] = makeBlock(0LL, (int64_t)(ctr + j));
        ParaEnc<T, N>(tmp, keys + batch);
        for (int i = 0; i < T; ++i)
            for (int j = 0; j < N; ++j)
                out[j] = out[j] ^ tmp[i*N + j];
    }
}

// (c) Fully fused via ParaEnc<K, N>. `tmp` is K*N blocks.
template <int K, int N>
static inline void full_xor_fold(const AES_KEY* keys, uint64_t ctr,
                                 block* tmp, block* out) {
    for (int i = 0; i < K; ++i)
        for (int j = 0; j < N; ++j)
            tmp[i*N + j] = makeBlock(0LL, (int64_t)(ctr + j));
    ParaEnc<K, N>(tmp, keys);
    for (int j = 0; j < N; ++j) {
        block acc = tmp[j];
        for (int i = 1; i < K; ++i) acc = acc ^ tmp[i*N + j];
        out[j] = acc;
    }
}

// Time `fn` enough iterations to total ~kTargetBlocks AES blocks of work.
// Returns ns per output-block (= ns per j).
template <typename Fn>
static double time_per_output_block(Fn&& fn, int K, int N,
                                    int64_t kTargetBlocks = (1LL << 26)) {
    int64_t blocks_per_call = (int64_t)K * N;
    int64_t calls = std::max<int64_t>(8, kTargetBlocks / blocks_per_call);

    // Warmup
    for (int i = 0; i < 3; ++i) fn(0);

    double best_us = 1e18;
    for (int trial = 0; trial < 5; ++trial) {
        double t0 = now_us();
        for (int64_t c = 0; c < calls; ++c) fn(c);
        double dt = now_us() - t0;
        best_us = std::min(best_us, dt);
    }
    // ns per call
    double ns_per_call = best_us * 1000.0 / (double)calls;
    // ns per output block = (ns per call) / N
    return ns_per_call / (double)N;
}

// Sink to defeat dead-code elimination.
static volatile uint64_t g_sink = 0;
static void absorb(const block* b, int N) {
    uint64_t s = 0;
    for (int j = 0; j < N; ++j) s ^= _mm_extract_epi64(b[j], 0);
    g_sink ^= s;
}

int main() {
    constexpr int kMaxK = 256;
    AES_KEY keys[kMaxK];
    {
        PRG prg(&fix_key);
        block seeds[kMaxK];
        prg.random_block(seeds, kMaxK);
        for (int i = 0; i < kMaxK; ++i) AES_set_encrypt_key(seeds[i], &keys[i]);
    }

    // Reusable heap intermediate, sized to the largest cell (kMaxK * 1024 = 4 MB).
    block* tmp_big = aligned_blocks((size_t)kMaxK * 1024);
    alignas(16) block out[1024];

    std::printf("# Multi-key AES-CTR + XOR-fold microbench\n");
    std::printf("# best of 5 trials per cell, ~2^26 AES block-ops per measurement\n");
    std::printf("# ns/blk = ns per output block (= per j); GB/s = output bandwidth\n");
    std::printf("# %-3s %-5s %-10s %10s %10s\n",
                "K", "N", "impl", "ns/blk", "GB/s");

    auto report = [&](int K, int N, const char* impl, double ns_per_blk) {
        double gbs = 16.0 / ns_per_blk;
        std::printf("  %-3d %-5d %-10s %10.3f %10.2f\n", K, N, impl, ns_per_blk, gbs);
    };

    // Driver: dispatch on (K, N) at compile time via switch-of-templates.
    auto run_cell = [&](int K, int N) {
        // ---- Sequential ----
        auto run_seq = [&]<int Nc>(std::integral_constant<int, Nc>) {
            double ns = time_per_output_block([&](int64_t c){
                seq_xor_fold<Nc>(keys, K, (uint64_t)c * Nc, tmp_big, out);
                absorb(out, Nc);
            }, K, Nc);
            report(K, Nc, "seq", ns);
        };

        // ---- Tiled fused ----
        auto run_tile = [&]<int T, int Nc>(std::integral_constant<int, T>,
                                            std::integral_constant<int, Nc>) {
            double ns = time_per_output_block([&](int64_t c){
                tiled_xor_fold<T, Nc>(keys, K, (uint64_t)c * Nc, tmp_big, out);
                absorb(out, Nc);
            }, K, Nc);
            char label[16];
            std::snprintf(label, sizeof(label), "tile-%d", T);
            report(K, Nc, label, ns);
        };

        // ---- Fully fused (only when K is one of the supported template args) ----
        auto run_full = [&]<int Kc, int Nc>(std::integral_constant<int, Kc>,
                                             std::integral_constant<int, Nc>) {
            double ns = time_per_output_block([&](int64_t c){
                full_xor_fold<Kc, Nc>(keys, (uint64_t)c * Nc, tmp_big, out);
                absorb(out, Nc);
            }, Kc, Nc);
            report(Kc, Nc, "full", ns);
        };

        // Run seq + tile-2/4/8 for each N ∈ {64, 256, 1024}.
        if (N == 64) {
            run_seq(std::integral_constant<int, 64>{});
            run_tile(std::integral_constant<int, 2>{}, std::integral_constant<int, 64>{});
            run_tile(std::integral_constant<int, 4>{}, std::integral_constant<int, 64>{});
            run_tile(std::integral_constant<int, 8>{}, std::integral_constant<int, 64>{});
        } else if (N == 256) {
            run_seq(std::integral_constant<int, 256>{});
            run_tile(std::integral_constant<int, 2>{}, std::integral_constant<int, 256>{});
            run_tile(std::integral_constant<int, 4>{}, std::integral_constant<int, 256>{});
            run_tile(std::integral_constant<int, 8>{}, std::integral_constant<int, 256>{});
        } else if (N == 1024) {
            run_seq(std::integral_constant<int, 1024>{});
            run_tile(std::integral_constant<int, 2>{}, std::integral_constant<int, 1024>{});
            run_tile(std::integral_constant<int, 4>{}, std::integral_constant<int, 1024>{});
            run_tile(std::integral_constant<int, 8>{}, std::integral_constant<int, 1024>{});
        }

        // Fully fused only for K ∈ {4, 8, 16}.
        if (K == 4) {
            if (N == 64)   run_full(std::integral_constant<int, 4>{}, std::integral_constant<int, 64>{});
            if (N == 256)  run_full(std::integral_constant<int, 4>{}, std::integral_constant<int, 256>{});
            if (N == 1024) run_full(std::integral_constant<int, 4>{}, std::integral_constant<int, 1024>{});
        } else if (K == 8) {
            if (N == 64)   run_full(std::integral_constant<int, 8>{}, std::integral_constant<int, 64>{});
            if (N == 256)  run_full(std::integral_constant<int, 8>{}, std::integral_constant<int, 256>{});
            if (N == 1024) run_full(std::integral_constant<int, 8>{}, std::integral_constant<int, 1024>{});
        } else if (K == 16) {
            if (N == 64)   run_full(std::integral_constant<int, 16>{}, std::integral_constant<int, 64>{});
            if (N == 256)  run_full(std::integral_constant<int, 16>{}, std::integral_constant<int, 256>{});
            if (N == 1024) run_full(std::integral_constant<int, 16>{}, std::integral_constant<int, 1024>{});
        }
    };

    for (int N : {64, 256, 1024}) {
        std::printf("\n## N = %d\n", N);
        for (int K : {4, 8, 16, 32, 64, 128, 256}) {
            run_cell(K, N);
        }
    }

    free(tmp_big);
    (void)g_sink;
    return 0;
}
