// Cross-platform breakdown bench for cGGM + ferret/softspoken
// hot paths. Three sections:
//
//   A) cGGM absolute cost + AES fraction at depths used by
//      ferret (d=13) and softspoken (d=2/4/8).
//   B) LPN compute cost at ferret_b13 production parameters
//      (this is the OTHER big slice of an extend round).
//   C) Memory-bandwidth floor (memcpy across the cGGM-tree-shaped
//      buffer) — context for "what's the speed of light?"
//
// All cost numbers reported as ns/op + MOps/s. Section A also
// reports the AES fraction = ns/H_raw / ns/H_cggm — i.e. how
// much of cGGM is just AES vs scaffolding.

#include "emp-tool/emp-tool.h"
#include "emp-ot/cggm.h"
#include "emp-ot/ferret/lpn_f2.h"
#include "emp-ot/ferret/constants.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <algorithm>
using namespace emp;

static double now_us() {
    using clk = std::chrono::high_resolution_clock;
    return std::chrono::duration<double, std::micro>(clk::now().time_since_epoch()).count();
}

static block* aligned_blocks(int64_t n) {
    void* p = nullptr;
    if (posix_memalign(&p, 16, sizeof(block) * (size_t)n) != 0) std::abort();
    return (block*)p;
}

// --- Section A: cGGM cost + AES fraction ---

static double bench_cggm(int d, int64_t trees) {
    const int Q = 1 << d;
    block* leaves = aligned_blocks(Q);
    block* K0     = aligned_blocks(d);
    block Delta, k;
    PRG prg;
    prg.random_block(&Delta, 1);
    prg.random_block(&k, 1);
    for (int i = 0; i < 4; ++i) cggm::build_sender(d, Delta, k, leaves, K0);
    double best = 1e18;
    for (int trial = 0; trial < 5; ++trial) {
        double t0 = now_us();
        for (int64_t t = 0; t < trees; ++t)
            cggm::build_sender(d, Delta, k, leaves, K0);
        best = std::min(best, now_us() - t0);
    }
    volatile uint64_t sink = 0;
    for (int j = 0; j < Q; ++j) sink ^= _mm_extract_epi64(leaves[j], 0);
    (void)sink;
    free(leaves); free(K0);
    return best;  // microseconds
}

static double bench_raw_H(int64_t total_H) {
    CCRH ccrh;
    constexpr int N = cggm::kTile;
    block* in  = aligned_blocks(N);
    block* out = aligned_blocks(N);
    PRG prg;
    prg.random_block(in, N);
    const int64_t calls = total_H / N;
    for (int i = 0; i < 4; ++i) ccrh.H<N>(out, in);
    double best = 1e18;
    // Chain a per-iteration data dependency on `out[0]` into the
    // visible sink so the compiler can't hoist H out of the loop.
    volatile uint64_t sink = 0;
    for (int trial = 0; trial < 5; ++trial) {
        uint64_t local_sink = 0;
        double t0 = now_us();
        for (int64_t c = 0; c < calls; ++c) {
            ccrh.H<N>(out, in);
            local_sink ^= _mm_extract_epi64(out[0], 0);
        }
        best = std::min(best, now_us() - t0);
        sink ^= local_sink;
    }
    (void)sink;
    free(in); free(out);
    return best;
}

static void section_A() {
    std::printf("=== A) cGGM cost + AES fraction (kTile=%d) ===\n", cggm::kTile);
    std::printf("  %-4s %-9s %-12s %-12s %-9s %-9s\n",
                "d", "H/tree", "ns/H_cggm", "ns/H_raw", "AES_frac", "headroom");
    struct { int d; const char* label; } cases[] = {
        {2,  "softspoken k=2"},
        {4,  "softspoken k=4"},
        {8,  "softspoken k=8"},
        {13, "ferret_b13"},
    };
    constexpr int64_t target_H = 1LL << 26;  // 64M H per measurement
    for (auto c : cases) {
        const int d = c.d;
        const int64_t H_per_tree = (1LL << d) - 2;
        int64_t trees = target_H / std::max<int64_t>(H_per_tree, 1);
        if (trees < 16) trees = 16;
        const int64_t total_H = trees * H_per_tree;

        double us_cggm = bench_cggm(d, trees);
        double us_raw  = bench_raw_H(total_H);

        double ns_per_H_cggm = us_cggm * 1000.0 / (double)total_H;
        double ns_per_H_raw  = us_raw  * 1000.0 / (double)total_H;
        double aes_frac = ns_per_H_raw / ns_per_H_cggm;
        double headroom = 1.0 - aes_frac;
        std::printf("  d=%-2d %-9lld %-12.3f %-12.3f %-9.1f%% %-9.1f%%   [%s]\n",
                    d, (long long)H_per_tree,
                    ns_per_H_cggm, ns_per_H_raw,
                    aes_frac * 100, headroom * 100,
                    c.label);
    }
}

// --- Section B: LPN compute cost at ferret_b13 ---

static void section_B() {
    std::printf("\n=== B) LPN compute (ferret_b13: n=%lld, k=%lld) ===\n",
                (long long)ferret_b13.n, (long long)ferret_b13.k);
    ThreadPool pool(4);
    LpnF2<10> lpn(ALICE, ferret_b13.n, ferret_b13.k, &pool, nullptr, 4);
    block* nn = aligned_blocks(ferret_b13.n);
    block* kk = aligned_blocks(ferret_b13.k);
    PRG prg;
    prg.random_block(kk, ferret_b13.k);
    memset(nn, 0, sizeof(block) * (size_t)ferret_b13.n);

    for (int i = 0; i < 2; ++i) lpn.bench(nn, kk);
    double best = 1e18;
    for (int trial = 0; trial < 3; ++trial) {
        double t0 = now_us();
        lpn.bench(nn, kk);
        best = std::min(best, now_us() - t0);
    }
    volatile uint64_t sink = 0;
    for (int64_t j = 0; j < ferret_b13.n; j += 4096) sink ^= _mm_extract_epi64(nn[j], 0);
    (void)sink;

    double ms = best / 1000.0;
    double ns_per_out = best * 1000.0 / (double)ferret_b13.n;
    double mout_s = (double)ferret_b13.n / (best / 1e6) / 1e6;
    std::printf("  one extend's worth of LPN: %.2f ms  (%.3f ns/output, %.2f Mout/s)\n",
                ms, ns_per_out, mout_s);
    std::printf("  Per-output cost factors:\n");
    std::printf("    cGGM (1 H per output @ d=13):  %.3f ns/output\n",
                bench_cggm(13, 1024) / 1024.0 / 8190.0 * 1000.0);
    std::printf("    LPN (above):                   %.3f ns/output\n", ns_per_out);

    free(nn); free(kk);
}

// --- Section C: memcpy bandwidth ---

static void section_C() {
    std::printf("\n=== C) Memory bandwidth (sanity floor) ===\n");
    const int64_t N = 1 << 24;  // 256 MB of blocks
    block* a = aligned_blocks(N);
    block* b = aligned_blocks(N);
    PRG prg;
    prg.random_block(a, std::min<int64_t>(N, 1 << 20));

    for (int i = 0; i < 2; ++i) std::memcpy(b, a, sizeof(block) * N);
    double best = 1e18;
    for (int trial = 0; trial < 3; ++trial) {
        double t0 = now_us();
        std::memcpy(b, a, sizeof(block) * N);
        best = std::min(best, now_us() - t0);
    }
    volatile uint64_t sink = _mm_extract_epi64(b[N - 1], 0);
    (void)sink;
    double bw_gb = (double)(sizeof(block) * N) / (best / 1e6) / (1024.0 * 1024.0 * 1024.0);
    std::printf("  memcpy 256 MiB block array:  %.2f GiB/s\n", bw_gb);
    free(a); free(b);
}

int main() {
    section_A();
    section_B();
    section_C();
    return 0;
}
