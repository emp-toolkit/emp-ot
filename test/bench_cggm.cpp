// cGGM throughput sweep across (tile, depth). Tile size is the only
// compile-time tunable in cggm.h; production picks one per platform
// based on this bench's results.
//
// Per cell: ns/H of cggm::build_sender, where H is the underlying
// CCRH call (= one fixed-key AES + linear orthomorphism). One tree
// at depth d does (2^d - 2) calls to H, batched in tiles of `Tile`.
//
// First column is the raw H<Tile> peak — same AES, no cGGM scaffolding
// (no level-sum compute, no parents_buf copy, no per-level loop).
// Compare against the depth columns to see how much overhead the
// tree expander adds; the gap shrinks as d grows because the AES gen
// dominates at depth.
//
// Tiles probed by passing a non-default Tile template parameter to
// cggm::build_sender (default = kTile, the platform's compile-time
// constexpr). No code duplicated from cggm.h.

#include "emp-tool/emp-tool.h"
#include "emp-ot/ot_extension/cggm.h"
#include <cstdio>
#include <cstdlib>
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

// ---------- Raw H<Tile> peak (no cGGM scaffolding) ----------
template <int Tile>
static double bench_raw_H(CCRH& ccrh, block* in, block* out, int64_t total_H) {
    const int64_t calls = total_H / Tile;
    for (int i = 0; i < 4; ++i) ccrh.H<Tile>(out, in);
    double best = 1e18;
    for (int trial = 0; trial < 5; ++trial) {
        double t0 = now_us();
        for (int64_t c = 0; c < calls; ++c) ccrh.H<Tile>(out, in);
        best = std::min(best, now_us() - t0);
    }
    volatile uint64_t sink = 0;
    for (int i = 0; i < Tile; ++i) sink ^= _mm_extract_epi64(out[i], 0);
    (void)sink;
    return best;
}

// ---------- cGGM build_sender at arbitrary tile ----------
template <int Tile>
static double bench_cggm_at(int d, int64_t trees, block* leaves, block* K0,
                            block Delta, block k) {
    for (int i = 0; i < 4; ++i) cggm::build_sender<Tile>(d, Delta, k, leaves, K0);
    double best = 1e18;
    for (int trial = 0; trial < 5; ++trial) {
        double t0 = now_us();
        for (int64_t t = 0; t < trees; ++t)
            cggm::build_sender<Tile>(d, Delta, k, leaves, K0);
        best = std::min(best, now_us() - t0);
    }
    volatile uint64_t sink = 0;
    for (int j = 0; j < (1 << d); ++j) sink ^= _mm_extract_epi64(leaves[j], 0);
    (void)sink;
    return best;
}

// One row of the table: raw H<Tile> ns + cGGM ns/H at each depth.
template <int Tile>
static void run_row(CCRH& ccrh, block* raw_in, block* raw_out,
                    block* leaves, block* K0, block Delta, block k,
                    const int* depths, int n_depths) {
#ifdef NDEBUG
    constexpr int64_t total_H_target = 1LL << 22;  // ~4M H
#else
    constexpr int64_t total_H_target = 1LL << 18;  // ~256K H — Debug-CI fast path
#endif

    const double raw_us = bench_raw_H<Tile>(ccrh, raw_in, raw_out, total_H_target);
    const double raw_ns = raw_us * 1000.0 / (double)total_H_target;

    const char* mark = (Tile == cggm::kTile) ? " *" : "";
    std::printf("  %-5d %2s  %8.3f", Tile, mark, raw_ns);

    for (int i = 0; i < n_depths; ++i) {
        const int d = depths[i];
        const int64_t H_per_tree = (1LL << d) - 2;
        int64_t trees = total_H_target / H_per_tree;
        if (trees < 16) trees = 16;
        const int64_t total_H = trees * H_per_tree;

        const double us = bench_cggm_at<Tile>(d, trees, leaves, K0, Delta, k);
        const double ns_per_H = us * 1000.0 / (double)total_H;
        std::printf("  %8.3f", ns_per_H);
    }
    std::printf("\n");
}

int main() {
    // Depths probed: ferret production is d=13; smaller depths cover
    // softspoken (k ∈ {2, 4, 8}, but d ≤ 8 has too few leaves to dwarf
    // build/loop overhead — start at d=8) and a long-tail check at d=14.
    const int depths[] = {8, 10, 12, 13, 14};
    constexpr int n_depths = sizeof(depths) / sizeof(depths[0]);

    // Pre-allocate the largest leaves buffer (deepest depth) once.
    int max_d = 0;
    for (int d : depths) max_d = std::max(max_d, d);
    block* leaves = aligned_blocks(1LL << max_d);
    block* K0     = aligned_blocks(max_d);

    constexpr int kMaxTile = 128;
    block* raw_in  = aligned_blocks(kMaxTile);
    block* raw_out = aligned_blocks(kMaxTile);
    PRG prg;
    prg.random_block(raw_in, kMaxTile);
    block Delta, k;
    prg.random_block(&Delta, 1);
    prg.random_block(&k,     1);

    CCRH ccrh;

    std::printf("# cGGM throughput sweep — ns/H (lower = faster). Best of 5 trials.\n");
    std::printf("# raw H<Tile> column: standalone CCRH::H<Tile> peak (no cGGM scaffolding).\n");
    std::printf("# d=N column: cggm::build_sender at depth N, ns per H call.\n");
    std::printf("# Current cggm::kTile (compile-time) = %d, marked '*'.\n", cggm::kTile);
    std::printf("\n");
    std::printf("  %-5s %2s  %8s", "Tile", "", "raw H");
    for (int d : depths) std::printf("  %5s%-3d", "d=", d);
    std::printf("\n");
    std::printf("  -----      --------  --------  --------  --------  --------  --------\n");

    run_row<  4>(ccrh, raw_in, raw_out, leaves, K0, Delta, k, depths, n_depths);
    run_row<  8>(ccrh, raw_in, raw_out, leaves, K0, Delta, k, depths, n_depths);
    run_row< 16>(ccrh, raw_in, raw_out, leaves, K0, Delta, k, depths, n_depths);
    run_row< 32>(ccrh, raw_in, raw_out, leaves, K0, Delta, k, depths, n_depths);
    run_row< 64>(ccrh, raw_in, raw_out, leaves, K0, Delta, k, depths, n_depths);
    run_row<128>(ccrh, raw_in, raw_out, leaves, K0, Delta, k, depths, n_depths);

    free(leaves); free(K0); free(raw_in); free(raw_out);
    return 0;
}
