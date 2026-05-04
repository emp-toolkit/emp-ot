// cGGM tile-size sweep for the production depth d=13.
//
// `cggm::kTile` is a compile-time constexpr picked per platform.
// This bench probes whether the choice is correct by re-running
// cGGM with several alternative tile sizes (template instantiated
// here, not in cggm.h) at d=13 and reporting MH/s for each.
//
// If a non-default tile beats the current pick by >5%, the cggm.h
// constexpr should be revised for that platform.

#include "emp-tool/emp-tool.h"
#include "emp-ot/cggm.h"
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

// Local copy of cggm::detail::expand_level templated on tile size,
// so we can probe N != cggm::kTile without rebuilding cggm.h.
template <int Tile>
static void expand_level(CCRH& ccrh, block* leaves, int parents,
                         block& left_sum, block& right_sum) {
    block parents_buf[Tile];
    block lefts_buf[Tile];
    for (int s = parents; s > 0; ) {
        const int n    = std::min(s, Tile);
        const int base = s - n;
        for (int t = 0; t < n; ++t) parents_buf[t] = leaves[base + t];
        if (n == Tile) ccrh.H<Tile>(lefts_buf, parents_buf);
        else           ccrh.Hn(lefts_buf, parents_buf, n);
        for (int t = n - 1; t >= 0; --t) {
            const int j = base + t;
            const block left  = lefts_buf[t];
            const block right = parents_buf[t] ^ left;
            leaves[2 * j]     = left;
            leaves[2 * j + 1] = right;
            left_sum  ^= left;
            right_sum ^= right;
        }
        s = base;
    }
}

template <int Tile>
static void build_sender_at_tile(int d, block Delta, block k,
                                 block* leaves, block* K0) {
    CCRH ccrh;
    leaves[0] = k;
    leaves[1] = Delta ^ k;
    K0[0] = leaves[0];
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        block ls = zero_block, rs = zero_block;
        expand_level<Tile>(ccrh, leaves, parents, ls, rs);
        K0[i - 1] = ls;
    }
}

template <int Tile>
static double bench(int d, int64_t trees, block* leaves, block* K0,
                    block Delta, block k) {
    for (int i = 0; i < 4; ++i) build_sender_at_tile<Tile>(d, Delta, k, leaves, K0);
    double best = 1e18;
    for (int trial = 0; trial < 5; ++trial) {
        double t0 = now_us();
        for (int64_t t = 0; t < trees; ++t)
            build_sender_at_tile<Tile>(d, Delta, k, leaves, K0);
        best = std::min(best, now_us() - t0);
    }
    volatile uint64_t sink = 0;
    for (int j = 0; j < (1 << d); ++j) sink ^= _mm_extract_epi64(leaves[j], 0);
    (void)sink;
    return best;
}

int main() {
    constexpr int d = 13;
    const int Q = 1 << d;
    const int64_t H_per_tree = (1LL << d) - 2;
    int64_t trees = (1LL << 28) / H_per_tree;
    if (trees < 16) trees = 16;
    const int64_t total_H = trees * H_per_tree;

    block* leaves = aligned_blocks(Q);
    block* K0     = aligned_blocks(d);
    block Delta, k;
    PRG prg;
    prg.random_block(&Delta, 1);
    prg.random_block(&k, 1);

    std::printf("# cGGM tile sweep at d=%d (current cggm::kTile=%d)\n", d, cggm::kTile);
    std::printf("# total H per measurement: %lld; best of 5 trials\n", (long long)total_H);
    std::printf("  %-6s %-9s %-9s\n", "Tile", "MH/s", "ns/H");

    auto report = [&](int tile, double us) {
        double mh = (double)total_H / (us / 1e6) / 1e6;
        double ns = us * 1000.0 / (double)total_H;
        const char* mark = (tile == cggm::kTile) ? " *" : "";
        std::printf("  %-6d %-9.2f %-9.3f%s\n", tile, mh, ns, mark);
    };

    report(  4, bench<  4>(d, trees, leaves, K0, Delta, k));
    report(  8, bench<  8>(d, trees, leaves, K0, Delta, k));
    report( 16, bench< 16>(d, trees, leaves, K0, Delta, k));
    report( 32, bench< 32>(d, trees, leaves, K0, Delta, k));
    report( 64, bench< 64>(d, trees, leaves, K0, Delta, k));
    report(128, bench<128>(d, trees, leaves, K0, Delta, k));

    free(leaves); free(K0);
    return 0;
}
