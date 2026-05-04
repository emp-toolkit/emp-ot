// Phase-by-phase compute ceiling for one ferret extend round at
// ferret_b13 production params. Runs cGGM × tree_n then LPN × n
// in-process (no NetIO). Reports a Mout/s ceiling that bounds
// what test_ferret could ever achieve if IO/sync were free.
//
// Compare against test_ferret's measured Active FERRET RCOT
// throughput to quantify IO + base-OT + sync overhead per extend.

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

int main() {
    const auto& p = ferret_b13;
    const int  tree_d   = (int)p.log_bin_sz;          // 13
    const int  Q        = 1 << tree_d;                // 8192 leaves per tree
    const int64_t n_out = p.n;                        // 10,485,760
    const int  threads  = 4;

    std::printf("# ferret_b13 one-extend compute ceiling\n");
    std::printf("#   tree_n = %lld   tree_d = %d   leaves_per_tree = %d\n",
                (long long)p.t, tree_d, Q);
    std::printf("#   LPN n = %lld   k = %lld   threads = %d\n",
                (long long)p.n, (long long)p.k, threads);
    std::printf("# best of 3 trials per phase, no IO, single host\n\n");

    // ---- cGGM phase: t trees, each of depth tree_d. ----
    block* leaves = aligned_blocks(Q);
    block* K0     = aligned_blocks(tree_d);
    block Delta, k_seed;
    PRG prg;
    prg.random_block(&Delta, 1);
    prg.random_block(&k_seed, 1);

    // Warmup.
    for (int i = 0; i < 4; ++i)
        cggm::build_sender(tree_d, Delta, k_seed, leaves, K0);

    double cggm_us = 1e18;
    for (int trial = 0; trial < 3; ++trial) {
        double t0 = now_us();
        for (int64_t t = 0; t < p.t; ++t)
            cggm::build_sender(tree_d, Delta, k_seed, leaves, K0);
        cggm_us = std::min(cggm_us, now_us() - t0);
    }
    volatile uint64_t sink = 0;
    for (int j = 0; j < Q; ++j) sink ^= _mm_extract_epi64(leaves[j], 0);
    free(leaves); free(K0);

    // ---- LPN phase. ----
    block* nn = aligned_blocks(n_out);
    block* kk = aligned_blocks(p.k);
    prg.random_block(kk, p.k);
    std::memset(nn, 0, sizeof(block) * (size_t)n_out);

    ThreadPool pool(threads);
    LpnF2<10> lpn(ALICE, n_out, p.k, &pool, nullptr, threads);
    for (int i = 0; i < 2; ++i) lpn.bench(nn, kk);

    double lpn_us = 1e18;
    for (int trial = 0; trial < 3; ++trial) {
        double t0 = now_us();
        lpn.bench(nn, kk);
        lpn_us = std::min(lpn_us, now_us() - t0);
    }
    for (int64_t j = 0; j < n_out; j += 4096) sink ^= _mm_extract_epi64(nn[j], 0);
    (void)sink;
    free(nn); free(kk);

    // ---- Report. ----
    const double cggm_ms = cggm_us / 1000.0;
    const double lpn_ms  = lpn_us  / 1000.0;
    const double tot_ms  = cggm_ms + lpn_ms;
    const double mops    = (double)n_out / (tot_ms / 1000.0) / 1e6;

    std::printf("Phase            ms        ns/output    %% of compute\n");
    std::printf("cGGM             %7.2f    %7.3f       %5.1f%%\n",
                cggm_ms, cggm_us * 1000.0 / (double)n_out,
                100.0 * cggm_ms / tot_ms);
    std::printf("LPN              %7.2f    %7.3f       %5.1f%%\n",
                lpn_ms,  lpn_us  * 1000.0 / (double)n_out,
                100.0 * lpn_ms / tot_ms);
    std::printf("---\n");
    std::printf("Total compute    %7.2f    %7.3f       100.0%%\n",
                tot_ms, tot_ms * 1000000.0 / (double)n_out);
    std::printf("Compute ceiling: %.1f Mout/s\n", mops);
    std::printf("\n");
    std::printf("# Compare to: test_ferret 'Active FERRET RCOT' (measured)\n");
    std::printf("# Gap (compute_ceiling - measured) = IO + base-OT + sync overhead.\n");
    return 0;
}
