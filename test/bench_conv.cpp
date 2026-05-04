// Microbenchmark for SoftSpoken's Conv (= softspoken::pack_planes_to_blocks).
// For k in {2,4,8} the bulk Conv is a 128 x length bit-matrix transpose:
// rows = n*k = 128 bit-planes (each `bpr` blocks long), cols = `length` OTs;
// output is `length` blocks, one per OT.
//
// We isolate the Conv cost by pre-filling planes with random data and
// calling pack_planes_to_blocks in a loop; no PRG / network in the path.
//
// Sweeps both small-batch (length=1248, planes fit in L1) and
// large-batch (length=2^20, planes ~16 MB in L3) regimes for k=2,4,8.

#include "emp-tool/emp-tool.h"
#include "emp-ot/softspoken/softspoken_ot.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>

using namespace emp;

static double now_us() {
    using clk = std::chrono::high_resolution_clock;
    auto t = clk::now().time_since_epoch();
    return std::chrono::duration<double, std::micro>(t).count();
}

template <int k>
static void bench_one(int64_t length) {
    constexpr int n = 128 / k;  // n_subvoles<k>(); n*k == 128 for k in {1,2,4,8}
    static_assert(n * k == 128, "expected n*k == 128");

    const int64_t bpr = (length + 127) / 128;
    const size_t plane_blocks = static_cast<size_t>(n) * k * bpr;

    std::vector<block> scratch(plane_blocks);
    std::vector<block> out(static_cast<size_t>(length));
    std::vector<const block*> planes(static_cast<size_t>(n) * k);

    PRG prg;
    prg.random_block(scratch.data(), scratch.size());
    for (int i = 0; i < n; ++i)
        for (int b = 0; b < k; ++b)
            planes[i * k + b] = scratch.data() +
                (static_cast<size_t>(i) * k + b) * bpr;

    // Total OTs to process per measurement: aim for ~0.2-1s wall time.
    // Conv runs at ~ns/OT, so 2^28 OTs of work is roughly the right scale.
    const int64_t kTotalOTs = 1LL << 28;
    const int64_t iters = std::max<int64_t>(1, kTotalOTs / length);

    // Warmup
    for (int it = 0; it < 5; ++it)
        softspoken::pack_planes_to_blocks<k>(planes.data(), n, length, bpr, out.data());

    double best_us = 1e18;
    for (int trial = 0; trial < 5; ++trial) {
        double t0 = now_us();
        for (int64_t it = 0; it < iters; ++it)
            softspoken::pack_planes_to_blocks<k>(planes.data(), n, length, bpr, out.data());
        double dt = now_us() - t0;
        best_us = std::min(best_us, dt);
    }

    // Sink to keep the optimizer from eliding work.
    volatile uint64_t sink = 0;
    for (int64_t j = 0; j < length; ++j) sink ^= _mm_extract_epi64(out[j], 0);
    (void)sink;

    const double total_ot = (double)iters * (double)length;
    const double secs = best_us / 1e6;
    const double mots = total_ot / secs / 1e6;
    const double ns_per_ot = best_us * 1000.0 / total_ot;
    const double per_call_us = best_us / (double)iters;

    std::printf("  k=%d  len=%-8lld  bpr=%-6lld  plane_KB=%-8.1f  "
                "%7.2f M OT/s  %6.3f ns/OT  %8.3f us/call  (iters=%lld)\n",
                k,
                (long long)length,
                (long long)bpr,
                (double)(plane_blocks * sizeof(block)) / 1024.0,
                mots,
                ns_per_ot,
                per_call_us,
                (long long)iters);
}

int main() {
    std::printf("# Conv (pack_planes_to_blocks) microbench\n");
    std::printf("# best of 5 trials; ~2^28 OT-equivalents per measurement\n");
    std::printf("# planes pre-filled, output reused; no PRG / IO in hot loop\n\n");

    // Small-batch regime: planes fit in L1 (n*k*bpr*16 bytes, e.g.
    // 128*10*16=20.5 KB at length=1248). Tests pure transpose throughput.
    std::printf("== small-batch (planes in L1) ==\n");
    bench_one<2>(1248);
    bench_one<4>(1248);
    bench_one<8>(1248);

    // Mid-batch: planes ~MB, fit in L2/L3.
    std::printf("\n== mid-batch (planes in L2/L3) ==\n");
    bench_one<2>(1 << 14);   // bpr=128, plane_KB=256
    bench_one<4>(1 << 14);
    bench_one<8>(1 << 14);

    // Large-batch: planes >> L2, partly L3 / DRAM.
    std::printf("\n== large-batch (planes spill L3) ==\n");
    bench_one<2>(1 << 20);   // bpr=8192, plane_KB=16384 = 16 MB
    bench_one<4>(1 << 20);
    bench_one<8>(1 << 20);

    return 0;
}
