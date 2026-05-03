// Microbench for cggm::build_sender at various depths.
//
// Reports:
//   - trees/sec
//   - effective M H/sec (total H per tree = 2^d - 2; one tree =
//     2^d-2 calls to CCRH::H, batched by the kTile inside cggm.h).
//
// Compare this to bench_aes_batch's standalone CCRH::H<kTile>
// throughput to see how much overhead the cGGM scaffolding (tile
// loop, level-sum compute, copy-in/out of parents_buf) adds on
// top of the raw AES.

#include "emp-tool/emp-tool.h"
#include "emp-ot/cggm.h"
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <algorithm>
using namespace emp;

static double now_us() {
	using clk = std::chrono::high_resolution_clock;
	auto t = clk::now().time_since_epoch();
	return std::chrono::duration<double, std::micro>(t).count();
}

static block* aligned_blocks(int n) {
	void* p = nullptr;
	if (posix_memalign(&p, 16, sizeof(block) * (size_t)n) != 0) std::abort();
	return (block*)p;
}

static void run(int d) {
	const int Q  = 1 << d;          // leaves per tree
	const int K  = d;               // K0 size = d
	const int64_t H_per_tree = (int64_t)Q - 2;

	// Pick number of trees so total H ≈ 2^28 (matches bench_aes_batch).
	int64_t trees = (1LL << 28) / H_per_tree;
	if (trees < 16) trees = 16;

	block* leaves = aligned_blocks(Q);
	block* K0     = aligned_blocks(K);

	block Delta, k;
	PRG prg;
	prg.random_block(&Delta, 1);
	prg.random_block(&k,     1);

	// Warmup
	for (int i = 0; i < 4; ++i) cggm::build_sender(d, Delta, k, leaves, K0);

	double best_us = 1e18;
	for (int trial = 0; trial < 5; ++trial) {
		double t0 = now_us();
		for (int64_t t = 0; t < trees; ++t)
			cggm::build_sender(d, Delta, k, leaves, K0);
		double dt = now_us() - t0;
		best_us = std::min(best_us, dt);
	}

	volatile uint64_t sink = 0;
	for (int j = 0; j < Q; ++j) sink ^= _mm_extract_epi64(leaves[j], 0);
	(void)sink;

	double secs = best_us / 1e6;
	double trees_per_sec = (double)trees / secs;
	int64_t total_H = trees * H_per_tree;
	double mh = (double)total_H / secs / 1e6;
	double ns_per_h = best_us * 1000.0 / (double)total_H;

	std::printf("  d=%2d  Q=%-6d  H/tree=%-8lld  trees=%-7lld  "
	            "trees/s=%9.2f  MH/s=%7.2f  ns/H=%6.3f\n",
	            d, Q, (long long)H_per_tree, (long long)trees,
	            trees_per_sec, mh, ns_per_h);

	free(leaves); free(K0);
}

int main() {
	std::printf("# kTile = %d\n", cggm::kTile);
	std::printf("# best of 5 trials, in-cache for small d, ~L2 for d=13+\n");
	for (int d : {6, 8, 10, 12, 13, 14}) run(d);
	return 0;
}
