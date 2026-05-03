// Microbench for pprf::build_sender (plain GGM via TwoKeyPRP),
// mirror of bench_cggm.cpp for direct comparison.
//
// Per-tree work:
//   - leaves = 2^d; expansions = 2^d - 1; AES calls per child = 1
//     (TwoKeyPRP uses ParaEnc<2,N> so each parent → 2 children
//     with 2 AES calls total, i.e. 1 AES per child).
//   - Reports MH/s where M H = M "hash calls" = 2^d - 1 per tree
//     (counting one PRP-of-parent per child for normalization with
//     bench_cggm).

#include "emp-tool/emp-tool.h"
#include "emp-ot/pprf.h"
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
	const int Q  = 1 << d;
	// pprf counts H per child: 2^d - 1 expansions worth of work.
	// To compare apples-to-apples with cggm's "H per parent"
	// (which is also 2^d - 2 ≈ 2^d - 1), we report the same metric.
	const int64_t H_per_tree = (int64_t)Q - 1;

	int64_t trees = (1LL << 28) / H_per_tree;
	if (trees < 16) trees = 16;

	block* leaves = aligned_blocks(Q);
	block* K0     = aligned_blocks(d);
	block* K1     = aligned_blocks(d);

	block root;
	PRG prg;
	prg.random_block(&root, 1);

	for (int i = 0; i < 4; ++i) pprf::build_sender(d, root, leaves, K0, K1);

	double best_us = 1e18;
	for (int trial = 0; trial < 5; ++trial) {
		double t0 = now_us();
		for (int64_t t = 0; t < trees; ++t)
			pprf::build_sender(d, root, leaves, K0, K1);
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

	free(leaves); free(K0); free(K1);
}

int main() {
	std::printf("# pprf via TwoKeyPRP (node_expand_4to8, ParaEnc<2,4>)\n");
	std::printf("# best of 5 trials\n");
	for (int d : {6, 8, 10, 12, 13, 14}) run(d);
	return 0;
}
