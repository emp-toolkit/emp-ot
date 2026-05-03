// Batch-size benchmark for CCRH::H (= one-key fixed-key AES + linear
// orthomorphism, the cGGM hash). Helps decide the optimal batch
// size for the cGGM tree expander.
//
// One AES key, fixed total work per batch size, multiple trials.
// Reports throughput (M H/s) and time per H (ns) for each batch size.

#include "emp-tool/emp-tool.h"
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <algorithm>
using namespace emp;

// Total H calls per measurement (chosen so the smallest-batch run
// still completes in well under a second on a slow machine, and the
// largest-batch run is long enough to dwarf timer overhead).
static constexpr int64_t kTotalH = 1LL << 28;  // 256M H (~0.4s at peak 700 MH/s)

static double now_us() {
	using clk = std::chrono::high_resolution_clock;
	auto t = clk::now().time_since_epoch();
	return std::chrono::duration<double, std::micro>(t).count();
}

// 16-byte-aligned block buffer.
static block* aligned_blocks(int n) {
	void* p = nullptr;
	if (posix_memalign(&p, 16, sizeof(block) * (size_t)n) != 0) std::abort();
	return (block*)p;
}

template <int N>
double run_compile(CCRH& ccrh, block* in, block* out) {
	const int64_t calls = kTotalH / N;
	for (int i = 0; i < 4; ++i) ccrh.H<N>(out, in);
	double best_us = 1e18;
	for (int trial = 0; trial < 5; ++trial) {
		double t0 = now_us();
		for (int64_t c = 0; c < calls; ++c) ccrh.H<N>(out, in);
		double dt = now_us() - t0;
		best_us = std::min(best_us, dt);
	}
	volatile uint64_t sink = 0;
	for (int i = 0; i < N; ++i) sink ^= _mm_extract_epi64(out[i], 0);
	(void)sink;
	return best_us;
}

double run_runtime_Hn(CCRH& ccrh, int N, block* in, block* out, block* scratch) {
	const int64_t calls = kTotalH / N;
	for (int i = 0; i < 4; ++i) ccrh.Hn(out, in, N, scratch);
	double best_us = 1e18;
	for (int trial = 0; trial < 5; ++trial) {
		double t0 = now_us();
		for (int64_t c = 0; c < calls; ++c) ccrh.Hn(out, in, N, scratch);
		double dt = now_us() - t0;
		best_us = std::min(best_us, dt);
	}
	volatile uint64_t sink = 0;
	for (int i = 0; i < N; ++i) sink ^= _mm_extract_epi64(out[i], 0);
	(void)sink;
	return best_us;
}

int main() {
	CCRH ccrh;  // single AES key (zero_block by default)

	constexpr int kMaxN = 256;
	block* in      = aligned_blocks(kMaxN);
	block* out     = aligned_blocks(kMaxN);
	block* scratch = aligned_blocks(kMaxN);
	PRG prg;
	prg.random_block(in, kMaxN);

	std::printf("# total H calls per measurement: %lld\n", (long long)kTotalH);
	std::printf("# best of 5 trials, in-cache (input/output stays in L1)\n");
	std::printf("# %-6s %-10s %-12s %-12s\n", "N", "API", "MH/s", "ns/H");

	auto report = [&](const char* api, int N, double us) {
		double secs = us / 1e6;
		double mh   = (double)kTotalH / secs / 1e6;
		double ns_per_h = us * 1000.0 / (double)kTotalH;
		std::printf("  %-6d %-10s %-12.2f %-12.3f\n", N, api, mh, ns_per_h);
	};

	report("compile",   1, run_compile<1>(ccrh, in, out));
	report("compile",   2, run_compile<2>(ccrh, in, out));
	report("compile",   4, run_compile<4>(ccrh, in, out));
	report("compile",   8, run_compile<8>(ccrh, in, out));
	report("compile",  16, run_compile<16>(ccrh, in, out));
	report("compile",  32, run_compile<32>(ccrh, in, out));
	report("compile",  64, run_compile<64>(ccrh, in, out));
	report("compile", 128, run_compile<128>(ccrh, in, out));

	for (int N : {1, 2, 4, 8, 16, 32, 64, 128, 256}) {
		report("Hn", N, run_runtime_Hn(ccrh, N, in, out, scratch));
	}

	free(in); free(out); free(scratch);
	return 0;
}
