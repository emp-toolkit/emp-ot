// Compare SilentFerret's full materialization against two bounded-scratch
// paths: ordinary in-place LPN followed by XOR, and a fused LPN/XOR sink with
// no final store. All paths repeat from the same maliciously checked,
// post-begin current-round state; only wire-free online generation is timed.

#include "emp-ot/emp-ot.h"
#include "bench/bench.h"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <thread>
#include <vector>

using namespace emp;

namespace {

struct Config {
	const char *tag;
	PrimalLPNParameter param;
};

Config parse_config(const char *arg) {
	if (std::strcmp(arg, "b10") == 0) return {"b10", tuning::ferret_b10};
	if (std::strcmp(arg, "b11") == 0) return {"b11", tuning::ferret_b11};
	if (std::strcmp(arg, "b13") == 0) return {"b13", tuning::ferret_b13};
	expecting(false, "bench_silentferret_sink: parameter must be b10, b11, or b13");
	return {"b13", tuning::ferret_b13};
}

int parse_positive(const char *arg, const char *message) {
	char *end = nullptr;
	const long value = std::strtol(arg, &end, 10);
	expecting(arg[0] != '\0' && end != nullptr && *end == '\0' && value > 0 &&
	              value <= std::numeric_limits<int>::max(),
	          message);
	return (int)value;
}

block xor_blocks(const block *data, int64_t n) {
	block sums[4] = {zero_block, zero_block, zero_block, zero_block};
	for (int64_t i = 0; i < n; ++i)
		sums[i & 3] = sums[i & 3] ^ data[i];
	return (sums[0] ^ sums[1]) ^ (sums[2] ^ sums[3]);
}

void produce_full(SilentFerret& ot, block *out, int64_t n_trees,
	              int threads) {
	const int64_t chunk = ot.chunk_size();
	if (threads == 1) {
		ot.produce_range(out, 0, n_trees);
		return;
	}

	const int64_t first = (n_trees + 1) / 2;
	std::thread worker([&ot, out, chunk, first, n_trees]() {
		ot.produce_range(out + first * chunk, first, n_trees - first);
	});
	ot.produce_range(out, 0, first);
	worker.join();
}

block produce_scratch_xor(SilentFerret& ot, std::vector<BlockVec>& scratch,
	                      int64_t n_trees, int threads) {
	if (threads == 1)
		return ot.produce_range_scratch_xor(scratch[0].data(), 0, n_trees);

	const int64_t first = (n_trees + 1) / 2;
	std::array<block, 2> sums = {zero_block, zero_block};
	std::thread worker([&ot, &scratch, &sums, first, n_trees]() {
		sums[1] = ot.produce_range_scratch_xor(
		    scratch[1].data(), first, n_trees - first);
	});
	sums[0] = ot.produce_range_scratch_xor(scratch[0].data(), 0, first);
	worker.join();
	return sums[0] ^ sums[1];
}

block produce_fused_xor(SilentFerret& ot, std::vector<BlockVec>& scratch,
	                    int64_t n_trees, int threads) {
	if (threads == 1)
		return ot.produce_range_fused_xor(scratch[0].data(), 0, n_trees);

	const int64_t first = (n_trees + 1) / 2;
	std::array<block, 2> sums = {zero_block, zero_block};
	std::thread worker([&ot, &scratch, &sums, first, n_trees]() {
		sums[1] = ot.produce_range_fused_xor(
		    scratch[1].data(), first, n_trees - first);
	});
	sums[0] = ot.produce_range_fused_xor(scratch[0].data(), 0, first);
	worker.join();
	return sums[0] ^ sums[1];
}

double median(std::vector<double> samples) {
	std::sort(samples.begin(), samples.end());
	const size_t mid = samples.size() / 2;
	if ((samples.size() & 1U) != 0) return samples[mid];
	return (samples[mid - 1] + samples[mid]) * 0.5;
}

template <typename F>
double time_online(NetIO *io, F&& fn) {
	io->sync();
	const uint64_t sent_before = io->send_counter;
	const uint64_t recv_before = io->recv_counter;
	auto start = clock_start();
	fn();
	const double elapsed_us = (double)time_from(start);
	expecting(io->send_counter == sent_before &&
	              io->recv_counter == recv_before,
	          "bench_silentferret_sink: timed generation performed wire I/O");
	return elapsed_us;
}

}  // namespace

int main(int argc, char **argv) {
	if (argc > 6) {
		std::cerr << "usage: " << argv[0]
		          << " <party> [b10|b11|b13] [threads:1|2] [warmups] [reps]"
		          << std::endl;
		return 2;
	}
	const int party = parse_party(argv);
	const Config config = parse_config(argc > 2 ? argv[2] : "b13");
	const int threads =
	    argc > 3 ? parse_positive(argv[3], "threads must be 1 or 2") : 1;
	expecting(threads == 1 || threads == 2,
	          "bench_silentferret_sink: threads must be 1 or 2");
	const int warmups =
	    argc > 4 ? parse_positive(argv[4], "warmups must be positive") : 2;
	const int reps =
	    argc > 5 ? parse_positive(argv[5], "repetitions must be positive") : 9;
	expecting(reps >= 3,
	          "bench_silentferret_sink: use at least three repetitions");

	const int port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port)
	                           : NetIO::connect(peer_ip(), port);
	SilentFerret ot(party, io.get(), /*malicious=*/true, config.param, nullptr,
	                threads);
	const int64_t chunk = ot.chunk_size();
	const int64_t n_trees = ot.round_capacity();
	const int64_t n_cots = n_trees * chunk;

	BlockVec full((size_t)n_cots);
	pretouch_blocks(full.data(), n_cots);
	std::vector<BlockVec> scratch((size_t)threads);
	for (BlockVec& worker_scratch : scratch) {
		worker_scratch.resize((size_t)chunk);
		pretouch_blocks(worker_scratch.data(), chunk);
	}

	io->sync();
	ot.begin();
	io->sync();

	// Establish and validate the reference outside every timing window. These
	// calls also make instruction/data cold-start effects precede the warmups.
	produce_full(ot, full.data(), n_trees, threads);
	const block expected = xor_blocks(full.data(), n_cots);
	block initial_scratch = zero_block;
	block initial_fused = zero_block;
	if (threads == 1) {
		initial_scratch =
		    ot.produce_range_scratch_xor(scratch[0].data(), 0, n_trees);
		initial_fused =
		    ot.produce_range_fused_xor(scratch[0].data(), 0, n_trees);
	} else {
		const int64_t first = (n_trees + 1) / 2;
		const int64_t first_cots = first * chunk;
		const block expected_first = xor_blocks(full.data(), first_cots);
		const block expected_second =
		    xor_blocks(full.data() + first_cots, n_cots - first_cots);
		const block scratch_first =
		    ot.produce_range_scratch_xor(scratch[0].data(), 0, first);
		const block scratch_second = ot.produce_range_scratch_xor(
		    scratch[1].data(), first, n_trees - first);
		const block fused_first =
		    ot.produce_range_fused_xor(scratch[0].data(), 0, first);
		const block fused_second = ot.produce_range_fused_xor(
		    scratch[1].data(), first, n_trees - first);
		expecting(cmpBlock(&expected_first, &scratch_first, 1) &&
		              cmpBlock(&expected_second, &scratch_second, 1),
		          "bench_silentferret_sink: scratch partition XOR mismatch");
		expecting(cmpBlock(&expected_first, &fused_first, 1) &&
		              cmpBlock(&expected_second, &fused_second, 1),
		          "bench_silentferret_sink: fused partition XOR mismatch");
		initial_scratch = scratch_first ^ scratch_second;
		initial_fused = fused_first ^ fused_second;
	}
	expecting(cmpBlock(&expected, &initial_scratch, 1),
	          "bench_silentferret_sink: materialize/scratch XOR mismatch");
	expecting(cmpBlock(&expected, &initial_fused, 1),
	          "bench_silentferret_sink: materialize/fused XOR mismatch");

	std::vector<double> materialize_us;
	std::vector<double> scratch_us;
	std::vector<double> fused_us;
	materialize_us.reserve((size_t)reps);
	scratch_us.reserve((size_t)reps);
	fused_us.reserve((size_t)reps);
	for (int iteration = 0; iteration < warmups + reps; ++iteration) {
		double one_materialize = 0.0;
		double one_scratch = 0.0;
		double one_fused = 0.0;
		block scratch_result = zero_block;
		block fused_result = zero_block;
		for (int step = 0; step < 3; ++step) {
			const int path = (iteration + step) % 3;
			if (path == 0) {
				one_materialize = time_online(io.get(), [&]() {
					produce_full(ot, full.data(), n_trees, threads);
				});
			} else if (path == 1) {
				one_scratch = time_online(io.get(), [&]() {
					scratch_result =
					    produce_scratch_xor(ot, scratch, n_trees, threads);
				});
			} else {
				one_fused = time_online(io.get(), [&]() {
					fused_result =
					    produce_fused_xor(ot, scratch, n_trees, threads);
				});
			}
		}
		expecting(cmpBlock(&expected, &scratch_result, 1),
		          "bench_silentferret_sink: timed scratch XOR mismatch");
		expecting(cmpBlock(&expected, &fused_result, 1),
		          "bench_silentferret_sink: timed fused XOR mismatch");
		if (iteration >= warmups) {
			materialize_us.push_back(one_materialize);
			scratch_us.push_back(one_scratch);
			fused_us.push_back(one_fused);
		}
	}

	const block final_full = xor_blocks(full.data(), n_cots);
	expecting(cmpBlock(&expected, &final_full, 1),
	          "bench_silentferret_sink: timed baseline XOR mismatch");
	ot.end();

	const double materialize_median_us = median(materialize_us);
	const double scratch_median_us = median(scratch_us);
	const double fused_median_us = median(fused_us);
	const double materialize_mot_s = (double)n_cots / materialize_median_us;
	const double scratch_mot_s = (double)n_cots / scratch_median_us;
	const double fused_mot_s = (double)n_cots / fused_median_us;
	std::cout << std::fixed << std::setprecision(2)
	          << "SilentFerret sink " << config.tag << " mali "
	          << (party == ALICE ? "sender" : "receiver")
	          << " threads=" << threads << " trees=" << n_trees
	          << " cots=" << n_cots << " warmups=" << warmups
	          << " reps=" << reps << " materialize=" << materialize_mot_s
	          << " MOT/s scratch+xor=" << scratch_mot_s
	          << " MOT/s fused-xor/no-final-store=" << fused_mot_s
	          << " MOT/s scratch-speedup="
	          << (materialize_median_us / scratch_median_us)
	          << "x fused-speedup="
	          << (materialize_median_us / fused_median_us)
	          << "x xor=ok" << std::endl;
	return 0;
}
