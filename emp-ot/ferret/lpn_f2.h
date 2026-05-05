#ifndef EMP_OT_LPN_F2_H__
#define EMP_OT_LPN_F2_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/test_random.h"

namespace emp {

//Implementation of local linear code on F_2^k
//Performance highly dependent on the CPU cache size
template<int d = 10>
class LpnF2 { public:
	int party;
	int64_t n;
	ThreadPool * pool;
	IOChannel *io;
	int threads, k, mask;
	block seed;
	LpnF2 (int party, int64_t n, int k, ThreadPool * pool, IOChannel *io, int threads) {
		this->party = party;
		this->k = k;
		this->n = n;
		this->pool = pool;
		this->io = io;
		this->threads = threads;
		mask = 1;
		while(mask < k) {
			mask <<=1;
			mask = mask | 0x1;
		}
	}

	// Process M outputs per AES batch. Larger M = more in-flight kk
	// loads, which matters at production k where kk (1.9-7.2 MB) lives
	// in L2 and per-output throughput is gated by load-queue / MSHR
	// depth, not arithmetic.  __restrict + local k/mask let the
	// compiler keep nn[i+m] in a register across the d-iter fold
	// instead of round-tripping through L1 between every XOR.
	template <int M>
	void compute_block(block * __restrict nn, const block * __restrict kk,
	                   int64_t i, PRP * prp) {
		// Each output needs d uint32_t indices. AES generates 4 per
		// block, so ceil(M*d/4) AES blocks suffice.
		constexpr int kNeededBlocks = (M * d + 3) / 4;
		block tmp[kNeededBlocks];
		for(int b = 0; b < kNeededBlocks; ++b)
			tmp[b] = makeBlock(i, b);
		AES_ecb_encrypt_blks(tmp, kNeededBlocks, &prp->aes);
		const uint32_t* r = (const uint32_t*)(tmp);
		const int lk = k, lmask = mask;
		for (int m = 0; m < M; ++m) {
			block acc = nn[i+m];
			for (int j = 0; j < d; ++j) {
				int index = (*r) & lmask;
				++r;
				if (index >= lk) index -= lk;
				acc = acc ^ kk[index];
			}
			nn[i+m] = acc;
		}
	}

	void task(block * __restrict nn, const block * __restrict kk,
	          int64_t start, int64_t end) {
		PRP prp(seed);
		int64_t j = start;
		// M = outputs per AES batch. M=32 picked from a cross-platform
		// sweep at ferret_b13 (k=452K, kk=7.2 MB lives in L2/L3):
		//   Apple M2  : M=16 25.6ms ≈ M=32 25.4ms (flat past 16)
		//   Intel SR+ : M=16 78.4ms → M=32 60.5ms → M=48 62.1ms (knee=32)
		//   AMD Zen5  : M=16 25.1ms → M=32 22.9ms → M=48 23.4ms (knee=32)
		// Larger M extends the in-flight kk-load window into the L2-/L3-
		// bound regime; past 32 the live nn-accumulator set starts to
		// spill out of the 32-zmm AVX-512 pool on x86. Override at
		// compile time via -DLPN_BATCH_M=<n> for further sweeps.
#ifndef LPN_BATCH_M
#define LPN_BATCH_M 32
#endif
		for(; j + LPN_BATCH_M <= end; j += LPN_BATCH_M)
			compute_block<LPN_BATCH_M>(nn, kk, j, &prp);
		for(; j + 4 <= end; j += 4)   compute_block<4>(nn, kk, j, &prp);
		for(; j < end; ++j)           compute_block<1>(nn, kk, j, &prp);
	}

	void compute(block * nn, const block * kk, block s = zero_block) {
		vector<std::future<void>> fut;
		int64_t width = n/threads;
        if(!cmpBlock(&s, &zero_block, 1)) seed = s;
		else seed = seed_gen();
		for(int i = 0; i < threads - 1; ++i) {
			int64_t start = i * width;
			int64_t end = std::min((i+1)* width, n);
			fut.push_back(pool->enqueue([this, nn, kk, start, end]() {
				task(nn, kk, start, end);
			}));
		}
		int64_t start = (threads - 1) * width;
        	int64_t end = n;
		task(nn, kk, start, end);

		for (auto &f: fut) f.get();
	}

	block seed_gen() {
		block seed;
		if(party == ALICE) {
			if (!ferret_test::maybe_test_seed(&seed)) {
				PRG prg;
				prg.random_block(&seed, 1);
			}
			io->send_data(&seed, sizeof(block));
		} else {
			io->recv_data(&seed, sizeof(block));
		}io->flush();
		return seed;
	}

	// Local-only benchmark of the compute kernel — uses a fixed seed to
	// skip the network handshake in compute(), so callers can pass
	// io=nullptr.
	void bench(block * nn, const block * kk) {
		compute(nn, kk, makeBlock(0, 1));
	}
};

}  // namespace emp
#endif
