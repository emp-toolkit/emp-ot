#ifndef EMP_OT_LPN_F2_H__
#define EMP_OT_LPN_F2_H__

#include "emp-tool/emp-tool.h"

namespace emp {

// Implementation of local linear code on F_2^k.
//
// Each output position consumes d uint32_t pseudorandom indices; for
// each index, we XOR kk[index] into the accumulator. The randomness
// is generated via a single sequential PRG (AES-CTR keyed by
// caller-supplied seed). PRG state advances naturally as
// compute_slice is called per-tree across the round, so per-tree
// slices map cleanly onto contiguous PRG output ranges — no global
// AES counter to thread through the call chain.
//
// LpnF2 is a pure compute class — no IO, no party. The caller is
// responsible for sourcing a fresh per-round seed (e.g. ferret
// passes io->get_digest() from its IOChannel FS transcript) and
// reseeding before the first compute_slice of each round.
template<int d = 10>
class LpnF2 { public:
	int k, mask;
	PRG prg_;

	// k must be a power of 2 (PrimalLPNParameter pins it via logk):
	// `(*r) & (k-1)` is then uniform on [0, k) with no rejection step.
	explicit LpnF2(int k) : k(k), mask(k - 1) {}

	// Reseed the internal PRG. Caller picks the seed source — for
	// ferret, that's io->get_digest() snapshotted once per round.
	// Subsequent compute_slice calls in the same round consume the
	// PRG sequentially.
	void reseed(block seed) { prg_.reseed(&seed); }

	// Process M outputs per AES batch. Larger M = more in-flight
	// kk loads — kk lives in L2 at production sizes, so per-output
	// throughput is gated by load-queue / MSHR depth, not arithmetic.
	// __restrict + local k/mask let the compiler keep nn[i+m] in a
	// register across the d-iter fold instead of round-tripping
	// through L1 between every XOR.
	template <int M>
	void compute_block(block * __restrict nn, const block * __restrict kk,
	                   int64_t i) {
		// Each output needs d uint32_t indices. PRG generates 4 per
		// block, so ceil(M*d/4) PRG blocks suffice.
		constexpr int kNeededBlocks = (M * d + 3) / 4;
		block tmp[kNeededBlocks];
		prg_.random_block(tmp, kNeededBlocks);
		const uint32_t* r = (const uint32_t*)(tmp);
		const int lk = k, lmask = mask;
		for (int m = 0; m < M; ++m) {
			block acc = nn[i+m];
			for (int j = 0; j < d; ++j) {
				int index = (*r) & lmask;
				++r;
				acc = acc ^ kk[index];
			}
			nn[i+m] = acc;
		}
	}

	// Streaming API for ferret's per-tree LPN slicing.
	//
	// compute_slice(out, kk, length): consume `length * d/4` PRG blocks
	// (rounded up by batching) sequentially from prg_ and write
	// `length` LPN-folded blocks to out[0..length).
	//
	// Caller is responsible for calling compute_slice in the natural
	// per-tree order within a round: tree 0's slice, then tree 1's,
	// etc. PRG state advances monotonically; consuming slices in the
	// expected order preserves the round-fixed LPN matrix.
	void compute_slice(block * out, const block * kk, int64_t length) {
#ifndef LPN_BATCH_M
#define LPN_BATCH_M 32
#endif
		int j = 0;
		for(; j + LPN_BATCH_M <= length; j += LPN_BATCH_M)
			compute_block<LPN_BATCH_M>(out, kk, j);
		for(; j + 4 <= length; j += 4)   compute_block<4>(out, kk, j);
		for(; j < length; ++j)           compute_block<1>(out, kk, j);

	}
};

}  // namespace emp
#endif
