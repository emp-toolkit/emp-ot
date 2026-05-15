#ifndef EMP_FERRET_CONSTANTS_H__
#define EMP_FERRET_CONSTANTS_H__

#include "emp-tool/emp-tool.h"

namespace emp {
// LSB-convention masks used throughout ferret. The COT correlation
// `delta` always has bit 0 = 1, so each per-leaf SPCOT output is
// masked to clear bit 0 before the punctured leaf gets `delta` XORed
// in (so its bit 0 carries the choice signal).
inline const block lsb_clear_mask = makeBlock(0xFFFFFFFFFFFFFFFFLL,
                                              0xFFFFFFFFFFFFFFFELL);
inline const block lsb_only_mask  = makeBlock(0LL, 1LL);

// Number of base COTs consumed by the malicious chi-fold consistency
// check. Fixed at 128 because the chi-fold packs into one F_{2^128}
// block.
inline constexpr int kConsistCheckCotNum = 128;

class PrimalLPNParameter { public:
	int64_t t, logk, tree_depth;
	int64_t k;            // = 1 << logk (power of 2 by construction; the
	                      // LpnF2 sampler does `(*r) & (k-1)` with no fold).
	int64_t M;            // base COTs per round = k + t*tree_depth + 128
	int64_t refill_trees; // = ceil(M / 2^tree_depth); the round's last
	                      // refill_trees trees write next round's bases.
	PrimalLPNParameter()
		: t(0), logk(0), tree_depth(0), k(0), M(0), refill_trees(0) {}
	PrimalLPNParameter(int64_t t, int64_t logk, int64_t tree_depth)
		: t(t), logk(logk), tree_depth(tree_depth),
		  k(int64_t{1} << logk),
		  M(k + t * tree_depth + kConsistCheckCotNum) {
		const int64_t leave_n = int64_t{1} << tree_depth;
		refill_trees = (M + leave_n - 1) / leave_n;
	}
};

const static PrimalLPNParameter ferret_b13 = PrimalLPNParameter(1280, 19, 13); // N = 10,485,760
const static PrimalLPNParameter ferret_b12 = PrimalLPNParameter(1520, 18, 12); // N = 6,225,920
const static PrimalLPNParameter ferret_b11 = PrimalLPNParameter(1170, 17, 11); // N = 2,396,160
// Tentative — pending full BJMM_ISD pass. The hybrid attack
// (hardness_of_lpn / hybrid_2_quick) gives ~128.7 bits at t=850,
// logk=16, tree_depth=10; all other (cheaper) attacks land ≥ 131 bits.
const static PrimalLPNParameter ferret_b10 = PrimalLPNParameter(850,  16, 10); // N = 870,400

}//namespace
#endif //EMP_FERRET_CONSTANTS_H__
