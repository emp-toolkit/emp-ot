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

class PrimalLPNParameter { public:
	int64_t n, t, k, log_bin_sz;
	PrimalLPNParameter() {}
	PrimalLPNParameter(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz)
		: n(n), t(t), k(k), log_bin_sz(log_bin_sz) {
		if (n != t * (1 << log_bin_sz))
			error("LPN parameter not matched");
	}
	int64_t buf_sz() const {
		return n - t * log_bin_sz - k - 128;
	}
};

const static PrimalLPNParameter ferret_b13 = PrimalLPNParameter(10485760, 1280, 452000, 13);
const static PrimalLPNParameter ferret_b12 = PrimalLPNParameter(10268672, 2507, 238000, 12);
const static PrimalLPNParameter ferret_b11 = PrimalLPNParameter(10180608, 4971, 124000, 11);

}//namespace
#endif //EMP_FERRET_CONSTANTS_H__
