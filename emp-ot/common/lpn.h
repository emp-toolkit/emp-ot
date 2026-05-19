#ifndef EMP_OT_LPN_H__
#define EMP_OT_LPN_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/tuning.h"
#include <algorithm>

// Generic LPN linear-code amplifier. One file, one function shape,
// works for Ferret (AuthValue=AuthValueFerret, single-block carrier,
// XOR) and sVOLE (AuthValueF2k: block val+mac, XOR; AuthValueFp:
// uint64 val+mac, mod-p add with periodic partial reduction).
//
// Each output position consumes d uint32_t pseudorandom indices; for
// each index, pre[index] is folded into the accumulator via
// AuthValue::auth_add_into. Randomness comes from a sequential PRG
// keyed by reseed(); PRG state advances naturally across
// compute_slice calls, so per-tree (Ferret) or per-chunk (sVOLE)
// slicing maps cleanly onto contiguous PRG output ranges.
//
// k must be a power of 2 (callers' LPN parameters pin it via logk in
// PrimalLPNParameter): idx = r & (k-1) is then uniform on [0, k)
// with no rejection step.
//
// AuthValue contract (provided by the concrete carrier type itself —
// AuthValueFerret / AuthValueF2k / AuthValueFp):
//   static constexpr int kLpnSafeAddsPerReduce;     // INT_MAX for F2,
//                                                   // 5 for Mersenne Fp
//   static void auth_add_into(AuthValue&, const AuthValue&);
//   static void auth_partial_reduce(AuthValue&);    // no-op on F2
//   static void auth_final_reduce(AuthValue&);      // no-op on F2

namespace emp {

template <typename AuthValue, int d = tuning::lpn_d>
class Lpn { public:
    int k, mask;
    PRG prg_;

    explicit Lpn(int k_) : k(k_), mask(k_ - 1) {}
    void reseed(block seed) { prg_.reseed(&seed); }

    // Fold one block of M output positions starting at i. Reads d
    // pseudo-random indices per output from prg_ (advancing by
    // ceil(M*d/4) blocks), then accumulates pre[idx[j]] into out[i+m].
    // Inserts a partial-reduce every kLpnSafeAddsPerReduce adds, and a
    // final-reduce at the end of each output.
    template <int M>
    void compute_block(AuthValue * __restrict out,
                       const AuthValue * __restrict pre, int64_t i) {
        constexpr int kNeededBlocks = (M * d + 3) / 4;
        block tmp[kNeededBlocks];
        prg_.random_block(tmp, kNeededBlocks);
        const uint32_t* r = (const uint32_t*)(tmp);
        const int lmask = mask;
        constexpr int kStep = (AuthValue::kLpnSafeAddsPerReduce < d)
                              ? AuthValue::kLpnSafeAddsPerReduce : d;
        for (int m = 0; m < M; ++m) {
            AuthValue acc = out[i+m];
            int j = 0;
            while (j < d) {
                const int batch_end = std::min(j + kStep, d);
                for (; j < batch_end; ++j) {
                    const int idx = (int)((*r) & lmask);
                    ++r;
                    AuthValue::auth_add_into(acc, pre[idx]);
                }
                if (j < d) AuthValue::auth_partial_reduce(acc);
            }
            AuthValue::auth_final_reduce(acc);
            out[i+m] = acc;
        }
    }

    // Process `length` consecutive output positions. M-batched first
    // (tuning::lpn_batch_m), then 4-batched, then scalar — matches
    // the previous LpnF2 / LpnFp dispatch shape.
    void compute_slice(AuthValue *out, const AuthValue *pre, int64_t length) {
        constexpr int M = tuning::lpn_batch_m;
        int64_t j = 0;
        for (; j + M <= length; j += M) compute_block<M>(out, pre, j);
        for (; j + 4 <= length; j += 4) compute_block<4>(out, pre, j);
        for (; j < length; ++j)         compute_block<1>(out, pre, j);
    }
};

}  // namespace emp
#endif
