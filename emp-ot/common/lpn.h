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
class Lpn { private:
    int mask;
    bool prefetch_;   // table larger than L2 -> gather prefetch pays (see compute_block)
    PRG prg_;

    // Fold one block of M output positions starting at i, drawing the
    // index randomness from `prg`. Reads d pseudo-random indices per
    // output (advancing `prg` by ceil(M*d/4) blocks), then accumulates
    // pre[idx[j]] into out[i+m]. Inserts a partial-reduce every
    // kLpnSafeAddsPerReduce adds and a final-reduce per output.
    //
    // At production table sizes `pre` lives beyond L2 (e.g. ferret_b13:
    // 2^19 blocks = 8 MiB), so the d random gathers per output are
    // latency-bound; all M*d indices sit in tmp[] before the fold
    // starts, so each output's fold can prefetch the targets of the
    // output kLpnPrefetchAhead positions ahead. Measured on Zen 5, the
    // prefetch pays only once the table exceeds L2 (crossover ~2 MiB);
    // below that the out-of-order core already covers the latency and
    // the extra instructions are pure overhead — hence the Prefetch
    // template split, selected per instance from the table size.
    static constexpr int kLpnPrefetchAhead = 4;
    template <int M, bool Prefetch>
    void compute_block(PRG & prg, AuthValue * __restrict out,
                       const AuthValue * __restrict pre, int64_t i) const {
        constexpr int kNeededBlocks = (M * d + 3) / 4;
        block tmp[kNeededBlocks];
        prg.random_block(tmp, kNeededBlocks);
        const uint32_t* r = (const uint32_t*)(tmp);
        const int lmask = mask;
        constexpr int kStep = (AuthValue::kLpnSafeAddsPerReduce < d)
                              ? AuthValue::kLpnSafeAddsPerReduce : d;
        constexpr int kPf = kLpnPrefetchAhead;
        if constexpr (Prefetch) {
            const int pf_head = (M < kPf) ? M : kPf;
            for (int m = 0; m < pf_head; ++m)
                for (int j = 0; j < d; ++j)
                    __builtin_prefetch(pre + (r[(size_t)m * d + j] & lmask), 0, 3);
        }
        for (int m = 0; m < M; ++m) {
            if constexpr (Prefetch) {
                if (m + kPf < M) {
                    const uint32_t* rp = r + (size_t)(m + kPf) * d;
                    for (int j = 0; j < d; ++j)
                        __builtin_prefetch(pre + (rp[j] & lmask), 0, 3);
                }
            }
            const uint32_t* rm = r + (size_t)m * d;
            AuthValue acc = out[i+m];
            int j = 0;
            while (j < d) {
                const int batch_end = std::min(j + kStep, d);
                for (; j < batch_end; ++j) {
                    const int idx = (int)(rm[j] & lmask);
                    AuthValue::auth_add_into(acc, pre[idx]);
                }
                if (j < d) AuthValue::auth_partial_reduce(acc);
            }
            AuthValue::auth_final_reduce(acc);
            out[i+m] = acc;
        }
    }

    // Dispatch a whole slice at one Prefetch setting (chosen per instance
    // in the constructor from the table size).
    template <bool Prefetch>
    void compute_slice_(PRG & prg, AuthValue *out, const AuthValue *pre,
                        int64_t length) const {
        constexpr int M = tuning::lpn_batch_m;
        int64_t j = 0;
        for (; j + M <= length; j += M) compute_block<M, Prefetch>(prg, out, pre, j);
        for (; j + 4 <= length; j += 4) compute_block<4, Prefetch>(prg, out, pre, j);
        for (; j < length; ++j)         compute_block<1, Prefetch>(prg, out, pre, j);
    }

public:
    explicit Lpn(int k_)
        : mask(k_ - 1),
          prefetch_((int64_t)k_ * (int64_t)sizeof(AuthValue) >
                    tuning::lpn_prefetch_min_table_bytes) {}
    void reseed(block seed) { prg_.reseed(&seed); }

    // The instance's PRG key (= reseed() seed). A caller can build a PRG
    // from it and seek its counter to fold an arbitrary chunk
    // independently of prg_'s position — used for order-independent,
    // thread-safe slicing (see SilentFerret::produce_range).
    block prg_key() const { return prg_.seed(); }

    // Exact number of PRG blocks compute_slice() consumes for one chunk
    // of `length` outputs. Deterministic in (length, d), so chunk k's
    // PRG offset = k * blocks_per_chunk(length).
    uint64_t blocks_per_chunk(int64_t length) const {
        constexpr int M = tuning::lpn_batch_m;
        uint64_t blocks = 0;
        int64_t j = 0;
        for (; j + M <= length; j += M) blocks += (uint64_t)(M * d + 3) / 4;
        for (; j + 4 <= length; j += 4) blocks += (uint64_t)(4 * d + 3) / 4;
        for (; j < length; ++j)         blocks += (uint64_t)(1 * d + 3) / 4;
        return blocks;
    }

    // Process `length` consecutive output positions, drawing index
    // randomness from the caller-owned `prg`. Reentrant (no shared
    // state): callers fork a PRG per task/range for parallel slicing.
    // M-batched first (tuning::lpn_batch_m), then 4-batched, then tail.
    void compute_slice(PRG & prg, AuthValue *out, const AuthValue *pre,
                       int64_t length) const {
        if (prefetch_) compute_slice_<true>(prg, out, pre, length);
        else           compute_slice_<false>(prg, out, pre, length);
    }

    // Back-compat: fold a chunk using the instance's own advancing PRG.
    // (Ferret / sVOLE serial path; advances prg_ by blocks_per_chunk.)
    void compute_slice(AuthValue *out, const AuthValue *pre, int64_t length) {
        compute_slice(prg_, out, pre, length);
    }
};

}  // namespace emp
#endif
