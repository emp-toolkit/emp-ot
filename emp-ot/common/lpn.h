#ifndef EMP_OT_LPN_H__
#define EMP_OT_LPN_H__

#include "emp-tool/emp-tool.h"
#include "emp-ot/tuning.h"
#include <algorithm>

// Generic LPN linear-code amplifier, one class for every carrier: Ferret
// (AuthValueFerret: single block, XOR), F_p sVOLE (AuthValueFp: uint64
// val+mac, mod-p adds with periodic partial reduction), and GF(2^128) sVOLE
// (AuthValueF2k: block val+mac, field coefficients).
//
// Each output position reads d uint32_t pseudorandom indices into the
// k-entry secret `pre` and adds those entries into the output. A carrier
// either adds them as they are (unit entries) or, if it declares
// kLpnCoefficients, multiplies each one by its own pseudorandom field element
// first. Randomness comes from a sequential PRG keyed by reseed(); PRG state
// advances naturally across compute_slice calls, so per-tree (Ferret) or
// per-chunk (sVOLE) slicing maps cleanly onto contiguous PRG output ranges.
//
// k must be a power of 2 (callers' LPN parameters pin it via logk in
// PrimalLPNParameter): idx = r & (k-1) is then uniform on [0, k)
// with no rejection step.
//
// AuthValue contract (provided by the concrete carrier type itself —
// AuthValueFerret / AuthValueF2k / AuthValueFp). Unit-entry carriers:
//   static constexpr int kLpnSafeAddsPerReduce;     // INT_MAX for F2,
//                                                   // 5 for Mersenne Fp
//   static void auth_add_into(AuthValue&, const AuthValue&);
//   static void auth_partial_reduce(AuthValue&);    // no-op on F2
//   static void auth_final_reduce(AuthValue&);      // no-op on F2
// Coefficient carriers ({block val; block mac;} over GF(2^128)) instead:
//   static constexpr bool kLpnCoefficients = true;

namespace emp {

template <typename AuthValue>
inline constexpr bool lpn_has_coefficients =
    requires { requires AuthValue::kLpnCoefficients; };

template <typename AuthValue, int d = tuning::lpn_d>
class Lpn { private:
    static constexpr bool kCoef = lpn_has_coefficients<AuthValue>;
    int mask;
    bool fold_val_ = true;
    PRG prg_;

    // Fold one block of M output positions starting at i, drawing the
    // index randomness from `prg`. Reads d pseudo-random indices per
    // output (advancing `prg` by ceil(M*d/4) blocks), then accumulates
    // pre[idx[j]] into out[i+m]. Inserts a partial-reduce every
    // kLpnSafeAddsPerReduce adds and a final-reduce per output.
    template <int M>
    void compute_block(PRG & prg, AuthValue * __restrict out,
                       const AuthValue * __restrict pre, int64_t i) const {
        constexpr int kNeededBlocks = (M * d + 3) / 4;
        block tmp[kNeededBlocks];
        prg.random_block(tmp, kNeededBlocks);
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

    // Variant of compute_block that exposes each finalized value to a
    // caller-supplied sink instead of writing it back to `initial`. The sink
    // receives (position, value), with positions ordered over the slice.
    template <int M, typename Sink>
    void compute_block_sink(PRG & prg,
                            const AuthValue * __restrict initial,
                            const AuthValue * __restrict pre, int64_t i,
                            Sink & sink) const {
        constexpr int kNeededBlocks = (M * d + 3) / 4;
        block tmp[kNeededBlocks];
        prg.random_block(tmp, kNeededBlocks);
        const uint32_t* r = (const uint32_t*)(tmp);
        const int lmask = mask;
        constexpr int kStep = (AuthValue::kLpnSafeAddsPerReduce < d)
                              ? AuthValue::kLpnSafeAddsPerReduce : d;
        for (int m = 0; m < M; ++m) {
            AuthValue acc = initial[i+m];
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
            sink(i + m, acc);
        }
    }

    // ---- Coefficient carriers ----
    //
    // Output r becomes out[r] + Σ_l a_{r,l}·pre[idx_{r,l}], with its own
    // pseudorandom field element a_{r,l} at every matrix entry, applied to
    // val and mac alike (the map is F-linear, so mac = key + val·Δ carries
    // over). Rows go in groups of four. A group draws d blocks of indices
    // (row j's l-th index is uint32 word j·d + l) and then 4·d blocks of
    // coefficients (a_{j,l} is block 4·l + j: term-major, as
    // vector_inn_prdt_sum_red_x4 takes them). Each output therefore depends
    // only on where its group sits in the stream, not on the batch size, and
    // a partial last group draws a whole group.
    static constexpr int kCoefGroupBlocks = 5 * d;

    // Fold G groups of four rows starting at i; the last group writes only
    // its first `last_rows` rows. Every group's 4·d entries are copied out
    // before any group is multiplied, so the wide loads in the multiplies do
    // not wait on the narrow stores that just filled the scratch.
    template <int G, bool kFoldVal>
    void compute_groups_coef(PRG & prg, AuthValue * __restrict out,
                             const AuthValue * __restrict pre, int64_t i,
                             int last_rows) const {
        block rnd[G * kCoefGroupBlocks];
        prg.random_block(rnd, G * kCoefGroupBlocks);
        const int lmask = mask;
        block mac[G][4 * d];
        [[maybe_unused]] block val[kFoldVal ? G : 1][4 * d];
        for (int g = 0; g < G; ++g) {
            const uint32_t *w =
                reinterpret_cast<const uint32_t *>(rnd + g * kCoefGroupBlocks);
            for (int j = 0; j < 4; ++j)
                for (int l = 0; l < d; ++l) {
                    const AuthValue &e = pre[w[j * d + l] & lmask];
                    mac[g][4 * l + j] = e.mac;
                    if constexpr (kFoldVal) val[g][4 * l + j] = e.val;
                }
        }
        for (int g = 0; g < G; ++g) {
            const block *coef = rnd + g * kCoefGroupBlocks + d;
            const int rows = (g + 1 < G) ? 4 : last_rows;
            AuthValue *o = out + i + 4 * g;
            block r[4];
            vector_inn_prdt_sum_red_x4<d>(r, coef, mac[g]);
            for (int j = 0; j < rows; ++j) o[j].mac = o[j].mac ^ r[j];
            if constexpr (kFoldVal) {
                vector_inn_prdt_sum_red_x4<d>(r, coef, val[g]);
                for (int j = 0; j < rows; ++j) o[j].val = o[j].val ^ r[j];
            }
        }
    }

    // At most 16 groups per draw, so the scratch stays bounded whatever the
    // batch size; outputs depend only on stream position, not on the split.
    template <int M2, bool kFoldVal>
    void compute_slice_coef(PRG & prg, AuthValue *out, const AuthValue *pre,
                            int64_t length) const {
        static_assert(M2 % 4 == 0, "coefficient rows go in groups of 4");
        constexpr int G = (M2 / 4 < 16) ? M2 / 4 : 16;
        int64_t j = 0;
        for (; j + 4 * G <= length; j += 4 * G)
            compute_groups_coef<G, kFoldVal>(prg, out, pre, j, 4);
        for (; j + 4 <= length; j += 4)
            compute_groups_coef<1, kFoldVal>(prg, out, pre, j, 4);
        if (j < length)
            compute_groups_coef<1, kFoldVal>(prg, out, pre, j, (int)(length - j));
    }

public:
    explicit Lpn(int k_) : mask(k_ - 1) {}
    void reseed(block seed) { prg_.reseed(&seed); }

    // Coefficient carriers: fold the mac half only, for a party whose val
    // half is zero throughout. Each output's val is left as it was in `out`.
    void fold_mac_only() {
        static_assert(kCoef, "fold_mac_only: coefficient carriers only");
        fold_val_ = false;
    }

    // The instance's PRG key (= reseed() seed). A caller can build a PRG
    // from it and seek its counter to fold an arbitrary chunk
    // independently of prg_'s position — used for order-independent,
    // thread-safe slicing (see SilentFerret::produce_range).
    block prg_key() const { return prg_.seed(); }

    // Exact number of PRG blocks compute_slice() consumes for one chunk
    // of `length` outputs. Deterministic in (length, d), so chunk k's
    // PRG offset = k * blocks_per_chunk(length).
    uint64_t blocks_per_chunk(int64_t length) const {
        if constexpr (kCoef)
            return (uint64_t)((length + 3) / 4) * kCoefGroupBlocks;
        constexpr int M = tuning::lpn_batch_m;
        uint64_t blocks = 0;
        int64_t j = 0;
        for (; j + M <= length; j += M) blocks += (uint64_t)(M * d + 3) / 4;
        for (; j + 4 <= length; j += 4) blocks += (uint64_t)(4 * d + 3) / 4;
        for (; j < length; ++j)         blocks += (uint64_t)(1 * d + 3) / 4;
        return blocks;
    }

    // Tuning/test hook: fold with an explicit batch size instead of the
    // tuning.h value. Outputs and PRG consumption are identical to
    // compute_slice for any M2 with M2*d % 4 == 0 that divides `length`
    // (production fold lengths are 2^tree_depth, so the tuner's
    // candidates {16, 32, 64} qualify); a tail would consume padding
    // randomness differently per M2. Coefficient carriers draw per group of
    // four rows, so any M2 divisible by 4 gives identical results at any
    // length. test_tuning_invariance asserts these properties.
    template <int M2>
    void compute_slice_as(PRG & prg, AuthValue *out, const AuthValue *pre,
                          int64_t length) const {
        if constexpr (kCoef) {
            if (fold_val_) compute_slice_coef<M2, true>(prg, out, pre, length);
            else           compute_slice_coef<M2, false>(prg, out, pre, length);
        } else {
            int64_t j = 0;
            for (; j + M2 <= length; j += M2) compute_block<M2>(prg, out, pre, j);
            for (; j + 4 <= length; j += 4)   compute_block<4>(prg, out, pre, j);
            for (; j < length; ++j)           compute_block<1>(prg, out, pre, j);
        }
    }

    // Process `length` consecutive output positions, drawing index
    // randomness from the caller-owned `prg`. Reentrant (no shared
    // state): callers fork a PRG per task/range for parallel slicing.
    // M-batched first (tuning::lpn_batch_m), then 4-batched, then tail.
    void compute_slice(PRG & prg, AuthValue *out, const AuthValue *pre,
                       int64_t length) const {
        compute_slice_as<tuning::lpn_batch_m>(prg, out, pre, length);
    }

    // Process a slice with the same PRG consumption and finalized values as
    // compute_slice(), but call `sink(position, value)` once per output rather
    // than storing those final values back to `initial`. The initial carrier
    // values remain available for callers that reuse a bounded scratch area.
    template <typename Sink>
    void compute_slice_sink(PRG & prg, const AuthValue *initial,
                            const AuthValue *pre, int64_t length,
                            Sink && sink) const {
        static_assert(!kCoef, "compute_slice_sink: unit-entry carriers only");
        constexpr int M = tuning::lpn_batch_m;
        int64_t j = 0;
        for (; j + M <= length; j += M)
            compute_block_sink<M>(prg, initial, pre, j, sink);
        for (; j + 4 <= length; j += 4)
            compute_block_sink<4>(prg, initial, pre, j, sink);
        for (; j < length; ++j)
            compute_block_sink<1>(prg, initial, pre, j, sink);
    }

    // Back-compat: fold a chunk using the instance's own advancing PRG.
    // (Ferret / sVOLE serial path; advances prg_ by blocks_per_chunk.)
    void compute_slice(AuthValue *out, const AuthValue *pre, int64_t length) {
        compute_slice(prg_, out, pre, length);
    }
};

}  // namespace emp
#endif
