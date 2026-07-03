#ifndef EMP_OT_TUNING_H__
#define EMP_OT_TUNING_H__

#include <cstdint>
#include "emp-tool/emp-tool.h"

// Single source of truth for emp-ot's tunable performance parameters
// and LPN security parameters. Every consumer (IKNP, SoftSpoken,
// Ferret, cGGM, LpnF2, COT chosen-input wrapper) reads its knob
// from here. Edit values in this file to retune; no #defines, all
// `constexpr` so the compiler folds them.
//
// LPN security parameters live here too — they're not pure perf, but
// they're the most-tuned knobs in the codebase, and keeping them next
// to the perf knobs makes "what changes if I bump this" easier to see.

namespace emp {

// Number of base COTs consumed by Ferret's malicious chi-fold
// consistency check. Fixed at 128 because the chi-fold packs into
// one F_{2^128} block. Structural, not tunable, but lives here
// because PrimalLPNParameter's constexpr ctor folds it into M.
inline constexpr int kConsistCheckCotNum = 128;

// Ferret LPN-parameter bundle. Pre-computed `k`, `M`, and
// `refill_trees` are derived from (t, logk, tree_depth) so the
// hot-path code doesn't recompute them.
class PrimalLPNParameter { public:
    int64_t t = 0, logk = 0, tree_depth = 0;
    int64_t k = 0;            // = 1 << logk (power of 2 by construction;
                              // LpnF2 samples `(*r) & (k-1)` with no fold).
    int64_t M = 0;            // base COTs per round = k + t*tree_depth + 128
    int64_t refill_trees = 0; // = ceil(M / 2^tree_depth); the round's last
                              // refill_trees trees write next round's bases.
    constexpr PrimalLPNParameter() = default;
    constexpr PrimalLPNParameter(int64_t t_, int64_t logk_, int64_t tree_depth_)
        : t(t_), logk(logk_), tree_depth(tree_depth_),
          k(int64_t{1} << logk_),
          M(k + t_ * tree_depth_ + kConsistCheckCotNum),
          refill_trees((M + (int64_t{1} << tree_depth_) - 1) >> tree_depth_) {}
};

namespace tuning {

// ===== IKNP =====
// Chunk size in OTs per do_{send,recv}_rcot_next call. Must be a multiple of
// 128 (one IKNP matrix row's worth) and a multiple of the F_{2^128}
// gadget packing (128 OTs → one packed element).
inline constexpr int64_t iknp_chunk_ots = 2048;

// ===== COT chosen-input wrapper (emp-ot/ot.h) =====
// MITCCRH tile size: this many OT outputs hashed per ParaEnc<1, N>
// AES-NI call inside COT::send / COT::recv / send_rot / recv_rot.
// 8 keeps round-keys + plaintexts register-resident on x86 AVX-512
// and aarch64 NEON.
inline constexpr int64_t cot_chosen_input_tile = 8;

// ===== cGGM tree expand (emp-ot/common/cggm.h) =====
// Per-arch in-register tile for the children-from-parents step.
// cggm.h selects which one at compile time based on EMP_HAS_*
// (VAES-512, VAES-256, or aarch64 NEON via sse2neon).
// VAES-512: 32 lands two CCRH::H tiles on the AES interleaved path (relies on
// aes.hpp's apply_grouped emitting <=4-tile groups); a sweep on Intel Granite
// Rapids and AMD Zen 5 picks 32 over 16 at production depths d>=12. Larger
// tiles help Zen 5 further but regress Granite Rapids, so 32 is the cross-x86
// optimum. aarch64 is flat across 4..64 (within noise); 4 retained.
inline constexpr int cggm_tile_x86_vaes512 = 32;
inline constexpr int cggm_tile_x86_vaes256 = 32;
inline constexpr int cggm_tile_aarch64     = 4;

// ===== SoftSpoken =====
// Per-chunk size in 128-block units; chunk_ots = N * 128.
// Larger N = more in-register AES pipeline depth, but more L1
// pressure on the plane buffer.
// kChunkBlocks: per-chunk plane buffer is `128 * kChunkBlocks * 16 B`
// (128 KB at kcb=64, 256 KB at kcb=128, ..., 2 MB at kcb=1024). The sweet
// spot keeps the plane L1/L2-resident while still amortizing per-chunk
// setup (FS digest, malicious VW, butterfly key schedule). Values below
// are selected from local aarch64 and AWS x86_64 sweeps across k x mode.
template <int k>
constexpr int softspoken_chunk_blocks() {
    if constexpr (k <= 2)      return  64;
    else if constexpr (k <= 4) return  64;
    else                       return 128;
}
// Compile-time cap for the chunk-blocks template parameter. Sizes
// scratch buffers that get reused across chunks.
inline constexpr int softspoken_chunk_blocks_max = 1024;
// When SoftSpoken is nested inside Ferret's bootstrap, it runs
// against a smaller M (~74k base COTs for b10) so the default
// 1024-block chunk over-produces. 580 blocks = 74,240 OTs/chunk,
// sized to fit b10.M in a single SoftSpoken chunk.
inline constexpr int softspoken_ferret_bootstrap_chunk_blocks = 580;

// ===== Ferret =====
// Bootstrap nesting threshold: if param.M > this * ferret_b10.M,
// supply the round via a nested b10 instance (which itself uses
// SoftSpoken on ~74k base COTs) instead of running SoftSpoken
// directly against the larger param.M. Below the threshold, the
// cost is small enough that one level is cheaper than two.
inline constexpr int ferret_bootstrap_nest_factor = 2;

// ===== Ferret LPN parameters =====
// Selected to give ~128-bit security against the published
// regular-LPN attacks (Gauss / SD-ISD / BJMM / hybrid / esser /
// agb2) per the lpnestimator. The hybrid attack is the binding
// constraint; it gets easier with larger N at fixed k, so each t
// is the largest value the (logk, tree_depth) pair admits at the
// 128-bit floor.
inline constexpr PrimalLPNParameter ferret_b13 = PrimalLPNParameter(1900, 19, 13); // N = 15,564,800
inline constexpr PrimalLPNParameter ferret_b12 = PrimalLPNParameter(1520, 18, 12); // N =  6,225,920
inline constexpr PrimalLPNParameter ferret_b11 = PrimalLPNParameter(1170, 17, 11); // N =  2,396,160
inline constexpr PrimalLPNParameter ferret_b10 = PrimalLPNParameter( 850, 16, 10); // N =    870,400

// ===== LPN encoder (LpnF2) =====
// XOR positions per LPN output (the "d" of LPN(n, k, d)).
inline constexpr int lpn_d = 10;
// LpnF2::compute_slice batch size (outputs per AES-PRG inner batch)
// and the table size above which Lpn's gather prefetch pays. Both are
// per-platform, swept like the cggm tiles:
//   x86 (swept on Zen 5, 1 MiB private L2): 64 independent accumulator
//   chains beat 32 at every table size, and prefetching the next
//   outputs' gather targets pays once the pre table falls out of L2
//   (crossover ~2 MiB) -- below that the out-of-order window already
//   covers the latency and the prefetches are pure overhead.
//   aarch64 (swept on Apple M4, large shared L2): both changes REGRESS
//   at production table sizes -- the big L2 keeps the table
//   cache-resident and the wider batch thrashes -- so ARM keeps the
//   original settings (M=32, prefetch never).
#ifdef __x86_64__
inline constexpr int     lpn_batch_m = 64;
inline constexpr int64_t lpn_prefetch_min_table_bytes = 2ll << 20;
#else
inline constexpr int     lpn_batch_m = 32;
inline constexpr int64_t lpn_prefetch_min_table_bytes = INT64_MAX;
#endif

}  // namespace tuning
}  // namespace emp

#endif  // EMP_OT_TUNING_H__
