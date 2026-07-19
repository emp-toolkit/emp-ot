#ifndef EMP_OT_TUNING_H__
#define EMP_OT_TUNING_H__

#include "emp-tool/emp-tool.h"
#include <limits>

// Single source of truth for emp-ot's tunable performance parameters
// and LPN security parameters. Every consumer (IKNP, SoftSpoken,
// Ferret, cGGM, LpnF2, COT chosen-input wrapper) reads its knob
// from here.
//
// LPN security parameters live here too — they're not pure perf, but
// they're the most-tuned knobs in the codebase, and keeping them next
// to the perf knobs makes "what changes if I bump this" easier to see.
//
// ===== Per-build-directory overrides (`make tune`) =====
//
// LOCAL-class knobs — scheduling/layout only, output- and wire-invariant,
// so parties may differ freely (see docs/performance-tuning.md for the
// LOCAL / AGREEMENT / SECURITY classification) — are macro-guarded when
// managed by the auto-tuner, and may then be overridden by a generated
// tuning_local.h. Fixed LOCAL policies are plain constexpr with an
// explicit rationale. The override header lives in the BUILD directory
// (<build>/tuning-include/emp-ot/tuning_local.h): CMake creates a canonical
// marked stub at configure time; the `tune` tool overwrites it with
// provenance comments, `tune-clean` restores the stub, and `install` ships the file
// the library objects were compiled with. Every build directory owns its
// tuning state; a source-tree tuning_local.h is a pre-redesign leftover
// and is not read by CMake builds. AGREEMENT and SECURITY knobs are plain
// constexpr, with no macro guard: tuning_local.h has no channel to reach
// them. test_tuning_invariance asserts the output-invariance of every
// guarded knob at its extreme candidate values.
#if __has_include("emp-ot/tuning_local.h")
#include "emp-ot/tuning_local.h"
#endif

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
        : t(t_), logk(logk_), tree_depth(tree_depth_) {
        // Guard every derived-value operation before evaluating it. Calls to
        // expecting(false, ...) are skipped for valid constant evaluation, so
        // the shipped presets remain constexpr while malformed runtime input
        // fails before a shift or signed multiplication can be undefined.
        if (t <= 0)
            expecting(false, "PrimalLPNParameter: t must be positive");
        if (logk < 0 || logk > 30)
            expecting(false,
                      "PrimalLPNParameter: logk must be in [0, 30]");
        if (tree_depth <= 0 || tree_depth > 30)
            expecting(false,
                      "PrimalLPNParameter: tree_depth must be in [1, 30]");

        constexpr int64_t max_i64 = std::numeric_limits<int64_t>::max();
        k = int64_t{1} << logk;
        const int64_t m_fixed = k + kConsistCheckCotNum;
        if (t > (max_i64 - m_fixed) / tree_depth)
            expecting(false, "PrimalLPNParameter: M overflows int64_t");
        M = m_fixed + t * tree_depth;

        const int64_t chunk = int64_t{1} << tree_depth;
        if (M > max_i64 - (chunk - 1))
            expecting(false,
                      "PrimalLPNParameter: refill rounding overflows int64_t");
        refill_trees = (M + chunk - 1) / chunk;
        if (refill_trees <= 0 || refill_trees >= t)
            expecting(false,
                      "PrimalLPNParameter: no user-output trees per round");
        if (t > max_i64 / chunk)
            expecting(false,
                      "PrimalLPNParameter: round output size overflows int64_t");
    }
};

// Runtime validation for user-supplied parameter bundles. The constexpr
// constructor keeps the shipped presets usable at compile time; protocol
// constructors call this before allocating, shifting, or narrowing `k` to the
// LPN kernel's int mask.
inline void validate_primal_lpn_parameter(const PrimalLPNParameter &p) {
    constexpr int64_t max_i64 = std::numeric_limits<int64_t>::max();
    expecting(p.t > 0, "PrimalLPNParameter: t must be positive");
    expecting(p.logk >= 0 && p.logk <= 30,
              "PrimalLPNParameter: logk must be in [0, 30]");
    const int64_t expected_k = int64_t{1} << p.logk;
    expecting(p.k == expected_k,
              "PrimalLPNParameter: inconsistent k/logk");
    expecting(p.tree_depth > 0 && p.tree_depth <= 30,
              "PrimalLPNParameter: tree_depth must be in [1, 30]");
    const int64_t chunk = int64_t{1} << p.tree_depth;
    const int64_t m_fixed = p.k + kConsistCheckCotNum;
    expecting(p.t <= (max_i64 - m_fixed) / p.tree_depth,
              "PrimalLPNParameter: M overflows int64_t");
    const int64_t expected_M =
        m_fixed + p.t * p.tree_depth;
    expecting(p.M == expected_M,
              "PrimalLPNParameter: inconsistent M");
    expecting(p.M <= max_i64 - (chunk - 1),
              "PrimalLPNParameter: refill rounding overflows int64_t");
    const int64_t expected_refill = (p.M + chunk - 1) / chunk;
    expecting(p.refill_trees == expected_refill,
              "PrimalLPNParameter: inconsistent refill_trees");
    expecting(p.refill_trees > 0 && p.refill_trees < p.t,
              "PrimalLPNParameter: no user-output trees per round");
    expecting(p.t <= max_i64 / chunk,
              "PrimalLPNParameter: round output size overflows int64_t");
}

namespace tuning {

// ===== IKNP =====
// Chunk size in OTs per do_{send,recv}_rcot_next call. Must be a multiple of
// 128 (one IKNP matrix row's worth) and a multiple of the F_{2^128}
// gadget packing (128 OTs → one packed element).
inline constexpr int64_t iknp_chunk_ots = 2048;

// ===== COT chosen-input wrapper (emp-ot/ot.h) =====
// LOCAL (pinned, not tuner-managed): MITCCRH tile size — this many OT
// outputs hashed per ParaEnc<1, N> AES-NI call inside COT::send /
// COT::recv / send_rot / recv_rot. 8 keeps round-keys + plaintexts
// register-resident on x86 AVX-512 and aarch64 NEON. LOCAL because
// MITCCRH keys derive from the running gid (bucketed by ReuseShift), so
// the OT-index -> key map and the pad byte stream are identical for
// every tile; only the call granularity changes (test_tuning_invariance
// asserts this). Pinned rather than macro-guarded because this is the
// one knob that shapes a class layout — COT's MITCCRH<ot_bsize> member —
// so an override would change the ABI of every COT descendant across
// differently-configured translation units, and no measured host has
// beaten the default beyond noise (`make tune` still sweeps it for the
// record).
inline constexpr int64_t cot_chosen_input_tile = 8;

// ===== cGGM tree expand (emp-ot/common/cggm.h) =====
// LOCAL (tunable). In-register tile for the children-from-parents step.
// Consumers read cggm_tile(); the per-arch selection AND any per-machine
// override resolve here, invisibly to them.
// VAES-512: 32 lands two CCRH::H tiles on the AES interleaved path (relies on
// aes.hpp's apply_grouped emitting <=4-tile groups); a sweep on Intel Granite
// Rapids and AMD Zen 5 picks 32 over 16 at production depths d>=12. Larger
// tiles help Zen 5 further but regress Granite Rapids, so 32 is the cross-x86
// optimum. aarch64 is flat across 4..64 (within noise); 4 retained.
#ifndef EMP_TUNE_CGGM_TILE
#define EMP_TUNE_CGGM_TILE 0   // 0 = use the per-arch default
#endif
// Shipped per-arch defaults (the tuner compares candidates against this).
constexpr int cggm_tile_arch_default() {
#if EMP_HAS_VAES512
    return 32;
#elif EMP_HAS_VAES256
    return 32;
#else
    return 4;
#endif
}
// The knob consumers read.
constexpr int cggm_tile() {
    return (EMP_TUNE_CGGM_TILE > 0) ? EMP_TUNE_CGGM_TILE
                                    : cggm_tile_arch_default();
}

// ===== Multi-point gadget preparation (emp-ot/common/mp_gadget.h) =====
// LOCAL scheduling policy (fixed, not auto-tuned): maximum trees whose
// malicious-mode corrections may be buffered between flushes. The useful
// value depends on two-party transport buffering and latency, which the
// single-process tuner cannot model; keep one conservative cross-platform
// policy here. It changes only flush timing, not transcript order or bytes.
inline constexpr int64_t mp_gadget_flush_trees = 128;

// ===== SoftSpoken =====
// LOCAL (tunable): sfvole butterfly tile T — the j-axis (PRG counter)
// width each fuse call keeps in registers. Larger T = more independent
// AES streams in flight (covers aesenc latency on multi-pipe parts) but
// a bigger basic block + register working set. Measured optima diverge
// by vendor AND by k — hence per-machine, per-k knobs, never a default
// change. NOTE: `make tune` auto-emits only the k=8 knob; at k<=4 the
// e2e optimum is dominated by two-party chunk scheduling that no
// single-process sweep can rank (verified misses in both directions),
// so K2/K4 are manual-only — see docs/performance-tuning.md.
// Candidates must keep T % AesLane width == 0 (8/16/32 are safe on
// every tier).
#ifndef EMP_TUNE_SFVOLE_TILE_K2
#define EMP_TUNE_SFVOLE_TILE_K2 8
#endif
#ifndef EMP_TUNE_SFVOLE_TILE_K4
#define EMP_TUNE_SFVOLE_TILE_K4 8
#endif
#ifndef EMP_TUNE_SFVOLE_TILE_K8
#define EMP_TUNE_SFVOLE_TILE_K8 8
#endif
template <int k>
constexpr int sfvole_tile() {
    if constexpr (k <= 2)      return EMP_TUNE_SFVOLE_TILE_K2;
    else if constexpr (k <= 4) return EMP_TUNE_SFVOLE_TILE_K4;
    else                       return EMP_TUNE_SFVOLE_TILE_K8;
}

// AGREEMENT (not tunable): per-chunk size in 128-block units;
// chunk_ots = N * 128.
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
// SECURITY (not tunable): XOR positions per LPN output (the "d" of
// LPN(n, k, d)).
inline constexpr int lpn_d = 10;
// LOCAL (tunable, with a divisibility contract): compute_slice batch
// size — outputs produced per AES-PRG inner batch. Larger = more
// in-flight kk loads pipelined, but pushes kk farther from the
// load-queue sweet spot. Output-identical across values ONLY when the
// batch divides every production fold length (Ferret/sVOLE lengths are
// 2^tree_depth, so powers of two <= 2^10 are safe; the candidate set
// {16, 32, 64} also keeps M*d divisible by 4, i.e. no per-batch
// randomness waste). test_tuning_invariance enforces both properties.
#ifndef EMP_TUNE_LPN_BATCH_M
#define EMP_TUNE_LPN_BATCH_M 32
#endif
inline constexpr int lpn_batch_m = EMP_TUNE_LPN_BATCH_M;

}  // namespace tuning
}  // namespace emp

#endif  // EMP_OT_TUNING_H__
