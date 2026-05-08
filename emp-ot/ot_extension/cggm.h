#ifndef EMP_OT_CGGM_H__
#define EMP_OT_CGGM_H__
#include <emp-tool/emp-tool.h>
#include <algorithm>

// Half-Tree correlated GGM tree (Guo-Yang-Wang-Zhang-Xie-Liu-Zhao,
// ePrint 2022/1431, Figure 3). At every non-leaf:
//   left  = H(parent)
//   right = parent XOR left
// Root children are (k, Δ XOR k); the leveled correlation
// `Δ = XOR of all nodes on level i` then holds for every i in [1, d].
// H is emp-tool's CCRH (= π(σ(x)) ⊕ σ(x), Theorem 4.3).
//
// Used as:
//   - the per-tree puncturable PRF in ferret's MPCOT (mpcot.h);
//   - the puncturable-PRF tree in softspoken (per-tree fresh Δ;
//     the receiver's view of `leaves[α]` is pseudorandom because
//     it never learns Δ).
//
// alpha bit convention: alpha_1 is MSB (alpha_j = bit (d-j) of
// alpha).

namespace emp { namespace cggm {

// Per-platform default tile size for batched H. Bench-derived from
// test/bench_cggm.cpp at d=13 (the production ferret depth), NOT
// from raw CCRH::H<N> peaks — at d=13 the leaves array is 128 KB
// (past L1), so per-tile working-set fit dominates over AES port
// saturation. Smaller tiles win when the tree exceeds L1; larger
// tiles only help when everything stays L1-resident. The Tile
// template parameter on expand_level / build_sender / eval_receiver
// defaults to kTile but can be overridden — the bench uses that to
// sweep tiles without rebuilding cggm.h.
//
// Measured d=13 cGGM throughput per (tile, platform):
//   Apple NEON  : tile=4   peak (658 MH/s); other tiles ≤ 60% of peak
//   AMD VAES512 : tile=16  peak (448 MH/s); tile=64 only 295 (-34%)
//   Intel VAES512: tile=16 peak (353 MH/s); tile=64 only 324 (-9%)
// VAES256 / AES-NI not re-measured against d=13 yet — kept at the
// raw-H peak; revisit if a workload there proves bottlenecked.
#if defined(__aarch64__)
constexpr int kTile = 4;        // NEON, d=13 peak ~660 MH/s
#elif EMP_AES_HAS_VAES512
constexpr int kTile = 16;       // x86 VAES512, d=13 peak ~350-450 MH/s
#elif EMP_AES_HAS_VAES256
constexpr int kTile = 32;       // VAES256 raw-H peak (untested at d=13)
#else
constexpr int kTile = 4;        // AES-NI only, raw-H peak (untested at d=13)
#endif

namespace detail {

// Per-level XOR sums of the just-expanded children, accumulated in
// register inside expand_level. `left` = XOR of all left children
// at this level; `right` = XOR of all right children. Caller picks
// whichever is needed: sender uses `left` directly as K^0_i;
// receiver uses one or the other (with a one-block correction for
// the on-path junk; see eval_receiver).
struct ExpandSums { block left, right; };

// Expand `parents` parents at leaves[0..parents) into children at
// leaves[0..2*parents) using batched CCRH::H<Tile> over the whole
// level. Returns per-level (left_sum, right_sum) so callers don't
// have to re-read the just-written child array.
//
// Tile invariant: process tiles top-down so each tile reads
// `parents[base..base+n)` and writes children at
// `[2*base, 2*(base+n))`. The next iteration's parents at
// `[0, base)` are strictly below the just-written `[2*base, ...)`
// region — no clobber.
template <int Tile = kTile>
inline ExpandSums expand_level(CCRH& ccrh, block* leaves, int parents) {
    block lefts_buf[Tile];
    block left_sum = zero_block, right_sum = zero_block;
    for (int s = parents; s > 0; ) {
        const int n    = std::min(s, Tile);
        const int base = s - n;
        // CCRH::H reads `in` once per element, doesn't alias `out`,
        // so we can pass leaves+base directly. Within the second
        // loop below, reads of leaves[j] at j=base..base+n-1 don't
        // overlap the just-written children at indices ≥ 2*base.
        if (n == Tile) ccrh.H<Tile>(lefts_buf, leaves + base);
        else           ccrh.Hn(lefts_buf, leaves + base, n);
        for (int t = n - 1; t >= 0; --t) {
            const int j = base + t;
            const block parent = leaves[j];
            const block left   = lefts_buf[t];
            const block right  = parent ^ left;
            leaves[2 * j]     = left;
            leaves[2 * j + 1] = right;
            left_sum  ^= left;
            right_sum ^= right;
        }
        s = base;
    }
    return {left_sum, right_sum};
}

}  // namespace detail

// Sender: build the depth-d cGGM tree given Δ and a top secret k.
// Writes 2^d leaves into `leaves` and the per-level left-side
// XOR-sums K^0_i for i ∈ [1, d] into `K0[i-1]`. The right-side
// sum at each level is K^1_i = K^0_i XOR Δ (leveled correlation),
// derivable by callers that need both sides.
//
// Tile defaults to the platform's kTile. Override only for benches.
template <int Tile = kTile>
inline void build_sender(int d, block Delta, block k,
                         block* leaves, block* K0) {
    CCRH ccrh;

    // Level 1 (two children of the conceptual root).
    leaves[0] = k;
    leaves[1] = Delta ^ k;
    K0[0] = leaves[0];

    // Levels 2..d. expand_level returns the per-level XOR-sums in
    // register; K^0_i = sum of left children.
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        K0[i - 1] = detail::expand_level<Tile>(ccrh, leaves, parents).left;
    }
}

// Receiver: reconstruct the depth-d cGGM tree from the punctured
// path `alpha` (d bits, MSB-first) and d corrections K_recv[i] =
// K^{ᾱ_{i+1}}_{i+1}. After return, leaves[x] holds the correct
// cGGM leaf for every x != alpha; leaves[alpha] is zero_block.
template <int Tile = kTile>
inline void eval_receiver(int d, int alpha,
                          const block* K_recv, block* leaves) {
    const int Q = 1 << d;
    for (int i = 0; i < Q; ++i) leaves[i] = zero_block;

    CCRH ccrh;

    // path = prefixsum_{i-1}(alpha): integer formed by alpha_1..alpha_{i-1}
    // (top-down, MSB-first). Doubles per level; alpha_i appended at end.
    int path = 0;

    // Level 1: receiver knows the alpha_bar_1-side root child only.
    {
        const int alpha_1     = (alpha >> (d - 1)) & 1;
        const int alpha_bar_1 = 1 - alpha_1;
        leaves[alpha_bar_1] = K_recv[0];
        path = alpha_1;
    }

    // Levels 2..d. Expand the whole previous-level layer (the
    // on-path parent at `path` is zero, so its two children become
    // junk from H(0); we overwrite both right after expansion).
    // Then recover the sibling on the alpha_bar_i side via
    // K_recv[i-1] XOR (XOR of expanded alpha_bar_i-side nodes).
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        const auto sums = detail::expand_level<Tile>(ccrh, leaves, parents);

        const int alpha_i     = (alpha >> (d - i)) & 1;
        const int alpha_bar_i = 1 - alpha_i;
        const int on_path_lvl = path * 2 + alpha_i;
        const int sibling_lvl = path * 2 + alpha_bar_i;

        // expand_level computed sums.{left,right} OVER ALL children
        // of this level, including the junk H(0) values that
        // expansion wrote at the on-path slot (parent at index
        // `path` was zero from the previous iteration's puncture, so
        // its two children are both H(0)). Capture H(0) from
        // leaves[2*path] (L1-hot) before zeroing, then subtract it
        // out of whichever side-sum we want — gives the same result
        // as the old "zero then re-sum" sequence, with no second
        // pass over the level.
        const block junk = leaves[2 * path];   // = H(0)
        leaves[2 * path]     = zero_block;
        leaves[2 * path + 1] = zero_block;
        const block sum_pre = (alpha_bar_i == 0) ? sums.left : sums.right;
        const block sum     = sum_pre ^ junk;
        leaves[sibling_lvl] = sum ^ K_recv[i - 1];

        path = on_path_lvl;
    }
}

}}  // namespace emp::cggm
#endif  // EMP_OT_CGGM_H__
