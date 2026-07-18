#ifndef EMP_OT_CGGM_H__
#define EMP_OT_CGGM_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/tuning.h"
#include <algorithm>
#include <type_traits>

// Half-Tree correlated GGM tree (Guo-Yang-Wang-Zhang-Xie-Liu-Zhao,
// ePrint 2022/1431, Figure 3). At every non-leaf:
//   left  = H(parent)
//   right = parent XOR left
// Root children are (k, Δ XOR k); the leveled correlation
// `Δ = XOR of all nodes on level i` then holds for every i in [1, d].
// H is emp-tool's CCRH (= π(σ(x)) ⊕ σ(x), Theorem 4.3).
//
// Used as:
//   - the per-tree puncturable PRF in MultiPointGadget (mp_gadget.h);
//   - the puncturable-PRF tree in softspoken (per-tree fresh Δ;
//     the receiver's view of `leaves[α]` is pseudorandom because
//     it never learns Δ).
//
// alpha bit convention: alpha_1 is MSB (alpha_j = bit (d-j) of
// alpha).
//
// Leaf storage is the split (bit-reversed) layout: each level expands
// in place by writing all left children to the lower half and all right
// children to the upper half, so the leaf for path p lands at array
// index bit_reverse(p, d). This keeps the per-level write pattern two
// sequential streams (left half stationary, right half appended) rather
// than a scatter to (2j, 2j+1). The leveled XOR correlations K^0_i / K^1_i
// are over the same child multisets and so are independent of the order;
// only the array positions change. Consumers handle the order two ways:
//   - MultiPointGadget: leaf order is irrelevant to its downstream (LPN
//     fold + VW sum), so it just reads the punctured slot at bit_reverse(α).
//   - softspoken: its sub-VOLE butterfly indexes leaves[x] as field
//     element x, so it picks the field element it wants and drives the
//     tree with path = bit_reverse(field element); the hole then lands at
//     storage index == field element (no reordering of the leaf array).

namespace emp { namespace cggm {

// Tile size for batched H, resolved in tuning.h (per-arch default; leaf
// values and K0 sums are identical for every tile). At production tree
// depth the leaves array exceeds L1, so per-tile working-set fit
// dominates over AES port saturation: smaller tiles when the tree
// exceeds L1, larger tiles only when everything stays L1-resident.
// The Tile template parameter on expand_level / build_sender /
// eval_receiver defaults to kTile but can be overridden.
constexpr int kTile = tuning::cggm_tile();

namespace detail {

// Bit-0-clear mask for the COT LSB convention. Used when callers
// want the final-level leaves to carry the choice signal in bit 0
// rather than its raw cGGM bit (currently ferret's MPCOT). The mask
// is applied both to the written leaf and the XOR-sum so K0 stays
// consistent on both sides.
inline constexpr block kCggmLsbClearMask = makeBlock(0xFFFFFFFFFFFFFFFFLL,
                                                     0xFFFFFFFFFFFFFFFELL);

// Expand `n` parents at leaves[0..n) into 2n children stored in the
// split (bit-reversed) layout: all left children at [0, n) — each
// overwriting its own parent in place — and all right children at
// [n, 2n). The new tree bit thus lands in the most-significant index
// position, so a parent at index j has children at j (left) and n+j
// (right).
//
// Returns the XOR-sum of one side, selected by `want_right`: the sender
// only ever needs the left sum (K^0_i), and the receiver needs exactly
// the alpha_bar_i side per level — so we accumulate just the one wanted
// (the unused side's sum would be derivable as the other XOR Δ, but the
// sender has Δ already and the receiver never has both needs at once).
//
// `ClearLSB`: if true, AND every written leaf with kCggmLsbClearMask
// and accumulate the XOR-sum over the cleared values. Used at the
// final level only — intermediate levels' children feed AES at the
// next level, so clearing them would corrupt the cGGM correlation.
//
// Tile invariant: tiles ascend. CCRH::H reads leaves[base..base+m) into
// lefts_buf up front, so the in-place left write leaves[j]=left (j in
// the tile) only touches already-consumed inputs; right writes land at
// [n+base, ...), strictly above the unread parents [base+m, n).
template <int Tile = kTile, bool ClearLSB = false>
inline block expand_level(CCRH& ccrh, block* leaves, int n, bool want_right) {
    block lefts_buf[Tile];
    block sum = zero_block;
    for (int base = 0; base < n; base += Tile) {
        const int m = std::min(Tile, n - base);
        if (m == Tile) ccrh.H<Tile>(lefts_buf, leaves + base);
        else           ccrh.Hn(lefts_buf, leaves + base, m);
        for (int t = 0; t < m; ++t) {
            const int j = base + t;
            const block parent = leaves[j];
            block left  = lefts_buf[t];
            block right = parent ^ left;
            if constexpr (ClearLSB) {
                left  = left  & kCggmLsbClearMask;
                right = right & kCggmLsbClearMask;
            }
            leaves[n + j] = right;   // upper half, fresh space
            leaves[j]     = left;    // in place (parent already consumed)
            sum ^= want_right ? right : left;
        }
    }
    return sum;
}

}  // namespace detail

// Reverse the low `d` bits of `x`. The split layout stores the leaf for
// path α (α_1 the MSB, top-down) at array index bit_reverse(α, d): each
// expansion prepends the new tree bit as the index MSB, so the final
// index reads the path bits least-significant-first. Callers that hold a
// top-down path integer use this to find / puncture the leaf slot.
inline uint32_t bit_reverse(uint32_t x, int d) {
    uint32_t r = 0;
    for (int i = 0; i < d; ++i) { r = (r << 1) | (x & 1u); x >>= 1; }
    return r;
}

// Sender: build the depth-d cGGM tree given Δ and a top secret k.
// Writes 2^d leaves into `leaves` and the per-level left-side
// XOR-sums K^0_i for i ∈ [1, d] into `K0[i-1]`. The right-side
// sum at each level is K^1_i = K^0_i XOR Δ (leveled correlation),
// derivable by callers that need both sides.
//
// `ClearLeafLSB`: if true, the level-d leaves are written with
// bit 0 cleared, and K0[d-1] is the XOR-sum over the cleared
// values. Used by ferret's MPCOT to fold the COT LSB convention
// into the tree-build write pass (saves a separate AND loop over
// 2^d leaves). softspoken does not want this — its sub-VOLE PRG
// reads the full leaf bytes — so the default is off.
//
// Tile defaults to the platform's kTile.
template <int Tile = kTile, bool ClearLeafLSB = false>
inline void build_sender(int d, block Delta, block k,
                         block* leaves, block* K0) {
    CCRH ccrh;

    // Level 1 (two children of the conceptual root).
    leaves[0] = k;
    leaves[1] = Delta ^ k;
    K0[0] = leaves[0];

    // Levels 2..d-1: never clear (intermediate parents feed AES
    // at the next level; clearing would corrupt the cGGM tree).
    for (int i = 2; i < d; ++i) {
        const int parents = 1 << (i - 1);
        K0[i - 1] = detail::expand_level<Tile, false>(ccrh, leaves, parents,
                                                      /*want_right=*/false);
    }

    // Level d: leaf level. Optionally clear LSBs in-place.
    if (d >= 2) {
        const int parents = 1 << (d - 1);
        K0[d - 1] = detail::expand_level<Tile, ClearLeafLSB>(ccrh, leaves, parents,
                                                             /*want_right=*/false);
    }
}

// Receiver: reconstruct the depth-d cGGM tree from the punctured
// path `alpha` (d bits, MSB-first) and d corrections K_recv[i] =
// K^{ᾱ_{i+1}}_{i+1}. After return, leaves[x] holds the correct cGGM
// leaf for every x != bit_reverse(alpha, d); the punctured leaf at
// index bit_reverse(alpha, d) is zero_block (split layout).
//
// `ClearLeafLSB`: same convention as build_sender. Both sides must
// agree; if the sender used ClearLeafLSB the receiver must too,
// so K0[d-1] / K_recv[d-1] match. Cleared leaves let the caller
// drop the post-eval AND loop and do a pure XOR-fold.
//
// Returns the XOR of all reconstructed leaves (the punctured slot remains
// zero). The value follows the same optional leaf-LSB clearing convention.
template <int Tile = kTile, bool ClearLeafLSB = false>
inline block eval_receiver(int d, int alpha,
                           const block* K_recv, block* leaves) {
    CCRH ccrh;

    // `pos` = split-layout storage index of the on-path node at the
    // current level. In the split layout a node at index j has its
    // children at j (left) and j+half (right), so the on-path index
    // grows by alpha_i*half per level (the new bit is the index MSB).
    int pos = 0;
    block known_xor = zero_block;

    // Level 1: receiver knows the alpha_bar_1-side root child only.
    {
        const int alpha_1     = (alpha >> (d - 1)) & 1;
        const int alpha_bar_1 = 1 - alpha_1;
        // Only the two live level-1 slots need initialization. Every later
        // expand_level call overwrites the complete live prefix [0, 2^i), so
        // zeroing the full leaf array would be a redundant O(2^d) pass.
        leaves[0] = zero_block;
        leaves[1] = zero_block;
        leaves[alpha_bar_1] = K_recv[0];
        pos = alpha_1;
        known_xor = K_recv[0];
    }

    // Levels 2..d. Expand the whole previous-level layer (the on-path
    // parent at `pos` is zero, so both its children — left at `pos`,
    // right at `pos+half` — become junk H(0); we overwrite both right
    // after expansion). Then recover the sibling on the alpha_bar_i
    // side via K_recv[i-1] XOR (XOR of expanded alpha_bar_i-side nodes,
    // with the on-path junk removed).
    //
    // The `step` lambda is invoked once per level. The bool template
    // parameter on expand_level / sibling-write must match across
    // sender / receiver and is fixed at compile time; we use
    // std::bool_constant to dispatch (false for i<d, ClearLeafLSB for i==d).
    auto step = [&](int i, auto clear_lsb) {
        constexpr bool C = decltype(clear_lsb)::value;
        const int half = 1 << (i - 1);   // parents = lower-half size
        const int alpha_i     = (alpha >> (d - i)) & 1;
        const int alpha_bar_i = 1 - alpha_i;

        // Accumulate only the alpha_bar_i side (the side the sibling lives
        // on); the other side's sum is never used here.
        const block sum_pre =
            detail::expand_level<Tile, C>(ccrh, leaves, half,
                                          /*want_right=*/alpha_bar_i != 0);

        // Both children of the punctured parent at `pos` carry junk
        // H(0): left at `pos`, right at `pos+half`. Capture (either is
        // H(0)), zero both, then remove that junk from the side-sum.
        const block junk = leaves[pos];
        leaves[pos]        = zero_block;
        leaves[pos + half] = zero_block;
        block sib = sum_pre ^ junk ^ K_recv[i - 1];
        if constexpr (C) sib = sib & detail::kCggmLsbClearMask;
        leaves[pos + alpha_bar_i * half] = sib;

        // XOR(left, right) equals the parent for every expanded pair. At the
        // leaf level both children are masked, so the pair XOR is the masked
        // parent. The two H(0) children of the punctured parent cancel before
        // they are cleared; installing the recovered sibling then XORs `sib`
        // into the known-node total. Carrying this invariant lets the caller
        // fill its punctured leaf without rescanning all 2^d leaves.
        if constexpr (C) known_xor = known_xor & detail::kCggmLsbClearMask;
        known_xor = known_xor ^ sib;

        pos += alpha_i * half;   // on-path child = next level's `pos`
    };

    for (int i = 2; i < d; ++i) step(i, std::false_type{});
    if (d >= 2) step(d, std::integral_constant<bool, ClearLeafLSB>{});
    return known_xor;
}

}}  // namespace emp::cggm
#endif  // EMP_OT_CGGM_H__
