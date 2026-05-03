#ifndef EMP_OT_CGGM_H__
#define EMP_OT_CGGM_H__
#include <emp-tool/emp-tool.h>

// Half-Tree correlated GGM tree (Guo-Yang-Wang-Zhang-Xie-Liu-Zhao,
// ePrint 2022/1431, Figure 3). At every non-leaf:
//   left  = H(parent)
//   right = parent XOR left
// Root children are (k, Δ XOR k); the leveled correlation
// `Δ = XOR of all nodes on level i` then holds for every i in [1, d].
// H is emp-tool's CCRH (= π(σ(x)) ⊕ σ(x), Theorem 4.3).
//
// Used as:
//   - the SPCOT tree algorithm in ferret (mpcot_reg.h via spcot.h);
//   - the puncturable-PRF tree in softspoken (per-tree fresh Δ;
//     the receiver's view of `leaves[α]` is pseudorandom because
//     it never learns Δ).
//
// alpha bit convention: alpha_1 is MSB (alpha_j = bit (d-j) of
// alpha).

namespace emp { namespace cggm {

// Sender: build the depth-d cGGM tree given Δ and a top secret k.
// Writes 2^d leaves into `leaves` and the per-level left-side
// XOR-sums K^0_i for i ∈ [1, d] into `K0[i-1]`. The right-side
// sum at each level is K^1_i = K^0_i XOR Δ (leveled correlation),
// derivable by callers that need both sides.
inline void build_sender(int d, block Delta, block k,
                         block* leaves, block* K0) {
    CCRH ccrh;

    // Level 1 (two children of the conceptual root).
    leaves[0] = k;
    leaves[1] = Delta ^ k;
    K0[0] = leaves[0];

    // Levels 2..d.
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        // Expand in place from index parents-1 downward so a parent
        // at index j produces children at 2j and 2j+1 without
        // clobbering yet-to-be-expanded parents.
        for (int j = parents - 1; j >= 0; --j) {
            block parent = leaves[j];
            block left   = ccrh.H(parent);
            block right  = parent ^ left;
            leaves[2 * j]     = left;
            leaves[2 * j + 1] = right;
        }
        block sum = zero_block;
        for (int j = 0; j < (1 << i); j += 2)
            sum = sum ^ leaves[j];
        K0[i - 1] = sum;
    }
}

// Receiver: reconstruct the depth-d cGGM tree from the punctured
// path `alpha` (d bits, MSB-first) and d corrections K_recv[i] =
// K^{ᾱ_{i+1}}_{i+1}. After return, leaves[x] holds the correct
// cGGM leaf for every x != alpha; leaves[alpha] is zero_block.
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

    // Levels 2..d. At each, every parent on level i-1 except the
    // on-path one (at index `path`) is fully known; we expand them,
    // then recover the on-path level-i node on the alpha_bar_i side
    // via K_recv[i-1] XOR (XOR of expanded alpha_bar_i-side nodes).
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        for (int j = parents - 1; j >= 0; --j) {
            block parent = leaves[j];
            block left   = ccrh.H(parent);
            block right  = parent ^ left;
            leaves[2 * j]     = left;
            leaves[2 * j + 1] = right;
        }

        const int alpha_i     = (alpha >> (d - i)) & 1;
        const int alpha_bar_i = 1 - alpha_i;
        const int on_path_lvl = path * 2 + alpha_i;
        const int sibling_lvl = path * 2 + alpha_bar_i;

        // Zero the on-path node's two children (junk from the H(0)
        // expansion above; sibling will be overwritten via K_recv;
        // on_path stays zero as the new puncture).
        leaves[2 * path]     = zero_block;
        leaves[2 * path + 1] = zero_block;

        block sum = zero_block;
        for (int j = alpha_bar_i; j < (1 << i); j += 2)
            sum = sum ^ leaves[j];
        leaves[sibling_lvl] = sum ^ K_recv[i - 1];

        path = on_path_lvl;
    }
}

}}  // namespace emp::cggm
#endif  // EMP_OT_CGGM_H__
