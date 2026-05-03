#ifndef EMP_OT_PPRF_H__
#define EMP_OT_PPRF_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ferret/twokeyprp.h"
#include <cstdint>

// Shared depth-d GGM puncturable PRF used by both ferret/spcot
// (single-point COT setup) and softspoken (small-field VOLE setup).
//
// Underlying PRG G(parent) is the matyas-meyer-oseas-style 2-key PRP
// in TwoKeyPRP, with fixed public keys (zero_block, makeBlock(0, 1)).
// We share that file rather than owning a parallel copy.
//
// Layout: leaves[0..2^d) is the level-d (= leaf) layer of the tree
// (the ggm_tree memory the callers already manage). Per-level XOR
// sums K0[h], K1[h] for h in [0, d) are emitted for the sender so
// that base 1-of-2 OTs (one per level) can ship them to the receiver,
// who learns K_{NOT alpha_j}^j and reconstructs every leaf except
// leaves[alpha].
//
// alpha bit convention: alpha_1 is MSB, i.e. alpha_j = bit (d-j) of
// alpha. After d levels the punctured leaf sits at position alpha.

namespace emp { namespace pprf {

namespace detail {
inline TwoKeyPRP* shared_prp() {
    // Read-only after construction; C++11 makes the function-local
    // static thread-safe to initialize. Same fixed (zero_block,
    // makeBlock(0,1)) keys ferret has used since the start.
    static TwoKeyPRP inst(zero_block, makeBlock(0, 1));
    return &inst;
}
}  // namespace detail

// Sender: build the depth-d tree from `root`, emit per-level
// left/right XOR sums into K0[h], K1[h]. K0[0] / K1[0] are the two
// children of the root themselves (no XOR — there is only one node
// to sum on each side at level 1); K0[h] / K1[h] for h >= 1 are
// XORs over all 2^h nodes on each side.
//
// Uses ferret's batched node_expand_2to4 (level 2) and node_expand_4to8
// (level >= 3, in 4-parent batches) so the AES pipeline stays full.
inline void build_sender(int d, block root,
                         block* leaves, block* K0, block* K1) {
    TwoKeyPRP* prp = detail::shared_prp();

    // Level 1: 1 root -> 2 children.
    prp->node_expand_1to2(leaves, root);
    K0[0] = leaves[0];
    K1[0] = leaves[1];
    if (d == 1) return;

    // Level 2: 2 -> 4 in one batched call.
    prp->node_expand_2to4(&leaves[0], &leaves[0]);
    K0[1] = leaves[0] ^ leaves[2];
    K1[1] = leaves[1] ^ leaves[3];

    // Levels 3..d: expand in batches of 4 parents -> 8 children.
    for (int h = 2; h < d; ++h) {
        K0[h] = K1[h] = zero_block;
        const int sz = 1 << h;
        for (int i = sz - 4; i >= 0; i -= 4) {
            prp->node_expand_4to8(&leaves[i * 2], &leaves[i]);
            K0[h] ^= leaves[i * 2];
            K0[h] ^= leaves[i * 2 + 2];
            K0[h] ^= leaves[i * 2 + 4];
            K0[h] ^= leaves[i * 2 + 6];
            K1[h] ^= leaves[i * 2 + 1];
            K1[h] ^= leaves[i * 2 + 3];
            K1[h] ^= leaves[i * 2 + 5];
            K1[h] ^= leaves[i * 2 + 7];
        }
    }
}

// Receiver: reconstruct the depth-d tree from `alpha` (the punctured
// leaf index, MSB-first) and the d sibling sums K_recv[j-1] =
// K_{NOT alpha_j}^j received via base OT. After return, leaves[x]
// holds the correct GGM leaf for every x != alpha; leaves[alpha] is
// zero_block.
//
// We recover one missing leaf at the current level via XOR of the
// other leaves on the alpha-bar side, then expand the whole layer in
// place using the same batched expansions the sender uses; the new
// missing pair (children of the leaf we just left at the missing
// position) is zeroed at the start of the next iteration before
// recovery, which kills the AES-of-zero junk those positions carry.
inline void eval_receiver(int d, int alpha,
                          const block* K_recv, block* leaves) {
    const int Q = 1 << d;
    for (int i = 0; i < Q; ++i) leaves[i] = zero_block;

    TwoKeyPRP* prp = detail::shared_prp();

    int path = 0;  // = Int(alpha_1, ..., alpha_{i-1}); doubled at each step.
    for (int i = 1; i <= d; ++i) {
        path *= 2;
        leaves[path]     = zero_block;
        leaves[path + 1] = zero_block;

        const int alpha_i     = (alpha >> (d - i)) & 1;
        const int alpha_bar_i = 1 - alpha_i;

        // Sum every 2nd leaf on the alpha-bar side starting at alpha_bar_i,
        // XOR with K_recv to recover the sibling.
        const int item_n = 1 << i;
        block nodes_sum = zero_block;
        for (int j = alpha_bar_i; j < item_n; j += 2)
            nodes_sum = nodes_sum ^ leaves[j];
        leaves[path + alpha_bar_i] = nodes_sum ^ K_recv[i - 1];
        // leaves[path + alpha_i] stays zero -- this is the new puncture.

        path += alpha_i;

        if (i == d) break;
        // Expand the whole layer to the next level (the missing parent
        // expands to AES-of-zero junk, which gets cleared at the top of
        // the next iteration).
        if (item_n == 2) {
            prp->node_expand_2to4(&leaves[0], &leaves[0]);
        } else {
            for (int j = item_n - 4; j >= 0; j -= 4)
                prp->node_expand_4to8(&leaves[j * 2], &leaves[j]);
        }
    }
}

}}  // namespace emp::pprf
#endif
