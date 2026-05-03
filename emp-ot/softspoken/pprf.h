#ifndef EMP_SOFTSPOKEN_PPRF_H__
#define EMP_SOFTSPOKEN_PPRF_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ferret/twokeyprp.h"
#include <cstdint>

namespace emp { namespace softspoken {

// Depth-k GGM puncturable PRF (cot.tex § Small-field VOLE step 1).
// Sender builds the full tree of 2^k leaves and emits the per-level
// XOR sums K0[j], K1[j] (level-1 sums are just the two root seeds).
// Receiver, given alpha in [0, 2^k) and the K_{not-alpha_j}^j it
// receives via base OT, reconstructs all leaves except leaf[alpha].
//
// Length-doubling PRG G(parent) is the same matyas-meyer-oseas-style
// 2-key PRP that ferret/spcot uses (TwoKeyPRP, fixed public keys
// (zero_block, makeBlock(0, 1))). We share that file rather than
// owning a parallel implementation, and lift the same node_expand_4to8
// / node_expand_2to4 batched expansions for the sender side.
//
// Bit convention: alpha's MSB is "alpha_1" in cot.tex, so the path
// index after j rounds is Int(alpha_1, ..., alpha_j) = alpha >> (k-j).
// The punctured leaf ends up at position alpha (with alpha_1 = MSB).

namespace detail {
inline TwoKeyPRP& shared_pprf_prp() {
    // Fixed public keys; same convention as ferret's spcot.
    static TwoKeyPRP prp(zero_block, makeBlock(0, 1));
    return prp;
}

template <int k>
inline void expand_level(TwoKeyPRP& prp, block* leaves, int parents) {
    if (parents == 1) {
        // Caller handles this (level 1 is sampled or handed in directly).
        return;
    }
    if (parents == 2) {
        prp.node_expand_2to4(&leaves[0], &leaves[0]);
        return;
    }
    // parents >= 4 — expand in 4-batches (reverse so in-place is safe).
    for (int i = parents - 4; i >= 0; i -= 4) {
        prp.node_expand_4to8(&leaves[i * 2], &leaves[i]);
    }
}
}  // namespace detail

// Sender: rng is consumed for one root seed; level 1 (the two children
// of that root) is produced via 1-to-2 expansion, matching ferret's
// pattern. K0[0] / K1[0] are the level-1 left/right children;
// K0[j-1] / K1[j-1] for j >= 2 are XOR sums over all left/right
// children at level j.
template <int k>
inline void pprf_build_sender(PRG& rng,
                              block leaves[1 << k],
                              block K0[k],
                              block K1[k]) {
    TwoKeyPRP& prp = detail::shared_pprf_prp();

    // Level 1: sample one root, expand to 2 children.
    block root;
    rng.random_block(&root, 1);
    prp.node_expand_1to2(leaves, root);
    K0[0] = leaves[0];
    K1[0] = leaves[1];

    for (int j = 2; j <= k; ++j) {
        const int parents = 1 << (j - 1);
        detail::expand_level<k>(prp, leaves, parents);

        // K_sigma^j = XOR of every other leaf at level j.
        block k0 = zero_block, k1 = zero_block;
        const int children = 1 << j;
        for (int x = 0; x < children; x += 2) {
            k0 = k0 ^ leaves[x];
            k1 = k1 ^ leaves[x + 1];
        }
        K0[j - 1] = k0;
        K1[j - 1] = k1;
    }
}

// Receiver: given alpha in [0, 2^k) and the k base-OT outputs
// (K_recv[j-1] = K_{1 - alpha_j}^j on the not-alpha side at each
// level), reconstructs leaves[x] for x != alpha. Sets leaves[alpha]
// = zero_block.
//
// We run the same batched expansion as the sender for parents >= 2,
// then explicitly zero the children of the missing parent (whose
// own value was zero, so node_expand_* produced bogus AES(0)-derived
// children for them) before step d. The missing parent's two children
// at level j are at positions 2*d_prev and 2*d_prev + 1; step d
// recovers one of them (the sibling of the new puncture) from the
// base-OT output, and the other stays zero — i.e. the new puncture.
template <int k>
inline void pprf_eval_receiver(int alpha,
                               const block K_recv[k],
                               block leaves[1 << k]) {
    constexpr int Q = 1 << k;
    for (int x = 0; x < Q; ++x) leaves[x] = zero_block;

    TwoKeyPRP& prp = detail::shared_pprf_prp();

    int d_prev = 0;
    for (int j = 1; j <= k; ++j) {
        const int alpha_j     = (alpha >> (k - j)) & 1;
        const int alpha_bar_j = 1 - alpha_j;
        const int parents     = 1 << (j - 1);

        if (j > 1) {
            detail::expand_level<k>(prp, leaves, parents);
            // The missing parent at index d_prev was zero before the expand,
            // so its children carry bogus AES-of-zero values. Clear them now;
            // step d will fill in the sibling, leaving the puncture at zero.
            leaves[2 * d_prev]     = zero_block;
            leaves[2 * d_prev + 1] = zero_block;
        }

        // Step d: s_{2 d_prev + alpha_bar_j}^j
        //   = K_recv[j-1] XOR (XOR over i != d_prev of s_{2i+alpha_bar_j}^j)
        block sum = K_recv[j - 1];
        for (int i = 0; i < parents; ++i) {
            if (i == d_prev) continue;
            sum = sum ^ leaves[2 * i + alpha_bar_j];
        }
        leaves[2 * d_prev + alpha_bar_j] = sum;
        // leaves[2 * d_prev + alpha_j] stays zero — this is the new puncture.

        d_prev = 2 * d_prev + alpha_j;
    }
}

}} // namespace emp::softspoken
#endif
