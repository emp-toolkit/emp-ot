#ifndef EMP_SOFTSPOKEN_PPRF_H__
#define EMP_SOFTSPOKEN_PPRF_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/cggm.h"

// Templated PPRF wrappers for SoftSpoken sub-VOLE depth (k in
// {2, 4, 8} pre-instantiated). Backed by the shared cGGM tree
// in emp-ot/cggm.h — same algorithm ferret uses for SPCOT.
//
// The cGGM construction is a valid PPRF here because softspoken
// never reveals Δ to the receiver (no per-COT correction byte,
// no global-Δ base-COT layer). With per-tree fresh Δ, the
// receiver's view of leaves[α] stays pseudorandom even though
// the leveled-correlation property `XOR(leaves) = Δ` holds —
// the receiver can compute `XOR(known leaves)` but not Δ, so
// leaves[α] = Δ XOR XOR(known) is uniform and independent of
// everything visible.

namespace emp { namespace softspoken {

// Sender: sample fresh Δ and root from `rng`, build the depth-k
// cGGM tree. K0[h] is the level-(h+1) left-side XOR-sum (= the
// protocol's K^0); K1[h] = K0[h] XOR Δ via leveled correlation.
// (K0[0] = leaves[0] is the level-1 left child; K1[0] = leaves[1]
// = Δ XOR k is the level-1 right child.) The (K0, K1) pair is
// shipped via base 1-of-2 OTs by the caller, exactly as before.
template <int k>
inline void pprf_build_sender(PRG& rng,
                              block leaves[1 << k],
                              block K0[k],
                              block K1[k]) {
    block Delta, root;
    rng.random_block(&Delta, 1);
    rng.random_block(&root, 1);
    cggm::build_sender(k, Delta, root, leaves, K0);
    for (int h = 0; h < k; ++h) K1[h] = K0[h] ^ Delta;
}

// Receiver: alpha in [0, 2^k) is the punctured leaf index, MSB-first
// (alpha_1 = bit (k-1) of alpha). On return, leaves[x] is correct for
// every x != alpha; leaves[alpha] = zero_block.
template <int k>
inline void pprf_eval_receiver(int alpha,
                               const block K_recv[k],
                               block leaves[1 << k]) {
    cggm::eval_receiver(k, alpha, K_recv, leaves);
}

}}  // namespace emp::softspoken
#endif
