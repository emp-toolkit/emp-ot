#ifndef EMP_SOFTSPOKEN_PPRF_H__
#define EMP_SOFTSPOKEN_PPRF_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/pprf.h"

// Thin templated wrappers around the shared depth-d GGM PPRF in
// emp::pprf, fixing the template parameter `k` for compile-time
// SoftSpoken sub-VOLE depth (k in {2, 4, 8} pre-instantiated). The
// real implementation — and the one ferret/spcot also uses — lives
// in emp-ot/pprf.h.

namespace emp { namespace softspoken {

// Sender: sample a fresh root from `rng` and build the depth-k GGM
// tree. K0[0]/K1[0] are the level-1 children (the protocol's
// (s_0^1, s_1^1)); K0[h]/K1[h] for h >= 1 are XOR sums shipped via
// base 1-of-2 OTs.
template <int k>
inline void pprf_build_sender(PRG& rng,
                              block leaves[1 << k],
                              block K0[k],
                              block K1[k]) {
    block root;
    rng.random_block(&root, 1);
    pprf::build_sender(k, root, leaves, K0, K1);
}

// Receiver: alpha in [0, 2^k) is the punctured leaf index, MSB-first
// (alpha_1 = bit (k-1) of alpha). On return, leaves[x] is correct for
// every x != alpha; leaves[alpha] = zero_block.
template <int k>
inline void pprf_eval_receiver(int alpha,
                               const block K_recv[k],
                               block leaves[1 << k]) {
    pprf::eval_receiver(k, alpha, K_recv, leaves);
}

}}  // namespace emp::softspoken
#endif
