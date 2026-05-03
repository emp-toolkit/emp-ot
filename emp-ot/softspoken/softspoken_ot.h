#ifndef EMP_SOFTSPOKEN_OT_H__
#define EMP_SOFTSPOKEN_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/cot.h"
#include "emp-ot/co.h"
#include "emp-ot/softspoken/conv.h"
#include "emp-ot/softspoken/pprf.h"
#include "emp-ot/softspoken/small_vole.h"
#include "emp-ot/softspoken/subspace_vole.h"
#include <cstdint>
#include <memory>
#include <vector>

namespace emp {

/*
 * SoftSpoken OT Extension — semi-honest, COT subclass.
 * [REF] L. Roy, "SoftSpokenOT: Quieter OT Extension from Small-Field
 *       Silent VOLE in the Minicrypt Model" — Crypto '22.
 *       https://eprint.iacr.org/2022/192
 *
 * The class is templated on k, the F_{2^k} sub-field size used inside
 * the small-field VOLE. Larger k = less bandwidth (~ kappa/k bytes per
 * COT) but more compute (~ 2^k / k AES blocks per COT). Pre-instantiated
 * for k in {2, 4, 8} in softspoken_ot.cpp; other k values require an
 * extra `template class SoftSpokenOT<...>;` in a translation unit you own.
 *
 * Role mapping (the easy thing to invert): the COT-Sender (which holds
 * Delta) plays the *Receiver* role in the underlying VOLE / PPRF, so
 * during setup it runs OTCO::recv on n*k base OTs with choices derived
 * from Delta. The COT-Receiver plays the VOLE-Sender / PPRF-Sender, so
 * it generates the GGM trees and runs OTCO::send.
 *
 * setup_send / setup_recv are run lazily on the first send_cot / recv_cot
 * call; they exchange n*k = >=128 base OTs and either build (sender) or
 * puncture-evaluate (receiver) the GGM trees. After setup, leaves stay
 * resident; per-call expansion uses PRG(leaf, session_counter) so each
 * call produces an independent G''-stream.
 *
 * No LSB-of-output choice convention. send_cot/recv_cot do explicit
 * derandomization (receiver -> sender bit per COT) on top of the protocol's
 * own VOLE-derandomization, exactly the same wire pattern as RandomCOT.
 */
template <int k>
class SoftSpokenOT : public COT {
    static_assert(k >= 1 && k <= 8, "SoftSpokenOT supports k in [1, 8]");
public:
    static constexpr int n = softspoken::n_subvoles<k>();
    static constexpr int Q = 1 << k;

    explicit SoftSpokenOT(IOChannel* io_);
    ~SoftSpokenOT() override = default;

    void send_cot(block* data, int64_t length) override;
    void recv_cot(block* data, const bool* b, int64_t length) override;

private:
    OTCO base_ot_;
    bool setup_done_ = false;
    uint64_t session_ = 0;

    // COT-Sender (= VOLE-Receiver / PPRF-Receiver) state.
    int alphas_[n] = {0};
    std::unique_ptr<block[]> leaves_recv_;  // n * Q blocks; punctured at alphas_[i]

    // COT-Receiver (= VOLE-Sender / PPRF-Sender) state.
    std::unique_ptr<block[]> leaves_send_;  // n * Q blocks; full GGM tree

    // Per-call scratch (grown lazily; reused across calls of equal length).
    std::vector<block>      planes_scratch_;  // n * k * bpr blocks
    std::vector<const block*> planes_ptrs_;   // n * k pointers into planes_scratch_

    void setup_send();
    void setup_recv();
};

extern template class SoftSpokenOT<2>;
extern template class SoftSpokenOT<4>;
extern template class SoftSpokenOT<8>;

} // namespace emp
#endif
