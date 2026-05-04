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
 * SoftSpoken OT Extension — semi-honest, RandomCOT subclass.
 * [REF] L. Roy, "SoftSpokenOT: Quieter OT Extension from Small-Field
 *       Silent VOLE in the Minicrypt Model" — Crypto '22.
 *       https://eprint.iacr.org/2022/192
 *
 * The protocol is natively a RandomCOT: after sfvole_*_compute,
 * u_canonical[j] is the receiver's intrinsic random choice bit and
 * Conv(V[j]) ⊕ Conv(W[j]) = u_canonical[j] · Δ at the full-block
 * level. rcot_send / rcot_recv expose this directly with the
 * LSB-of-output choice convention (LSB(K)=0, LSB(M)=u_canonical[j]).
 * send_cot / recv_cot are inherited from RandomCOT, which adds the
 * standard 1-bit-per-COT chosen-message correction wrapper.
 *
 * Templated on k, the F_{2^k} sub-field size used inside the small-
 * field VOLE. Larger k = less bandwidth (~ kappa/k bytes per COT)
 * but more compute (~ 2^k / k AES blocks per COT). Pre-instantiated
 * for k in {2, 4, 8} in softspoken_ot.cpp.
 *
 * Role mapping: the COT-Sender (which holds Delta) plays the
 * Receiver role in the underlying VOLE / PPRF, so during setup it
 * runs OTCO::recv on n*k base OTs with choices derived from Delta.
 * The COT-Receiver plays the VOLE-Sender / PPRF-Sender.
 *
 * Δ has LSB=1 (forced by setup_send no-arg, required of callers
 * passing setup_send(delta_in)). Required for the LSB-encoded
 * choice convention to round-trip the COT relation correctly.
 */
template <int k>
class SoftSpokenOT : public RandomCOT {
    static_assert(k >= 1 && k <= 8, "SoftSpokenOT supports k in [1, 8]");
public:
    static constexpr int n = softspoken::n_subvoles<k>();
    static constexpr int Q = 1 << k;

    explicit SoftSpokenOT(IOChannel* io_);
    ~SoftSpokenOT() override = default;

    // RandomCOT virtual contract. send_cot / recv_cot inherit from
    // RandomCOT and run the standard 1-bit-per-COT chosen-message
    // correction wrapper on top.
    void rcot_send(block* data, int64_t length) override;
    void rcot_recv(block* data, int64_t length) override;

    // Externally-provided Δ (must have LSB=1). The decomposition
    // unpack<k>(Δ, ...) into alphas_ works for any Δ ∈ F_{2^128};
    // setup proceeds identically. Used by ferret to share its
    // global Δ with the bootstrap base-OT generator.
    void setup_send(block delta_in);

    // Receiver-role setup. Exposed so ferret can drive the bootstrap
    // explicitly (rcot_send/rcot_recv auto-run the matching setup
    // on first call, but ferret wants to synchronize role selection
    // with its own party flag).
    void setup_recv();

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
};

extern template class SoftSpokenOT<2>;
extern template class SoftSpokenOT<4>;
extern template class SoftSpokenOT<8>;

} // namespace emp
#endif
