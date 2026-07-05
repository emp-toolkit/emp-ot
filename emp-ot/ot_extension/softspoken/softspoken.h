#ifndef EMP_SOFTSPOKEN_H__
#define EMP_SOFTSPOKEN_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/common/cggm.h"
#include "emp-ot/ot_extension/softspoken/sfvole_butterfly.h"
#include "emp-ot/tuning.h"
#include <cstdint>
#include <cstring>
#include <memory>

namespace emp {

// Default base OT for SoftSpoken. Change here to swap; OTExtension's
// contract just needs any malicious-secure (when malicious_=true) OT.
using SoftSpokenBaseOT = CSW;

} // namespace emp

namespace emp { namespace softspoken {

// Conv: F_2-linear bit packing between F_{2^k}^n and F_{2^128}. Bulk
// direction is one sse_trans_n128 of the plane buffer (see
// softspoken.cpp); the scalar inverse (Δ → n α_i bytes) is inlined
// at bootstrap_send_'s single use site.

template <int k>
constexpr int n_subvoles() {
    static_assert(k >= 1 && k <= 8 && (128 % k) == 0,
                  "softspoken: k must be in {1, 2, 4, 8} so n*k == 128");
    return 128 / k;
}

// Maximum chunk size (in bpr-blocks) the streaming pipeline emits.
constexpr int kMaxChunkBlocks = emp::tuning::softspoken_chunk_blocks_max;

// Per-k chunk size (in bpr-blocks). Values live in tuning.h.
template <int k>
constexpr int chunk_blocks_for() {
    return emp::tuning::softspoken_chunk_blocks<k>();
}

}}  // namespace emp::softspoken

namespace emp {

// SoftSpoken OT Extension — RandomCOT subclass.
// [REF] L. Roy, "SoftSpoken" (Crypto '22, eprint 2022/192).
//
// Templated on k = F_{2^k} sub-field exponent (k ∈ {2, 4, 8}). Larger k
// = less bandwidth (~κ/k B/COT) but more compute (~2^k/k AES blocks
// /COT). Pre-instantiated for k in {2, 4, 8} in softspoken.cpp.
//
// Pipeline + malicious-mode design lives in softspoken.cpp.
template <int k, int kChunkBlocks = softspoken::chunk_blocks_for<k>()>
class SoftSpoken : public OTExtension {
    static_assert(k >= 1 && k <= 8, "SoftSpoken supports k in [1, 8]");
public:
    static constexpr int n = softspoken::n_subvoles<k>();
    static constexpr int Q = 1 << k;

    // Default base OT is CSW (CDH-based "Blazing Fast" OT, malicious-secure).
    // Pass another (PVW / BMM) via the fourth ctor arg.
    explicit SoftSpoken(int party, IOChannel* io_,
                          bool malicious = true,
                          std::unique_ptr<OT> base_ot = nullptr);
    ~SoftSpoken() override = default;

    // Spawn a lane: a clone that SHARES this (already-bootstrapped) instance's
    // checked VOLE material (leaves, alphas, Δ) but runs an INDEPENDENT COT
    // extension on `new_io`, domain-separated by `lane_salt`. Lets L lanes
    // extend DISJOINT output ranges concurrently on L channels (one COT
    // instance's compute/transfer then fills more cores; see
    // docs/design/softspoken_lanes.md + threading_model.md).
    //
    // `lane_salt` MUST be nonzero and distinct per lane (0 is reserved for this
    // parent). It salts the per-chunk session AES key's HIGH 64 bits, so each
    // lane is an independent keystream domain over the shared leaves; a
    // duplicate/zero salt silently reuses a lane's COTs, so the caller must
    // allocate salts as a dense index (salt = lane index) from one source of
    // truth. For cross-peer choice consistency the caller must ALSO make the
    // [0,length) partition and salt a pure function of the lane index (never of
    // peer identity). This parent, and every `new_io`, must outlive the clone.
    std::unique_ptr<SoftSpoken> clone_lane(IOChannel* new_io, uint16_t lane_salt) const {
        return std::unique_ptr<SoftSpoken>(
            new SoftSpoken(OTExtension::CloneInit{}, *this, new_io, lane_salt));
    }

    static constexpr int kChunkBlocks_value = kChunkBlocks;
    static constexpr int kChunkOTs          = kChunkBlocks * 128;
    int64_t chunk_size() const override { return kChunkOTs; }

    // Per-chunk extend (next()) traffic direction: the OT-sender role here is
    // recv-dominant (recv_block of the d_buf correction), the receiver send-
    // dominant. Callers that interleave the COT with a fixed-direction protocol
    // on the same sockets read this to place the send-dominant role on the
    // send channel. (Ferret is the opposite — its sender sends per tree.)
    static constexpr bool kSenderSendsOnExtend = false;

    // StreamingExtension lifecycle. Party-dispatches inline to the
    // private per-role helpers below — SoftSpoken's sender and receiver
    // paths share no per-stage work.
    void begin() override;
    void next(block* out) override;
    void end() override;

private:
    // Clone ctor (used by clone_lane): construct a FRESH object — leaving all
    // mutable base-class state at its default — then copy the parent's shared
    // checked material. Never copy-construct a clone (that would alias the
    // parent's leftover_/mitccrh/prg). Defined in softspoken.cpp.
    SoftSpoken(OTExtension::CloneInit, const SoftSpoken& parent,
               IOChannel* new_io, uint16_t lane_salt);

    uint64_t session_ = 0;
    // Per-chunk session AES key's HIGH 64 bits (lane domain separator). 0 for
    // every non-clone instance -> makeBlock(0, session) is byte-identical to the
    // pre-lane code; the `= 0` in-class initializer is load-bearing for that
    // (the normal ctor's init list does not set it). Clones get a nonzero salt.
    uint16_t lane_salt_ = 0;

    // COT-Sender (= VOLE-Receiver / PPRF-Receiver) state.
    int alphas_[n] = {0};
    BlockVec leaves_recv_;          // n * Q blocks; punctured at alphas_[i]

    // COT-Receiver (= VOLE-Sender / PPRF-Sender) state.
    BlockVec leaves_send_;          // n * Q blocks; full GGM tree

    // Streaming session state.
    uint64_t cur_send_session_ = 0;
    uint64_t cur_recv_session_ = 0;
    int64_t cur_send_b0_ = 0;
    int64_t cur_recv_b0_ = 0;

    // Per-chunk scratch (lazily resized on first _next; reused across
    // chunks within and across sessions).
    BlockVec planes_chunk_;         // n * k * kChunkBlocks blocks
    BlockVec d_bufs_chunk_;         // (n - 1) * kChunkBlocks blocks

    // Malicious-mode chi-fold state.
    GaloisFieldPacking packer_;     // pack128 for F_{2^128} chi-fold
    block check_q_  = zero_block;   // sender's running fold
    block check_t_  = zero_block;   // receiver's running fold (T_i)
    block check_x_  = zero_block;   // receiver's running fold (R_i)
    BlockVec check_chi_chunk_;      // bs chi_i values for deferred inner product
    BlockVec check_pack_chunk_;     // bs packed Q_i / T_i values

    // Setup halves, lazy on first begin() per role.
    void bootstrap_send_();
    void bootstrap_recv_();
    void ensure_chunk_scratch_();
    // Malicious-mode PPRF check (Roy '22 Fig. protpprfconsistency).
    void pprf_check_send();
    void pprf_check_recv();
    // Per-chunk subspace-VOLE chi-fold (Roy '22 Fig. protvoleconsistency).
    void combine_send_chunk(block* out, int64_t bs);
    void combine_recv_chunk(block* out, const block* u_canonical, int64_t bs);
    // Per-chunk pipeline at arbitrary bs (1..kChunkBlocks). Called with
    // bs=kChunkBlocks from {send,recv}_next_, bs=1 from the sacrificial
    // chunk in {send,recv}_end_.
    void send_chunk_pipeline(block* out, int64_t bs);
    void recv_chunk_pipeline(block* out, int64_t bs);

    // Per-role bodies invoked from begin/next/end with inline
    // party-dispatch.
    void send_begin_();
    void send_next_(block* out);
    void send_end_();
    void recv_begin_();
    void recv_next_(block* out);
    void recv_end_();
};

extern template class SoftSpoken<2>;
extern template class SoftSpoken<4>;
extern template class SoftSpoken<8>;
// Smaller-chunk variant for Ferret::bootstrap_base_cots_.
extern template class SoftSpoken<8, emp::tuning::softspoken_ferret_bootstrap_chunk_blocks>;

} // namespace emp
#endif
