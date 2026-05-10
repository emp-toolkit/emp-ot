#ifndef EMP_SOFTSPOKEN_OT_H__
#define EMP_SOFTSPOKEN_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/pvw.h"
#include "emp-ot/ot_extension/cggm.h"
#include "emp-ot/ot_extension/softspoken/sfvole_butterfly.h"
#include <cstdint>
#include <cstring>
#include <memory>

namespace emp { namespace softspoken {

// =====================================================================
// Conv: F_2-linear bit packing between F_{2^k}^n and F_{2^128}.
// Bit (i*k + b) of the 128-bit output = bit b of the i-th F_{2^k} input.
// Constrained to k ∈ {1, 2, 4, 8} so n*k = 128 exactly; the bulk
// direction (Conv across many OTs at once) is then exactly a
// 128 × (bpr*128) sse_trans of the contiguous plane buffer — call
// sse_trans directly at the use site (see softspoken_ot.cpp).
//
// `unpack<k>` is the inverse direction, used by setup_send to split
// Δ into n alpha_i bytes — a single-block scalar op, no transpose
// involved.

template <int k>
constexpr int n_subvoles() {
    static_assert(k >= 1 && k <= 8 && (128 % k) == 0,
                  "softspoken: k must be in {1, 2, 4, 8} so n*k == 128");
    return 128 / k;
}

// Decompose a 128-bit block into n F_{2^k} elements (low k bits of
// each output byte hold the value). Used once per session in
// setup_send to split Δ into per-sub-VOLE alpha_i.
template <int k>
inline void unpack(block in, uint8_t* out_n) {
    constexpr int n = n_subvoles<k>();
    uint8_t bytes[16];
    std::memcpy(bytes, &in, 16);
    for (int i = 0; i < n; ++i) {
        uint8_t v = 0;
        for (int b = 0; b < k; ++b) {
            const int bitpos = i * k + b;
            v |= ((bytes[bitpos >> 3] >> (bitpos & 7)) & 1u) << b;
        }
        out_n[i] = v;
    }
}

// =====================================================================
// PPRF: thin wrappers around the shared cGGM tree (emp-ot/ot_extension/cggm.h),
// reused as a punctured PRF here because softspoken never reveals Δ to
// the receiver (no per-COT correction byte, no global-Δ base-COT
// layer). With per-tree fresh Δ, the receiver's view of leaves[α]
// stays pseudorandom even though XOR(leaves) = Δ holds.

// Sender: sample fresh Δ and root from `rng`, build the depth-k cGGM
// tree. K0[h] is the level-(h+1) left-side XOR-sum; K1[h] = K0[h] ⊕ Δ
// via leveled correlation. The (K0, K1) pair is shipped via base
// 1-of-2 OTs by the caller.
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

// Receiver: alpha in [0, 2^k) is the punctured leaf index, MSB-first.
// On return, leaves[x] is correct for every x != alpha; leaves[alpha]
// = zero_block.
template <int k>
inline void pprf_eval_receiver(int alpha,
                               const block K_recv[k],
                               block leaves[1 << k]) {
    cggm::eval_receiver(k, alpha, K_recv, leaves);
}

// =====================================================================
// Sub-space VOLE inner loop (chunked).
//
// Chunked variants take a counter offset b0 and chunk length bs (in
// bpr-blocks). Chunk c reads PRG output blocks [b0, b0+bs). Output is
// bit-identical to a single PRG.random_block over the same range —
// chunking + setting the counter to b0 reproduces the slice.
//
// PRG semantics: PRG_x(j) = AES_K(j ⊕ leaves[x] ⊕ session_xor) where
// K is a session-shared fixed AES key (built from emp-tool's `fix_key`
// constant). Treats AES_K as a random permutation, mirroring the
// PRP / CCRH / MITCCRH model already in emp-tool. The leaf is folded
// into the AES plaintext as a tweak rather than the AES key, so round
// keys persist across all Q × bs encryptions in a chunk and the key
// schedule is one-shot per kernel call instead of per-leaf.
//
// Inner loop uses the recursive butterfly kernel (sfvole_butterfly.h):
// Q AES outputs materialize into a tile-local stack scratch A[Q][T],
// then a k-round in-place XOR halving over the leaf axis emits the k
// v_planes (sender) or w_planes (receiver) and u. Same algorithm
// across all k ∈ {2, 4, 8}; all per-architecture code lives in
// sfvole_butterfly.h's aes_T_blocks_to.

// Maximum chunk size (in bpr-blocks) the chunked sfvole helpers will
// be called with. Sets stack-resident scratch sizing in
// softspoken_ot.cpp (u_canonical / u_temp).
constexpr int kMaxChunkBlocks = 1024;

// Per-k chunk size (in bpr-blocks). Larger chunks amortize per-chunk
// overhead better but eventually hit cache pressure; per-leaf compute
// grows as 2^k, so larger k tolerates a larger chunk.
//   k=2 → 128:  little compute per leaf — small chunk avoids cache
//               pressure.
//   k=4 → 1024: heavier compute per leaf supports a larger
//               amortization window.
//   k=8 → 1024: Q=256 leaves means lots of fold work per chunk.
template <int k>
constexpr int chunk_blocks_for() {
    if constexpr (k <= 2)      return 128;
    else if constexpr (k <= 4) return 1024;
    else                       return 1024;
}

// Sender-side chunked sfvole. Thin wrapper over the butterfly kernel
// (sfvole_butterfly.h); the wrapper exists so callers (softspoken_ot.cpp,
// prof_sfvole_local.cpp) can call a stable sfvole_*_compute_chunk
// interface without depending on the butterfly's specific signature.
template <int k>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_compute_chunk(const block leaves[1 << k],
                                        uint64_t session,
                                        int64_t b0,
                                        int64_t bs,
                                        block* u_bits_chunk,
                                        block* v_planes_chunk) {
    sfvole_sender_butterfly<k>(leaves, session, b0, bs,
                                u_bits_chunk, v_planes_chunk);
}

// Receiver-side chunked sfvole. Wrapper-shaped like the sender; the
// receiver butterfly skips x=alpha implicitly via leaves[alpha] =
// zero_block (pinned by pprf_eval_receiver).
template <int k>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_compute_chunk(int alpha,
                                          const block leaves[1 << k],
                                          uint64_t session,
                                          int64_t b0,
                                          int64_t bs,
                                          block* w_planes_chunk) {
    sfvole_receiver_butterfly<k>(alpha, leaves, session, b0, bs,
                                  w_planes_chunk);
}

// Apply d_i (bs blocks) to receiver's w_planes_i: for each set bit b
// of alpha_i, XOR d_i into plane b. Sub-space VOLE derandomization
// step on the OT-sender side.
template <int k>
inline void apply_derand_to_w_planes(int alpha_i,
                                     const block* d_i,
                                     int64_t bs,
                                     block* w_planes) {
    for (int b = 0; b < k; ++b) {
        if ((alpha_i >> b) & 1) {
            block* dst = w_planes + b * bs;
            for (int64_t j = 0; j < bs; ++j)
                dst[j] = dst[j] ^ d_i[j];
        }
    }
}

// Bulk Conv = sse_trans(out, planes, 128, bpr*128). The plane
// buffer's plane-major layout (plane p at offset p*bpr blocks) is
// already the row-major byte layout sse_trans expects; n_subvoles<k>'s
// static_assert above guarantees n*k == 128.

}}  // namespace emp::softspoken

namespace emp {

/*
 * SoftSpoken OT Extension — RandomCOT subclass, semi-honest by
 * default; call `set_malicious(true)` before setup to enable the two
 * malicious-security checks.
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
 * field VOLE. Larger k = less bandwidth (~kappa/k bytes per COT) but
 * more compute (~2^k / k AES blocks per COT). Pre-instantiated for
 * k in {2, 4, 8} in softspoken_ot.cpp.
 *
 * Streaming. rcot_send / rcot_recv chunk the OT-output axis: each
 * begin → loop _next → end runs one session, with a small per-chunk
 * plane scratch (member-resident BlockVec, sized n*k*kChunkBlocks).
 * The inner loop uses a session-shared fixed AES key with each leaf
 * as a plaintext tweak; see softspoken::sfvole_*_compute_chunk above.
 *
 * Δ has LSB=1 (forced by setup_send no-arg, required of callers
 * passing setup_send(delta_in)). Required for the LSB-encoded choice
 * convention to round-trip the COT relation correctly.
 *
 * Malicious mode (off by default). Two checks compose to upgrade from
 * the semi-honest baseline to malicious-secure (Roy '22 Fig.
 * `protpprfconsistency` and Fig. `protvoleconsistency`):
 *
 *   (1) PPRF check, run once at end of setup_send / setup_recv. The
 *       PPRF-sender (= COT-receiver / setup_recv side) ships per-level
 *       K^0/K^1 blocks via base OT and could lie there to corrupt the
 *       PPRF-receiver's (= COT-sender / setup_send side) leaves at
 *       indices y ≠ alpha_i. To bind, the PPRF-sender sends per-sub-
 *       VOLE (s' := SHA256(leaves), t' := XOR-of-leaves); the
 *       PPRF-receiver reconstructs leaves[alpha_i] = t' XOR
 *       XOR_{y≠alpha_i} leaves[y], hashes the full vector, and aborts
 *       on mismatch. Bounds the per-sub-VOLE selective-abort leakage
 *       to affinesub(F_2^k) (Roy Prop. `pprfcheckattack`).
 *
 *   (2) Subspace VOLE check, run once per begin/next…/end session.
 *       Each chunk derives chi by snapshotting the IOChannel FS
 *       transcript (io->get_digest()) — d_bufs bytes are absorbed
 *       automatically by send_data/recv_data, no per-chunk puts
 *       needed. Both sides chi-fold packed F_{2^128} elements over the
 *       post-Conv outputs (sender accumulates check_q := Σ chi_i ·
 *       Q_i, receiver check_t := Σ chi_i · T_i, check_x := Σ chi_i ·
 *       R_i where R_i = u_canonical[i]). One 128-OT sacrificial chunk
 *       runs in *_end before the (check_x, check_t) exchange and the
 *       check_q ?= check_t ⊕ check_x · Δ compare. Catches any
 *       deviation by the VOLE-sender (= COT-receiver) in the d_bufs
 *       syndrome. Same chi-fold shape as IKNP — see emp-ot/iknp.{h,cpp}.
 */
template <int k>
class SoftSpokenOT : public OTExtension {
    static_assert(k >= 1 && k <= 8, "SoftSpokenOT supports k in [1, 8]");
public:
    static constexpr int n = softspoken::n_subvoles<k>();
    static constexpr int Q = 1 << k;

    // User-supplied base OT, owned by SoftSpokenOT. Defaults to OTPVW
    // (DDH messy-mode PVW '08 — malicious-secure). Pass a different
    // one (e.g., OTCSW or OTPVWKyber) via the second ctor arg.
    explicit SoftSpokenOT(IOChannel* io_, std::unique_ptr<OT> base_ot = nullptr);
    ~SoftSpokenOT() override = default;

    // OTExtension contract. The base class supplies rcot_send /
    // rcot_recv as wrappers around do_rcot_*_begin/_next/_end with
    // chunk_ots() = kChunkOTs.
    static constexpr int kChunkBlocks = softspoken::chunk_blocks_for<k>();
    static constexpr int kChunkOTs    = kChunkBlocks * 128;
    int64_t chunk_ots() const override { return kChunkOTs; }

    // Externally-provided Δ (must have LSB=1). The decomposition
    // unpack<k>(Δ, ...) into alphas_ works for any Δ ∈ F_{2^128};
    // setup proceeds identically. Used by ferret to share its global
    // Δ with the bootstrap base-OT generator.
    void setup_send(block delta_in);

    // Receiver-role setup. Exposed so ferret can drive the bootstrap
    // explicitly (rcot_send/rcot_recv auto-run the matching setup on
    // first call, but ferret wants to synchronize role selection with
    // its own party flag).
    void setup_recv();

    // Enable malicious-mode checks. Must be called BEFORE setup_send /
    // setup_recv so the PPRF check runs at the tail of setup. Once
    // setup is done, the flag also gates the per-session subspace
    // VOLE check in rcot_*_begin/next/end. Asserts that the base OT
    // is itself malicious-secure (a semi-honest base would invalidate
    // the malicious-mode security claim).
    void set_malicious(bool on = true) {
        if (on && !base_ot_->is_malicious_secure())
            error("SoftSpokenOT::set_malicious(true) requires a malicious-secure base OT");
        malicious_ = on;
    }

protected:
    // OTExtension hooks. Each do_*_next writes exactly kChunkOTs blocks.
    void do_rcot_send_begin() override;
    void do_rcot_send_next(block* out) override;
    void do_rcot_send_end() override;
    void do_rcot_recv_begin() override;
    void do_rcot_recv_next(block* out) override;
    void do_rcot_recv_end() override;

    void ensure_setup_for_send() override {
        if (!setup_done_) setup_send();
    }
    void ensure_setup_for_recv() override {
        if (!setup_done_) setup_recv();
    }

private:
    std::unique_ptr<OT> base_ot_;
    bool setup_done_ = false;
    uint64_t session_ = 0;

    // COT-Sender (= VOLE-Receiver / PPRF-Receiver) state.
    int alphas_[n] = {0};
    BlockVec leaves_recv_;  // n * Q blocks; punctured at alphas_[i]

    // COT-Receiver (= VOLE-Sender / PPRF-Sender) state.
    BlockVec leaves_send_;  // n * Q blocks; full GGM tree

    // Streaming session state. Each begin/next.../end runs one
    // SoftSpoken session with a fresh session_id; cur_*_b0 tracks the
    // PRG counter offset (in bpr-blocks) consumed by previous _next
    // calls in this session.
    uint64_t cur_send_session_ = 0;
    uint64_t cur_recv_session_ = 0;
    int64_t cur_send_b0_ = 0;
    int64_t cur_recv_b0_ = 0;

    // Per-chunk scratch (allocated at the first _next call; reused
    // across chunks within and across sessions). Heap-resident so we
    // can grow B past the comfortable stack limit without changing
    // call sites.
    BlockVec planes_chunk_;   // n * k * kChunkBlocks blocks
    BlockVec d_bufs_chunk_;   // (n - 1) * kChunkBlocks blocks

    // ===== Malicious-mode state =====
    bool malicious_ = false;
    // Set in setup_send / setup_recv. Used as send_first when this
    // SoftSpokenOT instance enables IOChannel FS itself (i.e. when
    // not nested under an outer protocol that already enabled FS).
    bool is_sender_ = false;
    // Packs 128 consecutive post-Conv outputs into one F_{2^128}
    // element via (1, X, …, X^127); see iknp.cpp::combine_*.
    GaloisFieldPacking packer_;
    // Running chi-fold accumulators, reset at *_begin. Sender uses
    // check_q_; receiver uses check_t_ (folds T_i) and check_x_
    // (folds R_i = u_canonical[i]). The end-of-session compare is
    // check_q_ ?= check_t_ ⊕ check_x_ · Δ.
    block check_q_  = zero_block;
    block check_t_  = zero_block;
    block check_x_  = zero_block;

    void setup_send();
    // Resize the per-chunk scratch buffers to their full kChunkBlocks
    // capacity on first call; cheap no-op afterwards. Called at the
    // top of rcot_send_next / rcot_recv_next.
    void ensure_chunk_scratch_();
    // PPRF consistency check. _send runs on the PPRF-sender (=
    // setup_recv side); _recv on the PPRF-receiver (= setup_send
    // side). Implements Fig. `protpprfconsistency` directly on the
    // cGGM leaves (no separate PRG'_0 — leaves are already PRF
    // outputs and SHA-256 absorbs the full λ-bit input).
    void pprf_check_send();
    void pprf_check_recv();
    // Per-chunk subspace VOLE chi-fold. Both take the chunk's post-
    // Conv `out` (bs * 128 OTs) and accumulate into the matching
    // running check. Chi seed is io->get_digest(): the IOChannel FS
    // transcript snapshot taken after this chunk's d_bufs crossed the
    // wire. Mirrors IKNP::combine_*.
    void combine_send_chunk(block* out, int64_t bs);
    void combine_recv_chunk(block* out, const block* u_canonical, int64_t bs);

    // Per-chunk pipeline at arbitrary `bs` (1..kChunkBlocks). The
    // public do_rcot_*_next overrides call this with bs=kChunkBlocks;
    // the malicious-mode sacrificial chunk in do_rcot_*_end calls it
    // with bs=1 to avoid computing a wasted full-chunk pipeline.
    void send_chunk_pipeline(block* out, int64_t bs);
    void recv_chunk_pipeline(block* out, int64_t bs);
};

extern template class SoftSpokenOT<2>;
extern template class SoftSpokenOT<4>;
extern template class SoftSpokenOT<8>;

} // namespace emp
#endif
