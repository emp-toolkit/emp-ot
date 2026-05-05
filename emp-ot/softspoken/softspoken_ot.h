#ifndef EMP_SOFTSPOKEN_OT_H__
#define EMP_SOFTSPOKEN_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/cot.h"
#include "emp-ot/co.h"
#include "emp-ot/cggm.h"
#include "emp-ot/softspoken/aes_ctr_fold.h"
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
// (The single-element scalar pack used to live here as `pack<k>`
// alongside a `pack_row<k>` fallback for n*k != 128. With n*k==128
// the fast path always wins, so both have been dropped. unpack<k>
// remains as the inverse direction needed by setup_send to split Δ
// into n alpha_i bytes — that's a single-block scalar op, no
// transpose involved.)

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
// PPRF: thin wrappers around the shared cGGM tree (emp-ot/cggm.h),
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
// bit-identical to a single PRG.random_block(buf, b0+bs) covering the
// same range — emp::PRG is plain CTR (output[j] = AES_seed(makeBlock(0,j))),
// so re-keying per chunk + setting the counter to b0 reproduces the
// slice. We pay one AES_set_encrypt_key per leaf per chunk (~30
// cycles) instead of persisting Q PRG objects (~800 KB at k=8);
// amortized over bs * ~10 cycles of encrypt+fold, the overhead is
// ~3/bs.
//
// Inner loop uses the fused AES-CTR + multi-target XOR-fold kernel
// from emp-tool aes.h: each leaf's r_x[bs] is generated and consumed
// inside the AES tile loop (in SIMD registers, never materialized to
// memory). Replaces the older
//   {fill r_x with counters; ParaEnc(r_x); u^=r_x; v[b]^=r_x for set bits}
// pattern, which round-tripped r_x through L1 four times per leaf.

// Maximum chunk size (in bpr-blocks) the chunked sfvole helpers will
// be called with. Sets stack-resident scratch sizing in
// softspoken_ot.cpp (u_canonical / u_temp). The fused kernel itself
// no longer needs a per-leaf scratch buffer.
constexpr int kMaxChunkBlocks = 1024;

// Per-k chunk size (in bpr-blocks). Picked from a wide A/B sweep
// across Apple M / Sapphire Rapids+ / Zen 5c at length=2^19 (ferret
// regime) and 2^24 (standalone). Curves are unimodal; these are the
// joint optima at length=2^19.
//   k=2 → 128: re-key cost is already ≤5% at bs=128; bigger just adds
//              cache pressure on small-L1 parts.
//   k=4 → 1024: heavy compute per leaf, larger amortization window
//              wins. Apple M flat across 256–1024.
//   k=8 → 1024: Q=256 means each leaf produces a lot of fold work;
//              amortization keeps winning until L2 cliff.
template <int k>
constexpr int chunk_blocks_for() {
    if constexpr (k <= 2)      return 128;
    else if constexpr (k <= 4) return 1024;
    else                       return 1024;
}

// Sender-side chunked sfvole: re-keys each leaf's AES from its 16 B
// seed, then folds AES_seed(b0..b0+bs) directly into u_bits and the
// selected v_planes via aes_ctr_fold (no r_x materialization).
template <int k>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_compute_chunk(const block leaves[1 << k],
                                        uint64_t session,
                                        int64_t b0,
                                        int64_t bs,
                                        block* u_bits_chunk,
                                        block* v_planes_chunk) {
    constexpr int Q = 1 << k;

    std::memset(u_bits_chunk,   0, sizeof(block) * bs);
    std::memset(v_planes_chunk, 0, sizeof(block) * k * bs);

    AES_KEY aes_local;
    const block session_xor = makeBlock(0LL, static_cast<int64_t>(session));

    for (int x = 0; x < Q; ++x) {
        // Matches PRG(seed=leaves[x], id=session).random_block at
        // counter offset b0: emp::PRG seeds via XOR with (0,id) and
        // emits AES_seed(counter) in CTR mode.
        AES_set_encrypt_key(leaves[x] ^ session_xor, &aes_local);

        // Build the leaf's fold target list: u always, v_planes[b] for
        // each set bit b of x. n ∈ [1, 1+k].
        block* tgts[1 + k];
        int n = 0;
        tgts[n++] = u_bits_chunk;
        for (int b = 0; b < k; ++b)
            if ((x >> b) & 1) tgts[n++] = v_planes_chunk + (size_t)b * bs;

        dispatch_ctr_fold<k>(tgts, n, static_cast<int>(bs), b0, &aes_local);
    }
}

// Receiver-side chunked sfvole. Skips x = alpha; folds AES_seed(b0..b0+bs)
// into w_planes[b] for each set bit b of (alpha XOR x).
template <int k>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_compute_chunk(int alpha,
                                          const block leaves[1 << k],
                                          uint64_t session,
                                          int64_t b0,
                                          int64_t bs,
                                          block* w_planes_chunk) {
    constexpr int Q = 1 << k;

    std::memset(w_planes_chunk, 0, sizeof(block) * k * bs);

    AES_KEY aes_local;
    const block session_xor = makeBlock(0LL, static_cast<int64_t>(session));

    for (int x = 0; x < Q; ++x) {
        if (x == alpha) continue;
        AES_set_encrypt_key(leaves[x] ^ session_xor, &aes_local);

        // For x ≠ alpha, coeff ≠ 0, so n ≥ 1. Max n = k.
        const int coeff = alpha ^ x;
        block* tgts[k > 0 ? k : 1];
        int n = 0;
        for (int b = 0; b < k; ++b)
            if ((coeff >> b) & 1) tgts[n++] = w_planes_chunk + (size_t)b * bs;

        dispatch_ctr_fold<k>(tgts, n, static_cast<int>(bs), b0, &aes_local);
    }
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

// Bulk Conv = sse_trans(out, planes, 128, bpr*128). Inlined at the
// (few) call sites in softspoken_ot.cpp / bench_conv. The plane
// buffer's plane-major layout (plane p at offset p*bpr blocks) is
// already the row-major byte layout sse_trans expects; n_subvoles<k>'s
// static_assert above guarantees n*k == 128.

}}  // namespace emp::softspoken

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
 * field VOLE. Larger k = less bandwidth (~kappa/k bytes per COT) but
 * more compute (~2^k / k AES blocks per COT). Pre-instantiated for
 * k in {2, 4, 8} in softspoken_ot.cpp.
 *
 * Streaming. rcot_send / rcot_recv chunk the OT-output axis: each
 * begin → loop _next → end runs one session, with a small per-chunk
 * plane scratch (member-resident BlockVec, sized n*k*kChunkBlocks).
 * The per-leaf AES key is re-expanded from its 16 B seed at the start
 * of every chunk — see softspoken::sfvole_*_compute_chunk above.
 *
 * Δ has LSB=1 (forced by setup_send no-arg, required of callers
 * passing setup_send(delta_in)). Required for the LSB-encoded choice
 * convention to round-trip the COT relation correctly.
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
    //
    // rcot_send / rcot_recv are thin wrappers around the streaming
    // API below: each runs one _begin → loop _next → _end session,
    // with internal chunk size kChunkBlocks * 128 OTs.
    void rcot_send(block* data, int64_t length) override;
    void rcot_recv(block* data, int64_t length) override;

    // Streaming API — IKNP-shape. After _begin(), call _next() any
    // number of times with chunk_len a multiple of 128 and ≤
    // kChunkBlocks * 128, then _end() to flush. Setup must already be
    // done (one-shot wrappers above auto-run setup; the streaming
    // entry points assert it).
    static constexpr int kChunkBlocks = softspoken::chunk_blocks_for<k>();
    static constexpr int kChunkOTs    = kChunkBlocks * 128;

    void rcot_send_begin();
    void rcot_send_next(block* out, int64_t chunk_len);
    void rcot_send_end();

    void rcot_recv_begin();
    void rcot_recv_next(block* out, int64_t chunk_len);
    void rcot_recv_end();

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

private:
    OTCO base_ot_;
    bool setup_done_ = false;
    uint64_t session_ = 0;

    // COT-Sender (= VOLE-Receiver / PPRF-Receiver) state.
    int alphas_[n] = {0};
    std::unique_ptr<block[]> leaves_recv_;  // n * Q blocks; punctured at alphas_[i]

    // COT-Receiver (= VOLE-Sender / PPRF-Sender) state.
    std::unique_ptr<block[]> leaves_send_;  // n * Q blocks; full GGM tree

    // Streaming session state. Each begin/next.../end runs one
    // SoftSpoken session with a fresh session_id; cur_*_b0 tracks the
    // PRG counter offset (in bpr-blocks) consumed by previous _next
    // calls in this session.
    bool send_session_active_ = false;
    bool recv_session_active_ = false;
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

    void setup_send();
};

extern template class SoftSpokenOT<2>;
extern template class SoftSpokenOT<4>;
extern template class SoftSpokenOT<8>;

} // namespace emp
#endif
