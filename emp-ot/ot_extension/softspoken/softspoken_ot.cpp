#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"
#include "emp-ot/ot_extension/ferret/constants.h"   // lsb_clear_mask, lsb_only_mask
#include <algorithm>
#include <cassert>
#include <cstring>

namespace emp {

template <int k>
SoftSpokenOT<k>::SoftSpokenOT(IOChannel* io_, std::unique_ptr<OT> base_ot)
    : base_ot_(base_ot ? std::move(base_ot)
                       : std::unique_ptr<OT>(new OTPVW(io_))) {
    this->io = io_;
    this->Delta = zero_block;
}

template <int k>
void SoftSpokenOT<k>::setup_send() {
    // Sample Δ with LSB=1 (required by the LSB-encoded choice
    // convention rcot_send/rcot_recv use; RandomCOT-inherited
    // send_cot/recv_cot also depend on it via getLSB(data)).
    block delta;
    this->prg.random_block(&delta, 1);
    delta = (delta & lsb_clear_mask) ^ lsb_only_mask;
    setup_send(delta);
}

template <int k>
void SoftSpokenOT<k>::setup_send(block delta_in) {
    this->Delta = delta_in;

    // Decompose Delta into n F_{2^k} elements alphas_[i].
    uint8_t alpha_bytes[256];
    softspoken::unpack<k>(this->Delta, alpha_bytes);
    for (int i = 0; i < n; ++i) alphas_[i] = alpha_bytes[i];

    // Base OT choice bits: ᾱ_{i,j} = 1 - alpha_{i,j}, with alpha_{i,1} = MSB.
    const int total = n * k;
    // unsigned char (not bool) so .data() is contiguous one-byte-each
    // storage; the OT::recv signature still expects bool* so we
    // reinterpret_cast at the call boundary.
    default_init_vector<unsigned char> choices(total);
    for (int i = 0; i < n; ++i) {
        for (int j = 1; j <= k; ++j) {
            const int alpha_j = (alphas_[i] >> (k - j)) & 1;
            choices[i * k + (j - 1)] = (alpha_j == 0);
        }
    }

    BlockVec received(total);
    base_ot_->recv(received.data(),
                   reinterpret_cast<bool*>(choices.data()), total);

    // Reconstruct each sub-VOLE's punctured GGM tree.
    leaves_recv_.resize(static_cast<size_t>(n) * Q);
    block K_recv[k];
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < k; ++j) K_recv[j] = received[i * k + j];
        softspoken::pprf_eval_receiver<k>(alphas_[i], K_recv, &leaves_recv_[i * Q]);
    }

    if (malicious_) pprf_check_recv();

    setup_done_ = true;
}

template <int k>
void SoftSpokenOT<k>::setup_recv() {
    // Build n GGM trees and ship the per-level XOR sums via base OT.
    leaves_send_.resize(static_cast<size_t>(n) * Q);
    const int total = n * k;
    BlockVec K0(total), K1(total);
    block K0_buf[k], K1_buf[k];
    for (int i = 0; i < n; ++i) {
        softspoken::pprf_build_sender<k>(this->prg,
                                          &leaves_send_[i * Q],
                                          K0_buf, K1_buf);
        for (int j = 0; j < k; ++j) {
            K0[i * k + j] = K0_buf[j];
            K1[i * k + j] = K1_buf[j];
        }
    }
    base_ot_->send(K0.data(), K1.data(), total);

    if (malicious_) pprf_check_send();

    setup_done_ = true;
}

// =====================================================================
// Malicious-mode: PPRF consistency check (Roy '22 Fig. protpprfconsistency)
// =====================================================================
//
// For each sub-VOLE i, the PPRF-sender (this side) commits to its full
// 2^k-leaf vector by sending (s'_i, t'_i):
//   s'_i = SHA256(leaves[i*Q] || ... || leaves[i*Q + Q-1])
//   t'_i = XOR_y leaves[i*Q + y]
// One batched send for all n sub-VOLEs. The PPRF-receiver matches via
// pprf_check_recv. Skip the explicit length-doubling PRG'_0 from the
// paper: leaves are already cGGM-derived pseudo-random blocks, so
// SHA-256 over them gives the same collision-resistance binding (full
// λ-bit input absorbed into 256-bit output).

template <int k>
void SoftSpokenOT<k>::pprf_check_send() {
    constexpr int kHashSize = Hash::DIGEST_SIZE;  // 32 B
    BlockVec t_buf(n);
    default_init_vector<unsigned char> s_buf((size_t)n * kHashSize);

    for (int i = 0; i < n; ++i) {
        const block* leaves_i = &leaves_send_[(size_t)i * Q];
        block t = zero_block;
        for (int y = 0; y < Q; ++y) t = t ^ leaves_i[y];
        t_buf[i] = t;
        Hash::hash_once(s_buf.data() + (size_t)i * kHashSize,
                        leaves_i, Q * (int)sizeof(block));
    }

    this->io->send_block(t_buf.data(), n);
    this->io->send_data(s_buf.data(), (size_t)n * kHashSize);
    this->io->flush();
}

template <int k>
void SoftSpokenOT<k>::pprf_check_recv() {
    constexpr int kHashSize = Hash::DIGEST_SIZE;
    BlockVec t_buf(n);
    default_init_vector<unsigned char> s_buf((size_t)n * kHashSize);
    this->io->recv_block(t_buf.data(), n);
    this->io->recv_data(s_buf.data(), (size_t)n * kHashSize);

    unsigned char dgst[kHashSize];
    for (int i = 0; i < n; ++i) {
        block* leaves_i = &leaves_recv_[(size_t)i * Q];
        // Recover the punctured leaf: leaves_recv_[alpha_i] is currently
        // zero_block (eval_receiver pinned it). t_buf[i] is the sender's
        // claimed XOR of all 2^k leaves; XORing in our (Q-1) known
        // leaves yields what the missing leaf must be for the claim to
        // hold. If the sender lied in any base OT, our reconstruction
        // of some leaves[y≠alpha_i] differs from the sender's, and the
        // Hash compare below catches it (collision-resistance of SHA-256).
        block missing = t_buf[i];
        for (int y = 0; y < Q; ++y) missing = missing ^ leaves_i[y];
        leaves_i[alphas_[i]] = missing;
        Hash::hash_once(dgst, leaves_i, Q * (int)sizeof(block));
        if (std::memcmp(dgst, s_buf.data() + (size_t)i * kHashSize, kHashSize) != 0)
            error("SoftSpoken PPRF check failed");
    }
}

// =====================================================================
// Streaming API
// =====================================================================
//
// Each rcot_*_next call processes one chunk of `chunk_len` OTs
// (multiple of 128, ≤ kChunkOTs). Internally:
//
//   * For every sub-VOLE i in [0, n), the chunk-aware sfvole_*_compute_chunk
//     produces this chunk's u_target / v_planes (sender side, a.k.a.
//     OT-receiver) or w_planes (receiver side, a.k.a. OT-sender),
//     re-keying AES from per-leaf seeds rather than persisting Q PRG
//     objects across chunks. PRG counter offset = cur_*_b0_ (advances
//     by `bs` per chunk within the session) so the keystream slice
//     across chunks of one session matches one bulk PRG invocation.
//
//   * The OT-receiver side (rcot_recv_next) batches all n-1 d_buf_i
//     vectors of this chunk into one io->send_block call (saves
//     n-2 NetIO ops per chunk vs sub-VOLE-by-sub-VOLE sends). The
//     OT-sender side (rcot_send_next) reads them with a matching
//     batched io->recv_block. Both bytes-on-the-wire orderings are
//     fixed: chunk 0's d_bufs (sub-VOLE 1..n-1 concatenated), then
//     chunk 1's, etc.
//
//   * After the chunk's planes are populated (and derand-applied on
//     the OT-sender side), one 128×(bs·128) sse_trans against the
//     chunk-local plane buffer writes `bs * 128` OT blocks to `out`
//     — the plane-major layout is exactly the row-major byte layout
//     sse_trans expects, so no gather scratch is needed. The LSB
//     convention is applied to the same chunk-local slice.
//
// Memory: the dominant inner-loop scratch is `planes_chunk` of size
// n*k*kChunkBlocks blocks = 128 * 32 = 4096 blocks = 64 KB. Sized to
// fit L1 on Apple M / Zen 5c / Sapphire Rapids (with B reducible if
// needed). In contrast the bulk path held n*k*bpr = 16 MB of plane
// data at length=2^20 — past L3 on small-cache parts.

template <int k>
void SoftSpokenOT<k>::ensure_chunk_scratch_() {
    // n*k = 128 always (static_assert in n_subvoles<k>).
    if (planes_chunk_.size() < static_cast<size_t>(128) * kChunkBlocks)
        planes_chunk_.resize(static_cast<size_t>(128) * kChunkBlocks);
    if constexpr (n > 1) {
        if (d_bufs_chunk_.size() < static_cast<size_t>(n - 1) * kChunkBlocks)
            d_bufs_chunk_.resize(static_cast<size_t>(n - 1) * kChunkBlocks);
    }
}

template <int k>
void SoftSpokenOT<k>::do_rcot_send_begin() {
    assert(setup_done_ && "rcot_send_begin: setup_send not run");
    cur_send_session_ = session_++;
    cur_send_b0_ = 0;
    if (malicious_) {
        transcript_.reset();
        check_q_ = zero_block;
    }
}

template <int k>
void SoftSpokenOT<k>::do_rcot_send_end() {
    if (malicious_) {
        // Sacrificial 128-OT chunk: extends the chi-fold by one packed
        // F_{2^128} element so the revealed (check_x, check_t) doesn't
        // determine the user-visible R/T values in any single equation.
        // Run at bs=1 directly (not through do_rcot_send_next, which
        // would compute a full kChunkOTs).
        block scratch[128];
        send_chunk_pipeline(scratch, /*bs=*/1);
        // Receiver opens (check_x, check_t); accept iff
        // check_q_ ⊕ check_x · Δ == check_t.
        block x, t, tmp;
        this->io->recv_block(&x, 1);
        this->io->recv_block(&t, 1);
        gfmul(x, this->Delta, &tmp);
        block lhs = check_q_ ^ tmp;
        if (!cmpBlock(&lhs, &t, 1))
            error("SoftSpoken subspace VOLE check failed");
    }
}

template <int k>
void SoftSpokenOT<k>::do_rcot_send_next(block* out) {
    send_chunk_pipeline(out, /*bs=*/kChunkBlocks);
}

template <int k>
void SoftSpokenOT<k>::send_chunk_pipeline(block* out, int64_t bs) {
    const int64_t b0 = cur_send_b0_;             // PRG counter offset

    ensure_chunk_scratch_();
    block* w_planes_chunk = planes_chunk_.data();
    block* d_bufs = d_bufs_chunk_.data();

    // Compute every sub-VOLE's contribution to this chunk's w_planes.
    for (int i = 0; i < n; ++i) {
        block* w_i = w_planes_chunk + static_cast<size_t>(i) * k * bs;
        softspoken::sfvole_receiver_compute_chunk<k>(
            alphas_[i], &leaves_recv_[i * Q],
            cur_send_session_, b0, bs, w_i);
    }

    // Pull this chunk's batched d_bufs (n-1 vectors of bs blocks).
    if (n > 1) {
        const int64_t total_d_blocks = static_cast<int64_t>(n - 1) * bs;
        this->io->recv_block(d_bufs, total_d_blocks);
        // Absorb d_bufs into the FS transcript at the same point as
        // the receiver does (right after its send) so the snapshot-
        // derived chi sequence agrees byte-for-byte across both sides.
        if (malicious_)
            transcript_.put(d_bufs, total_d_blocks * sizeof(block));
        for (int i = 1; i < n; ++i) {
            block* w_i = w_planes_chunk + static_cast<size_t>(i) * k * bs;
            const block* d_i = d_bufs + static_cast<size_t>(i - 1) * bs;
            softspoken::apply_derand_to_w_planes<k>(alphas_[i], d_i, bs, w_i);
        }
    }

    // LSB convention (IKNP-style construction): force sub-VOLE 0's plane
    // 0 to zero, so after Conv bit_0 of every output block is zero.
    // Mirrored on the receiver side by V_0[0] := u_canonical. The COT
    // relation V ⊕ W = u_canonical · α at bit 0 (where bit_0(α_0) = 1
    // is forced in setup_send) then holds trivially: 0 ⊕ u_canonical =
    // u_canonical. The fold work for sub-VOLE 0 plane 0 above is wasted,
    // kept for now to avoid splitting the sfvole API.
    std::memset(w_planes_chunk, 0, sizeof(block) * bs);

    // Transpose 128 × (bs*128) bit-matrix → bs*128 output blocks.
    // w_planes_chunk's plane-major layout is exactly the row-major
    // byte layout sse_trans_n128 consumes.
    sse_trans_n128(reinterpret_cast<uint8_t*>(out),
                   reinterpret_cast<const uint8_t*>(w_planes_chunk),
                   /*ncols=*/bs * 128);

    if (malicious_) combine_send_chunk(out, bs);

    cur_send_b0_ += bs;
}

template <int k>
void SoftSpokenOT<k>::do_rcot_recv_begin() {
    assert(setup_done_ && "rcot_recv_begin: setup_recv not run");
    cur_recv_session_ = session_++;
    cur_recv_b0_ = 0;
    if (malicious_) {
        transcript_.reset();
        check_t_ = check_x_ = zero_block;
    }
}

template <int k>
void SoftSpokenOT<k>::do_rcot_recv_end() {
    if (malicious_) {
        // Mirror the sender's sacrificial chunk at bs=1, then open the
        // chi-fold accumulators. Must run before the io->flush() below
        // so the (check_x, check_t) bytes go out in the same flush.
        block scratch[128];
        recv_chunk_pipeline(scratch, /*bs=*/1);
        this->io->send_block(&check_x_, 1);
        this->io->send_block(&check_t_, 1);
    }
    // Flush any d_buf bytes still buffered in NetIO so the peer's
    // matching do_rcot_send_next can complete.
    this->io->flush();
}

template <int k>
void SoftSpokenOT<k>::do_rcot_recv_next(block* out) {
    recv_chunk_pipeline(out, /*bs=*/kChunkBlocks);
}

template <int k>
void SoftSpokenOT<k>::recv_chunk_pipeline(block* out, int64_t bs) {
    const int64_t b0 = cur_recv_b0_;

    ensure_chunk_scratch_();
    block* v_planes_chunk = planes_chunk_.data();
    block* d_bufs = d_bufs_chunk_.data();

    // u_canonical / u_temp stay on the stack — kChunkBlocks blocks each
    // (16 KB at kChunkBlocks=1024). Default 8 MB main-thread stack and
    // typical thread stacks (256 KB+) handle the 32 KB pair comfortably;
    // the inner loop benefits from the buffers being reliably hot.
    alignas(16) block u_canonical[kChunkBlocks];   // sub-VOLE 0's u
    alignas(16) block u_temp[kChunkBlocks];        // sub-VOLE i ≥ 1

    // Sub-VOLE 0 produces u_canonical (no d_buf for i=0).
    {
        block* v_0 = v_planes_chunk + 0 * k * bs;
        softspoken::sfvole_sender_compute_chunk<k>(
            &leaves_send_[0 * Q], cur_recv_session_, b0, bs,
            u_canonical, v_0);
    }

    // For i ≥ 1: produce u_temp and v_i, then d_buf_i = u_canonical ⊕ u_temp.
    for (int i = 1; i < n; ++i) {
        block* v_i = v_planes_chunk + static_cast<size_t>(i) * k * bs;
        softspoken::sfvole_sender_compute_chunk<k>(
            &leaves_send_[i * Q], cur_recv_session_, b0, bs,
            u_temp, v_i);
        block* d_i = d_bufs + static_cast<size_t>(i - 1) * bs;
        for (int64_t bb = 0; bb < bs; ++bb)
            d_i[bb] = u_canonical[bb] ^ u_temp[bb];
    }

    // One batched send: (n-1) * bs blocks.
    if (n > 1) {
        const int64_t total_d_blocks = static_cast<int64_t>(n - 1) * bs;
        this->io->send_block(d_bufs, total_d_blocks);
        // Same FS absorption point as the sender's matching recv.
        if (malicious_)
            transcript_.put(d_bufs, total_d_blocks * sizeof(block));
    }

    // LSB convention (IKNP-style construction): pin sub-VOLE 0's plane
    // 0 to u_canonical, so after Conv bit_0(out[j]) = bit_j(u_canonical)
    // = receiver's intrinsic choice bit. Mirrored on the sender side
    // by W_0[0] := 0. The fold work for sub-VOLE 0 plane 0 above is
    // wasted, kept for now to avoid splitting the sfvole API.
    std::memcpy(v_planes_chunk, u_canonical, sizeof(block) * bs);

    // Transpose 128 × (bs*128) bit-matrix → bs*128 output blocks.
    sse_trans_n128(reinterpret_cast<uint8_t*>(out),
                   reinterpret_cast<const uint8_t*>(v_planes_chunk),
                   /*ncols=*/bs * 128);

    if (malicious_) combine_recv_chunk(out, u_canonical, bs);

    cur_recv_b0_ += bs;
}

// =====================================================================
// Malicious-mode: per-chunk subspace VOLE chi-fold
// =====================================================================
//
// Each chunk's bs * 128 OT outputs satisfy the IKNP-shape relation
//   Q_i ⊕ T_i = R_i · Δ in F_{2^128},
// where (Q_i, T_i) = pack128(out[128i..128i+127]) on each side and
// R_i = u_canonical[i]. Chi-fold accumulates chi_i · {Q,T,R}_i into
// running checks; the final check at *_end verifies the linear
// relation under one fresh chi (statistical soundness ≈ 2^{-128}).
// Same shape as IKNP::combine_send / combine_recv — see iknp.cpp.

template <int k>
void SoftSpokenOT<k>::combine_send_chunk(block* out, int64_t bs) {
    PRG chiPRG;
    block seed;
    char dgst[Hash::DIGEST_SIZE];
    transcript_.digest(dgst, /*reset_after=*/false);
    std::memcpy(&seed, dgst, sizeof(block));
    chiPRG.reseed(&seed);
    block Q_i, chi, tmp;
    for (int64_t i = 0; i < bs; ++i) {
        packer_.packing(&Q_i, out + 128 * i);
        chiPRG.random_block(&chi, 1);
        gfmul(chi, Q_i, &tmp);
        check_q_ = check_q_ ^ tmp;
    }
}

template <int k>
void SoftSpokenOT<k>::combine_recv_chunk(block* out, const block* u_canonical, int64_t bs) {
    PRG chiPRG;
    block seed;
    char dgst[Hash::DIGEST_SIZE];
    transcript_.digest(dgst, /*reset_after=*/false);
    std::memcpy(&seed, dgst, sizeof(block));
    chiPRG.reseed(&seed);
    block T_i, chi, tmp;
    for (int64_t i = 0; i < bs; ++i) {
        packer_.packing(&T_i, out + 128 * i);
        // R_i = u_canonical[i]: after Conv, bit_0(out[128i+j]) =
        // bit_j(u_canonical[i]) by the LSB pinning convention, so
        // u_canonical[i] is exactly the packed F_{2^128} choice for
        // this 128-OT block.
        const block R_i = u_canonical[i];
        chiPRG.random_block(&chi, 1);
        gfmul(chi, T_i, &tmp);
        check_t_ = check_t_ ^ tmp;
        gfmul(chi, R_i, &tmp);
        check_x_ = check_x_ ^ tmp;
    }
}

template class SoftSpokenOT<2>;
template class SoftSpokenOT<4>;
template class SoftSpokenOT<8>;

} // namespace emp
