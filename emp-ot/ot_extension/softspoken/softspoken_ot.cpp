// SoftSpoken OT Extension implementation. See header for the public
// interface; the rest of this file documents the design.
//
// ===== Protocol shape =====
//
// RandomCOT: after sfvole_sender_butterfly / sfvole_receiver_butterfly
// emit (u, V) and (W) respectively, the COT relation Conv(V[j]) ⊕
// Conv(W[j]) = u_canonical[j] · Δ holds at the full-block level.
// rcot_send / rcot_recv expose this with the LSB-encoded choice
// convention (LSB(K) = 0, LSB(M) = u_canonical[j]). send_cot / recv_cot
// are inherited from RandomCOT, which adds the standard 1-bit-per-COT
// chosen-message correction wrapper.
//
// Δ has LSB=1 (forced by the base OTExtension ctor / set_delta).
// The LSB-encoded choice convention needs that bit to round-trip
// the COT relation correctly.
//
// ===== Per-k chunk-size rationale =====
//
// kChunkBlocks (chunk_blocks_for<k>() in the header):
//   k=2 → 128: little compute per leaf — small chunk avoids cache
//              pressure.
//   k=4 → 1024: heavier compute per leaf supports a larger
//               amortization window.
//   k=8 → 1024: Q=256 leaves means lots of fold work per chunk;
//               the larger window amortizes setup overhead.
//
// FerretCOT's bootstrap instantiates SoftSpokenOT<8, 580> so its
// one-shot ~74k base-COT request fits in a single chunk instead of
// overproducing the default 131,072-OT chunk and shipping ~107 KB of
// unused PPRF planes over the wire.
//
// ===== Streaming pipeline =====
//
// rcot_send / rcot_recv chunk the OT-output axis: begin → loop _next
// → end runs one session with a fresh session_id; cur_*_b0_ tracks the
// per-session PRG counter offset (in bpr-blocks) consumed by previous
// _next calls so the keystream across chunks of one session matches
// one bulk PRG invocation.
//
// Per chunk:
//   1. For every sub-VOLE i ∈ [0, n), sfvole_*_butterfly<k> writes
//      this chunk's u_canonical / v_planes (OT-receiver side) or
//      w_planes (OT-sender side).
//   2. OT-receiver side batches the n-1 d_buf_i = u_canonical ⊕ u_i
//      vectors into one io->send_block; OT-sender side reads them
//      with io->recv_block and applies the per-bit XOR to w_planes_i.
//   3. LSB pinning: sub-VOLE 0's plane 0 is forced to 0 / u_canonical
//      on the two sides so bit_0 of every output block carries the
//      receiver's choice.
//   4. One sse_trans_n128 over the chunk-local plane buffer writes
//      bs*128 OT blocks.
//
// ===== Malicious mode =====
//
// Two checks compose to upgrade from semi-honest to malicious-secure
// (Roy '22 Fig. protpprfconsistency + protvoleconsistency):
//
//   (1) PPRF check, once at end of setup_*. The PPRF-sender (=
//       COT-receiver) commits to its leaves via an expanded SHA-256
//       digest + XOR t̂ over PRG'-expanded check material. The
//       PPRF-receiver reconstructs s'_{α_i} (the 2λ check material,
//       not the real leaf) from t̂ and the digest, verifying the
//       commitment without learning leaves[α_i]. Bounds the per-sub-
//       VOLE selective-abort leakage to affinesub(F_2^k) (Roy Prop.
//       pprfcheckattack). Details inline below at pprf_check_send /
//       pprf_check_recv.
//
//   (2) Subspace VOLE check, once per begin/next…/end session. Each
//       chunk's d_bufs are absorbed into the IOChannel FS transcript
//       via send_data / recv_data; chi seed comes from
//       io->get_digest(). Both sides chi-fold packed F_{2^128} elements
//       over post-Conv outputs (sender accumulates check_q := Σ chi_i
//       · Q_i, receiver check_t := Σ chi_i · T_i and check_x := Σ chi_i
//       · R_i where R_i = u_canonical[i]). One 128-OT sacrificial chunk
//       runs in *_end before the (check_x, check_t) exchange and the
//       check_q ?= check_t ⊕ check_x · Δ compare. Same shape as IKNP
//       — see emp-ot/iknp.{h,cpp}.

#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"
#include "emp-ot/ot_extension/ferret/constants.h"   // lsb_clear_mask, lsb_only_mask
#include <algorithm>
#include <cassert>
#include <cstring>

namespace emp {

template <int k, int kChunkBlocks>
SoftSpokenOT<k, kChunkBlocks>::SoftSpokenOT(int party, IOChannel* io_, bool malicious,
                              std::unique_ptr<OT> base_ot)
    : OTExtension(party, io_, malicious, std::move(base_ot)) {}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::bootstrap_send_() {
    // Δ = α_0 + α_1·X + … + α_{n-1}·X^{n-1} over F_{2^k}: α_i is the
    // i-th k-bit slice of Δ (LSB-first within α_i). Base OT choice
    // bits ᾱ_{i,j} = 1 − α_{i,j} are sent MSB-first per α_i. The
    // base-class delta_bool[] is the Δ bool mirror.
    const int total = n * k;     // == 128
    // unsigned char (not bool) so .data() is contiguous one-byte-each
    // storage; the OT::recv signature still expects bool* so we
    // reinterpret_cast at the call boundary.
    default_init_vector<unsigned char> choices(total);
    for (int i = 0; i < n; ++i) {
        int alpha = 0;
        for (int j = 1; j <= k; ++j) {
            // α_{i,j} (j-th MSB of α_i) = bit (k-j) of α_i = delta_bool[i*k + (k-j)].
            const bool b = delta_bool[i*k + (k - j)];
            if (b) alpha |= 1 << (k - j);
            choices[i*k + (j-1)] = !b;
        }
        alphas_[i] = alpha;
    }

    BlockVec received(total);
    base_ot->recv(received.data(),
                  reinterpret_cast<bool*>(choices.data()), total);

    // Reconstruct each sub-VOLE's punctured GGM tree. cggm::eval_receiver
    // fills leaves[x] for x != alpha_i and pins leaves[alpha_i] to zero.
    leaves_recv_.resize(static_cast<size_t>(n) * Q);
    block K_recv[k];
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < k; ++j) K_recv[j] = received[i * k + j];
        cggm::eval_receiver(k, alphas_[i], K_recv, &leaves_recv_[i * Q]);
    }

    if (malicious) pprf_check_recv();

    setup_done = true;
    // OT-sender is the FS send_first side (convention shared across
    // IKNP / SoftSpoken / FerretCOT). When ferret nests SoftSpoken it
    // has already enabled FS, so this is a no-op.
    if (malicious && !this->io->fs_enabled())
        this->io->enable_fs(/*send_first=*/is_ot_sender());
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::bootstrap_recv_() {
    // Build n GGM trees and ship the per-level XOR sums via base OT.
    // Each tree gets a fresh Δ and root; K0[h] = level-(h+1) left-side
    // XOR-sum, K1[h] = K0[h] ⊕ Δ (leveled correlation, paper §2.2).
    leaves_send_.resize(static_cast<size_t>(n) * Q);
    const int total = n * k;
    BlockVec K0(total), K1(total);
    block K0_buf[k], K1_buf[k];
    for (int i = 0; i < n; ++i) {
        block Delta, root;
        this->prg.random_block(&Delta, 1);
        this->prg.random_block(&root, 1);
        cggm::build_sender(k, Delta, root, &leaves_send_[i * Q], K0_buf);
        for (int h = 0; h < k; ++h) K1_buf[h] = K0_buf[h] ^ Delta;
        for (int j = 0; j < k; ++j) {
            K0[i * k + j] = K0_buf[j];
            K1[i * k + j] = K1_buf[j];
        }
    }
    base_ot->send(K0.data(), K1.data(), total);

    if (malicious) pprf_check_send();

    setup_done = true;
    if (malicious && !this->io->fs_enabled())
        this->io->enable_fs(/*send_first=*/is_ot_sender());
}

// =====================================================================
// Malicious-mode: PPRF consistency check (Roy '22 Fig. protpprfconsistency)
// =====================================================================
//
// Each cGGM leaf is expanded by PRG' into three blocks under a fixed
// AES key shared by both parties:
//   exp = aes_ctr_fill_dm<3>(0, &check_K, cGGM_leaf)   // CRH, 3λ output
//     exp[0]  -> the "real" leaf that downstream sfvole uses
//                (PRG'_1 in the paper); overwrites leaves_*_[y] in place.
//     exp[1:] -> s'_y, the 2λ check material (PRG'_0).
// The separation is the security-critical part: the receiver's t̂-based
// reconstruction below recovers only s'_{α_i}, not the real leaf, so
// the PPRF-Receiver still doesn't know leaves_*_[α_i] after the check.
//
// Per sub-VOLE i, the PPRF-Sender accumulates t̂_i = (⊕_y exp[1],
// ⊕_y exp[2]) and feeds every (exp[1], exp[2]) pair into a single
// global SHA-256 over (i, y) in fixed order. One rolling digest binds
// the sender across every tree at once (catches cross-tree swap
// attempts that per-tree digests would miss).
//
// The PPRF-Receiver expands every y ≠ α_i identically, accumulates
// the same XOR, reconstructs s'_{α_i} = t̂_i ⊕ ⊕_{y≠α_i} (exp[1],
// exp[2]), feeds the resulting Q × 2-block vector through its own
// rolling SHA-256, and compares.
//
// kPPRFCheckSession sits in the high 64 bits to keep the check_K
// disjoint from per-chunk sfvole session keys (which use the low 64
// bits with the high 64 bits zeroed).

namespace {
constexpr int64_t kPPRFCheckSessionHigh = 0x70505246434B5F00LL; // "pPRFCK_\0"
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::pprf_check_send() {
    constexpr int kHashSize = Hash::DIGEST_SIZE;  // 32 B

    AES_KEY check_K;
    AES_set_encrypt_key(makeBlock(kPPRFCheckSessionHigh, 0LL), &check_K);

    // t̂_i ∈ {0,1}^{2λ}: 2-block XOR per sub-VOLE of the s'_y values.
    BlockVec t_buf(static_cast<size_t>(n) * 2);

    Hash hash;

    for (int i = 0; i < n; ++i) {
        block* leaves_i = &leaves_send_[(size_t)i * Q];
        block tx = zero_block, ty = zero_block;
        for (int y = 0; y < Q; ++y) {
            block exp[3];
            emp::aes_ctr_fill_dm<3>(exp, /*counter=*/0, &check_K, leaves_i[y]);
            leaves_i[y] = exp[0];          // real leaf for sfvole downstream
            tx = tx ^ exp[1];
            ty = ty ^ exp[2];
            hash.put(&exp[1], 2 * sizeof(block));
        }
        t_buf[(size_t)i * 2]     = tx;
        t_buf[(size_t)i * 2 + 1] = ty;
    }

    unsigned char digest[kHashSize];
    hash.digest(digest);

    this->io->send_block(t_buf.data(), n * 2);
    this->io->send_data(digest, kHashSize);
    this->io->flush();
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::pprf_check_recv() {
    constexpr int kHashSize = Hash::DIGEST_SIZE;

    AES_KEY check_K;
    AES_set_encrypt_key(makeBlock(kPPRFCheckSessionHigh, 0LL), &check_K);

    BlockVec t_buf(static_cast<size_t>(n) * 2);
    unsigned char their_digest[kHashSize];
    this->io->recv_block(t_buf.data(), n * 2);
    this->io->recv_data(their_digest, kHashSize);

    Hash hash;

    // Per-tree scratch for s'_y values; we need a second pass per tree
    // to feed the global hash in (i, y) order, since s'_{α_i} only
    // becomes known after XOR-accumulating the rest.
    BlockVec s_buf(static_cast<size_t>(Q) * 2);

    for (int i = 0; i < n; ++i) {
        block* leaves_i = &leaves_recv_[(size_t)i * Q];
        block tx = zero_block, ty = zero_block;
        for (int y = 0; y < Q; ++y) {
            if (y == alphas_[i]) continue;     // leaves_recv_[α] = zero_block, pinned
            block exp[3];
            emp::aes_ctr_fill_dm<3>(exp, /*counter=*/0, &check_K, leaves_i[y]);
            leaves_i[y] = exp[0];              // real leaf for sfvole downstream
            s_buf[(size_t)y * 2]     = exp[1];
            s_buf[(size_t)y * 2 + 1] = exp[2];
            tx = tx ^ exp[1];
            ty = ty ^ exp[2];
        }
        // Reconstructed s'_{α_i}. Receiver learns this 2λ value, but
        // PRG' security keeps the real leaf PRG'_1(cGGM_leaf_{α_i})
        // hidden — leaves_recv_[α_i] stays zero_block.
        s_buf[(size_t)alphas_[i] * 2]     = t_buf[(size_t)i * 2]     ^ tx;
        s_buf[(size_t)alphas_[i] * 2 + 1] = t_buf[(size_t)i * 2 + 1] ^ ty;

        hash.put(s_buf.data(), Q * 2 * sizeof(block));
    }

    unsigned char our_digest[kHashSize];
    hash.digest(our_digest);
    if (std::memcmp(our_digest, their_digest, kHashSize) != 0)
        error("SoftSpoken PPRF check failed");
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
//     OT-receiver) or w_planes (receiver side, a.k.a. OT-sender), via
//     the butterfly kernel — one session-shared fixed AES key, leaves
//     XORed in as plaintext tweaks. PRG counter offset = cur_*_b0_
//     (advances by `bs` per chunk within the session) so the keystream
//     slice across chunks of one session matches one bulk PRG invocation.
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
// n*k*kChunkBlocks blocks (= 64 KB at the current kChunkBlocks),
// sized to fit L1 across modern x86 and Apple Silicon parts. In
// contrast the bulk path held n*k*bpr of plane data at length=2^20 —
// well past L3 on small-cache parts.

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::ensure_chunk_scratch_() {
    // n*k = 128 always (static_assert in n_subvoles<k>).
    if (planes_chunk_.size() < static_cast<size_t>(128) * kChunkBlocks)
        planes_chunk_.resize(static_cast<size_t>(128) * kChunkBlocks);
    if constexpr (n > 1) {
        if (d_bufs_chunk_.size() < static_cast<size_t>(n - 1) * kChunkBlocks)
            d_bufs_chunk_.resize(static_cast<size_t>(n - 1) * kChunkBlocks);
    }
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::do_rcot_send_begin() {
    if (!setup_done) bootstrap_send_();
    cur_send_session_ = session_++;
    cur_send_b0_ = 0;
    if (malicious) check_q_ = zero_block;
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::do_rcot_send_end() {
    if (malicious) {
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

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::do_rcot_send_next(block* out) {
    send_chunk_pipeline(out, /*bs=*/kChunkBlocks);
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::send_chunk_pipeline(block* out, int64_t bs) {
    const int64_t b0 = cur_send_b0_;             // PRG counter offset

    ensure_chunk_scratch_();
    block* w_planes_chunk = planes_chunk_.data();
    block* d_bufs = d_bufs_chunk_.data();

    // Compute every sub-VOLE's contribution to this chunk's w_planes.
    for (int i = 0; i < n; ++i) {
        block* w_i = w_planes_chunk + i * k * bs;
        softspoken::sfvole_receiver_butterfly<k>(
            alphas_[i], &leaves_recv_[i * Q],
            cur_send_session_, b0, bs, w_i);
    }

    // Pull this chunk's batched d_bufs (n-1 vectors of bs blocks).
    if (n > 1) {
        const int64_t total_d_blocks = (int64_t)(n - 1) * bs;
        this->io->recv_block(d_bufs, total_d_blocks);
        // d_bufs are now absorbed into the IOChannel FS transcript via
        // recv_block → recv_data; the matching send side absorbs the
        // same bytes via send_data, so the chi seed taken via
        // io->get_digest() in combine_send_chunk agrees with the
        // receiver's combine_recv_chunk.
        for (int i = 1; i < n; ++i) {
            block* w_i = w_planes_chunk + i * k * bs;
            const block* d_i = d_bufs + (i - 1) * bs;
            // Sub-space VOLE derandomization: for each set bit b of
            // alpha_i, XOR d_i into plane b. Mirrors the sender's
            // d_i = u_canonical ^ u_temp_i contribution.
            for (int b = 0; b < k; ++b) {
                if ((alphas_[i] >> b) & 1)
                    xorBlocksTo_arr(w_i + b * bs, d_i, bs);
            }
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
    sse_trans_n128(out, w_planes_chunk, /*ncols=*/bs * 128);

    if (malicious) combine_send_chunk(out, bs);

    cur_send_b0_ += bs;
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::do_rcot_recv_begin() {
    if (!setup_done) bootstrap_recv_();
    cur_recv_session_ = session_++;
    cur_recv_b0_ = 0;
    if (malicious) check_t_ = check_x_ = zero_block;
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::do_rcot_recv_end() {
    if (malicious) {
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

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::do_rcot_recv_next(block* out) {
    recv_chunk_pipeline(out, /*bs=*/kChunkBlocks);
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::recv_chunk_pipeline(block* out, int64_t bs) {
    const int64_t b0 = cur_recv_b0_;

    ensure_chunk_scratch_();
    block* v_planes_chunk = planes_chunk_.data();
    block* d_bufs = d_bufs_chunk_.data();

    // u_canonical / u_temp stay on the stack — kChunkBlocks blocks each
    // (16 KB at kChunkBlocks=1024). Default 8 MB main-thread stack and
    // typical thread stacks (256 KB+) handle the 32 KB pair comfortably;
    // the inner loop benefits from the buffers being reliably hot.
    block u_canonical[kChunkBlocks];   // sub-VOLE 0's u
    block u_temp[kChunkBlocks];        // sub-VOLE i ≥ 1

    // Sub-VOLE 0 produces u_canonical (no d_buf for i=0).
    {
        block* v_0 = v_planes_chunk + 0 * k * bs;
        softspoken::sfvole_sender_butterfly<k>(
            &leaves_send_[0 * Q], cur_recv_session_, b0, bs,
            u_canonical, v_0);
    }

    // For i ≥ 1: produce u_temp and v_i, then d_buf_i = u_canonical ⊕ u_temp.
    for (int i = 1; i < n; ++i) {
        block* v_i = v_planes_chunk + i * k * bs;
        softspoken::sfvole_sender_butterfly<k>(
            &leaves_send_[i * Q], cur_recv_session_, b0, bs,
            u_temp, v_i);
        block* d_i = d_bufs + (i - 1) * bs;
        xorBlocks_arr(d_i, u_canonical, u_temp, bs);
    }

    // One batched send: (n-1) * bs blocks.
    if (n > 1) {
        const int64_t total_d_blocks = (int64_t)(n - 1) * bs;
        // send_block → send_data absorbs d_bufs into the IOChannel FS
        // transcript; the matching OT-sender's recv_block does the same,
        // so io->get_digest() in combine_*_chunk agrees on both sides.
        this->io->send_block(d_bufs, total_d_blocks);
    }

    // LSB convention (IKNP-style construction): pin sub-VOLE 0's plane
    // 0 to u_canonical, so after Conv bit_0(out[j]) = bit_j(u_canonical)
    // = receiver's intrinsic choice bit. Mirrored on the sender side
    // by W_0[0] := 0. The fold work for sub-VOLE 0 plane 0 above is
    // wasted, kept for now to avoid splitting the sfvole API.
    std::memcpy(v_planes_chunk, u_canonical, sizeof(block) * bs);

    // Transpose 128 × (bs*128) bit-matrix → bs*128 output blocks.
    sse_trans_n128(out, v_planes_chunk, /*ncols=*/bs * 128);

    if (malicious) combine_recv_chunk(out, u_canonical, bs);

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

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::combine_send_chunk(block* out, int64_t bs) {
    PRG chiPRG;
    block seed = this->io->get_digest();
    chiPRG.reseed(&seed);
    block Q_i, chi, tmp;
    for (int64_t i = 0; i < bs; ++i) {
        packer_.packing(&Q_i, out + 128 * i);
        chiPRG.random_block(&chi, 1);
        gfmul(chi, Q_i, &tmp);
        check_q_ = check_q_ ^ tmp;
    }
}

template <int k, int kChunkBlocks>
void SoftSpokenOT<k, kChunkBlocks>::combine_recv_chunk(block* out, const block* u_canonical, int64_t bs) {
    PRG chiPRG;
    block seed = this->io->get_digest();
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
// Smaller-chunk variant for FerretCOT::bootstrap_base_cots_.
template class SoftSpokenOT<8, 580>;

} // namespace emp
