#include "emp-ot/softspoken/softspoken_ot.h"
#include "emp-ot/ferret/constants.h"   // lsb_clear_mask, lsb_only_mask
#include <cstring>
#include <vector>

namespace emp {

template <int k>
SoftSpokenOT<k>::SoftSpokenOT(IOChannel* io_) : base_ot_(io_) {
    this->io = io_;
    this->Delta = zero_block;
}

template <int k>
void SoftSpokenOT<k>::setup_send() {
    // Sample Delta uniformly. (No LSB-bit-fix needed for the
    // chosen-message COT API: send_cot/recv_cot use explicit
    // per-bit d_chosen exchange. Callers using rcot_send/rcot_recv
    // — which DO rely on LSB(Δ)=1 — must pass Δ via the
    // setup_send(delta_in) overload below.)
    block delta;
    this->prg.random_block(&delta, 1);
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
    std::unique_ptr<bool[]> choices(new bool[total]);
    for (int i = 0; i < n; ++i) {
        for (int j = 1; j <= k; ++j) {
            const int alpha_j = (alphas_[i] >> (k - j)) & 1;
            choices[i * k + (j - 1)] = (alpha_j == 0);
        }
    }

    std::unique_ptr<block[]> received(new block[total]);
    base_ot_.recv(received.get(), choices.get(), total);

    // Reconstruct each sub-VOLE's punctured GGM tree.
    leaves_recv_.reset(new block[static_cast<size_t>(n) * Q]);
    block K_recv[k];
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < k; ++j) K_recv[j] = received[i * k + j];
        softspoken::pprf_eval_receiver<k>(alphas_[i], K_recv, &leaves_recv_[i * Q]);
    }

    setup_done_ = true;
}

template <int k>
void SoftSpokenOT<k>::setup_recv() {
    // Build n GGM trees and ship the per-level XOR sums via base OT.
    leaves_send_.reset(new block[static_cast<size_t>(n) * Q]);
    const int total = n * k;
    std::vector<block> K0(total), K1(total);
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
    base_ot_.send(K0.data(), K1.data(), total);

    setup_done_ = true;
}

template <int k>
void SoftSpokenOT<k>::send_cot(block* data, int64_t length) {
    if (!setup_done_) setup_send();
    if (length <= 0) return;

    const int64_t bpr = (length + 127) / 128;
    const uint64_t my_session = session_++;

    // Lazy-grow scratch (avoids per-call 256-MB-ish allocation at large ell).
    const size_t needed = static_cast<size_t>(n) * k * bpr;
    if (planes_scratch_.size() < needed) planes_scratch_.resize(needed);
    if (planes_ptrs_.size() < static_cast<size_t>(n) * k)
        planes_ptrs_.resize(static_cast<size_t>(n) * k);
    block* w_all = planes_scratch_.data();

    for (int i = 0; i < n; ++i) {
        block* w_planes_i = w_all + static_cast<size_t>(i) * k * bpr;
        softspoken::sfvole_receiver_compute<k>(
            alphas_[i],
            &leaves_recv_[i * Q],
            my_session,
            length,
            w_planes_i);
    }

    // Receive the n-1 derandomization vectors d_i (one per sub-VOLE i >= 1)
    // and apply them to w_i's bit planes.
    std::vector<block> d_buf(bpr);
    for (int i = 1; i < n; ++i) {
        this->io->recv_block(d_buf.data(), bpr);
        block* w_planes_i = w_all + static_cast<size_t>(i) * k * bpr;
        softspoken::apply_derand_to_w_planes<k>(alphas_[i], d_buf.data(),
                                                bpr, w_planes_i);
    }

    // Pack: data[j] = Conv(W[j][0..n)). Bulk pack via 128x128 sse_trans
    // when n*k == 128 (k in {2,4,8}), else fall back to per-row.
    for (int i = 0; i < n; ++i)
        for (int b = 0; b < k; ++b)
            planes_ptrs_[i * k + b] = w_all + (static_cast<size_t>(i) * k + b) * bpr;
    softspoken::pack_planes_to_blocks<k>(planes_ptrs_.data(), n, length, bpr, data);

    // Receive d_chosen = u XOR b (one bit per COT) and XOR Delta where set.
    std::vector<uint8_t> dc_bytes((length + 7) / 8);
    this->io->recv_data(dc_bytes.data(), dc_bytes.size());
    for (int64_t j = 0; j < length; ++j) {
        if ((dc_bytes[j >> 3] >> (j & 7)) & 1u)
            data[j] = data[j] ^ this->Delta;
    }
}

template <int k>
void SoftSpokenOT<k>::recv_cot(block* data, const bool* b, int64_t length) {
    if (!setup_done_) setup_recv();
    if (length <= 0) return;

    const int64_t bpr = (length + 127) / 128;
    const uint64_t my_session = session_++;

    // Lazy-grow scratch (avoids per-call 256-MB-ish allocation at large ell).
    const size_t needed = static_cast<size_t>(n) * k * bpr;
    if (planes_scratch_.size() < needed) planes_scratch_.resize(needed);
    if (planes_ptrs_.size() < static_cast<size_t>(n) * k)
        planes_ptrs_.resize(static_cast<size_t>(n) * k);
    block* v_all = planes_scratch_.data();

    std::vector<block> u_canonical(bpr);  // u_1
    std::vector<block> u_temp(bpr);
    std::vector<block> d_buf(bpr);

    for (int i = 0; i < n; ++i) {
        block* v_planes_i = v_all + static_cast<size_t>(i) * k * bpr;
        block* u_target = (i == 0) ? u_canonical.data() : u_temp.data();
        softspoken::sfvole_sender_compute<k>(
            &leaves_send_[i * Q],
            my_session,
            length,
            u_target,
            v_planes_i);

        if (i >= 1) {
            for (int64_t bb = 0; bb < bpr; ++bb)
                d_buf[bb] = u_canonical[bb] ^ u_temp[bb];
            this->io->send_block(d_buf.data(), bpr);
        }
    }

    // Pack: data[j] = Conv(V[j][0..n)). Bulk pack via 128x128 sse_trans
    // when n*k == 128 (k in {2,4,8}), else fall back to per-row.
    for (int i = 0; i < n; ++i)
        for (int bp = 0; bp < k; ++bp)
            planes_ptrs_[i * k + bp] = v_all + (static_cast<size_t>(i) * k + bp) * bpr;
    softspoken::pack_planes_to_blocks<k>(planes_ptrs_.data(), n, length, bpr, data);

    // d_chosen[j] = bit_j(u_canonical) XOR b[j]. Pack into bytes (LSB-first
    // within each byte; same convention the sender uses on the read side).
    std::vector<uint8_t> dc_bytes((length + 7) / 8, 0);
    const uint8_t* u_bytes = reinterpret_cast<const uint8_t*>(u_canonical.data());
    for (int64_t j = 0; j < length; ++j) {
        const int u_bit  = (u_bytes[j >> 3] >> (j & 7)) & 1;
        const int chosen = u_bit ^ (b[j] ? 1 : 0);
        if (chosen) dc_bytes[j >> 3] |= static_cast<uint8_t>(1u << (j & 7));
    }
    this->io->send_data(dc_bytes.data(), dc_bytes.size());
    this->io->flush();
}

// RCOT mode: same protocol as send_cot/recv_cot but skip the
// per-COT d_chosen derandomization and apply the LSB-encoded
// choice convention (LSB(K)=0, LSB(M)=b_intrinsic). With LSB(Δ)=1
// (caller-enforced via setup_send(delta_in)), the COT relation
// M⊕K = b·Δ holds, matching the layout ferret/cGGM consume.
//
// TODO: switch to the proper IKNP-style RCOT (skip canonicalizing
// w_0 in the protocol) — see plan: avoids the LSB-mask hack and
// gives natural correlated-random output.
template <int k>
void SoftSpokenOT<k>::rcot_send(block* data, int64_t length) {
    if (!setup_done_) setup_send();
    if (length <= 0) return;

    const int64_t bpr = (length + 127) / 128;
    const uint64_t my_session = session_++;

    const size_t needed = static_cast<size_t>(n) * k * bpr;
    if (planes_scratch_.size() < needed) planes_scratch_.resize(needed);
    if (planes_ptrs_.size() < static_cast<size_t>(n) * k)
        planes_ptrs_.resize(static_cast<size_t>(n) * k);
    block* w_all = planes_scratch_.data();

    for (int i = 0; i < n; ++i) {
        block* w_planes_i = w_all + static_cast<size_t>(i) * k * bpr;
        softspoken::sfvole_receiver_compute<k>(
            alphas_[i], &leaves_recv_[i * Q], my_session, length, w_planes_i);
    }

    std::vector<block> d_buf(bpr);
    for (int i = 1; i < n; ++i) {
        this->io->recv_block(d_buf.data(), bpr);
        block* w_planes_i = w_all + static_cast<size_t>(i) * k * bpr;
        softspoken::apply_derand_to_w_planes<k>(alphas_[i], d_buf.data(),
                                                bpr, w_planes_i);
    }

    for (int i = 0; i < n; ++i)
        for (int b = 0; b < k; ++b)
            planes_ptrs_[i * k + b] = w_all + (static_cast<size_t>(i) * k + b) * bpr;
    softspoken::pack_planes_to_blocks<k>(planes_ptrs_.data(), n, length, bpr, data);

    // LSB convention: clear bit 0 on sender side.
    for (int64_t j = 0; j < length; ++j) data[j] = data[j] & lsb_clear_mask;
}

template <int k>
void SoftSpokenOT<k>::rcot_recv(block* data, int64_t length) {
    if (!setup_done_) setup_recv();
    if (length <= 0) return;

    const int64_t bpr = (length + 127) / 128;
    const uint64_t my_session = session_++;

    const size_t needed = static_cast<size_t>(n) * k * bpr;
    if (planes_scratch_.size() < needed) planes_scratch_.resize(needed);
    if (planes_ptrs_.size() < static_cast<size_t>(n) * k)
        planes_ptrs_.resize(static_cast<size_t>(n) * k);
    block* v_all = planes_scratch_.data();

    std::vector<block> u_canonical(bpr);
    std::vector<block> u_temp(bpr);
    std::vector<block> d_buf(bpr);

    for (int i = 0; i < n; ++i) {
        block* v_planes_i = v_all + static_cast<size_t>(i) * k * bpr;
        block* u_target = (i == 0) ? u_canonical.data() : u_temp.data();
        softspoken::sfvole_sender_compute<k>(
            &leaves_send_[i * Q], my_session, length, u_target, v_planes_i);
        if (i >= 1) {
            for (int64_t bb = 0; bb < bpr; ++bb)
                d_buf[bb] = u_canonical[bb] ^ u_temp[bb];
            this->io->send_block(d_buf.data(), bpr);
        }
    }
    this->io->flush();

    for (int i = 0; i < n; ++i)
        for (int bp = 0; bp < k; ++bp)
            planes_ptrs_[i * k + bp] = v_all + (static_cast<size_t>(i) * k + bp) * bpr;
    softspoken::pack_planes_to_blocks<k>(planes_ptrs_.data(), n, length, bpr, data);

    // LSB convention: clear bit 0 and OR in the receiver's intrinsic
    // choice bit (= u_canonical[j]). With LSB(Δ)=1 the COT relation
    // K ⊕ M = b·Δ holds at the bit level (lower) and at the upper
    // bits (Conv pack already preserves it).
    const uint8_t* u_bytes = reinterpret_cast<const uint8_t*>(u_canonical.data());
    for (int64_t j = 0; j < length; ++j) {
        const uint64_t u_bit = (u_bytes[j >> 3] >> (j & 7)) & 1u;
        data[j] = (data[j] & lsb_clear_mask) ^ (u_bit ? lsb_only_mask : zero_block);
    }
}

template class SoftSpokenOT<2>;
template class SoftSpokenOT<4>;
template class SoftSpokenOT<8>;

} // namespace emp
