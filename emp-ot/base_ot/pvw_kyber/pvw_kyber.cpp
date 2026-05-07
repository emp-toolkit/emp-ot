#include "emp-ot/base_ot/pvw_kyber.h"
#include "emp-ot/base_ot/pvw_kyber/params.hpp"
#include "emp-ot/base_ot/pvw_kyber/crs.hpp"

// PVW's "Encode" / "Decode" map directly to Kyber's poly_frommsg /
// poly_tomsg (32 B ↔ R_q element with bit_i × ⌊(q+1)/2⌋ embedding;
// poly_tomsg rounds each coefficient to the nearest of {0, 1665} with
// boundary at q/4 and 3q/4). Both are constant-time in Kyber's
// reference. We call them directly — no wrapper layer.

#include <cstdint>
#include <cstring>
#include <memory>

namespace emp {

using namespace pvw_kyber;

namespace {

// Per-OT wire sizes. (u_β, v_β) carry Kyber's IND-CPA compression
// (du=10, dv=4 at K=2); receiver's t stays uncompressed (compressing
// it would add noise on the sender side, requiring a PVW-specific
// re-derivation of the bound). Sender writes the two branches back-
// to-back; per branch carries (compressed u_β, compressed v_β, c_β).
constexpr int kRecvBytesPerOT     = kPolyVecBytes;                                                     // t
constexpr int kSendBytesPerBranch = kPolyVecCompBytes + kPolyCompBytes + (int)sizeof(block);
constexpr int kSendBytesPerOT     = 2 * kSendBytesPerBranch;

// Expand the 16-byte sid into a 32-byte session seed via SHAKE-256;
// Kyber's CRS expanders consume 32 bytes.
inline void sid_to_session_seed(block sid, uint8_t out[kSymBytes]) {
    uint8_t in[sizeof(block)];
    std::memcpy(in, &sid, sizeof(block));
    shake256(out, kSymBytes, in, sizeof(in));
}

// Output key K = SHA256(sid || i || β || m_β), truncated to 128 bits.
// Domain separation defeats MRR21 batching attacks.
inline block derive_output_key(block sid, int64_t instance_idx,
                                int beta, const uint8_t m[kSymBytes]) {
    Hash h;
    h.put(&sid, sizeof(sid));
    h.put(&instance_idx, sizeof(instance_idx));
    const uint8_t b_byte = (uint8_t)beta;
    h.put(&b_byte, 1);
    h.put(m, kSymBytes);
    uint8_t dgst[Hash::DIGEST_SIZE];
    h.digest(dgst);
    block K;
    std::memcpy(&K, dgst, sizeof(block));
    return K;
}

// Sample a polyvec under CBD_eta1 keyed by `seed` with per-component
// nonces `base..base+K-1`. (Kyber's poly_getnoise_eta1 is one
// SHAKE-256 PRF call per polynomial.)
inline void sample_polyvec_eta1(polyvec* p, const uint8_t seed[kSymBytes],
                                uint8_t base) {
    for (int j = 0; j < kK; ++j) {
        poly_getnoise_eta1(&p->vec[j], seed, (uint8_t)(base + j));
    }
}

}  // anonymous namespace

OTPVWKyber::OTPVWKyber(IOChannel* io_, block sid) : io(io_), sid_(sid) {}

void OTPVWKyber::send(const block* data0, const block* data1, int64_t length) {
    if (length <= 0) return;

    uint8_t session_seed[kSymBytes];
    sid_to_session_seed(sid_, session_seed);

    // CRS: A^T (sender side) and V_0, V_1, all in NTT domain.
    polyvec AT[kK];
    polyvec V[2];
    crs_expand_matrix(AT, session_seed, /*transposed=*/true);
    crs_expand_v(&V[0], session_seed, 0);
    crs_expand_v(&V[1], session_seed, 1);
    for (int j = 0; j < kK; ++j) polyvec_ntt(&AT[j]);
    polyvec_ntt(&V[0]);
    polyvec_ntt(&V[1]);

    // Pull all of receiver's t's in one batched recv (one round-trip
    // for the entire batch — matches the OTCSW pattern).
    std::unique_ptr<uint8_t[]> recv_t_batch(
        new uint8_t[(size_t)length * kRecvBytesPerOT]);
    io->recv_data(recv_t_batch.get(), (size_t)length * kRecvBytesPerOT);

    // Per-OT sender output: (u_0, v_0, u_1, v_1, c_0, c_1).
    std::unique_ptr<uint8_t[]> send_buf(
        new uint8_t[(size_t)length * kSendBytesPerOT]);

    // PRG keyed from system entropy at construction; seeds per-OT
    // randomness for m_β and the noise terms.
    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        polyvec t;
        polyvec_frombytes(&t, recv_t_batch.get() + (size_t)i * kRecvBytesPerOT);
        polyvec_ntt(&t);

        uint8_t* out_ptr = send_buf.get() + (size_t)i * kSendBytesPerOT;

        for (int beta = 0; beta < 2; ++beta) {
            // Sample m_β (256-bit message) and a noise seed.
            uint8_t m[kSymBytes];
            uint8_t noise_seed[kSymBytes];
            prg.random_data_unaligned(m, kSymBytes);
            prg.random_data_unaligned(noise_seed, kSymBytes);

            polyvec rho, err1;
            poly err2;
            sample_polyvec_eta1(&rho,  noise_seed, /*base=*/0);
            sample_polyvec_eta1(&err1, noise_seed, /*base=*/kK);
            poly_getnoise_eta2(&err2, noise_seed, (uint8_t)(2 * kK));
            polyvec_ntt(&rho);

            // u_β = A^T · ρ (NTT-domain accumulate per row), then invNTT
            // and + err1 (in coefficient domain).
            polyvec u;
            for (int j = 0; j < kK; ++j) {
                polyvec_basemul_acc_montgomery(&u.vec[j], &AT[j], &rho);
            }
            polyvec_invntt_tomont(&u);
            polyvec_add(&u, &u, &err1);
            polyvec_reduce(&u);

            // v_β = (t - V_β)^T · ρ + err2 + Encode(m).
            polyvec t_minus_V;
            for (int j = 0; j < kK; ++j) {
                poly_sub(&t_minus_V.vec[j], &t.vec[j], &V[beta].vec[j]);
            }
            poly v;
            polyvec_basemul_acc_montgomery(&v, &t_minus_V, &rho);
            poly_invntt_tomont(&v);
            poly_add(&v, &v, &err2);
            poly enc;
            poly_frommsg(&enc, m);
            poly_add(&v, &v, &enc);
            poly_reduce(&v);

            // Wire: compress(u_β) || compress(v_β) — Kyber IND-CPA shape.
            polyvec_compress(out_ptr, &u);
            out_ptr += kPolyVecCompBytes;
            poly_compress(out_ptr, &v);
            out_ptr += kPolyCompBytes;

            // Chosen-input mask: c_β = K_β ⊕ data_β[i].
            const block K = derive_output_key(sid_, i, beta, m);
            const block masked = K ^ (beta == 0 ? data0[i] : data1[i]);
            std::memcpy(out_ptr, &masked, sizeof(block));
            out_ptr += sizeof(block);
        }
    }

    io->send_data(send_buf.get(), (size_t)length * kSendBytesPerOT);
}

void OTPVWKyber::recv(block* data, const bool* b, int64_t length) {
    if (length <= 0) return;

    uint8_t session_seed[kSymBytes];
    sid_to_session_seed(sid_, session_seed);

    // CRS: A (receiver side, non-transposed); V_β stay in coefficient
    // domain since the receiver adds V_b in the t = A·s + e + V_b step
    // before sending.
    polyvec A[kK];
    polyvec V[2];
    crs_expand_matrix(A, session_seed, /*transposed=*/false);
    crs_expand_v(&V[0], session_seed, 0);
    crs_expand_v(&V[1], session_seed, 1);
    for (int j = 0; j < kK; ++j) polyvec_ntt(&A[j]);

    // Per-OT receiver state: s in NTT domain (re-used at decryption).
    std::unique_ptr<polyvec[]> s_ntt(new polyvec[length]);

    // First pass: build the t batch.
    std::unique_ptr<uint8_t[]> send_t_batch(
        new uint8_t[(size_t)length * kRecvBytesPerOT]);

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        uint8_t noise_seed[kSymBytes];
        prg.random_data_unaligned(noise_seed, kSymBytes);

        polyvec s, e;
        sample_polyvec_eta1(&s, noise_seed, /*base=*/0);
        sample_polyvec_eta1(&e, noise_seed, /*base=*/kK);
        polyvec_ntt(&s);
        s_ntt[i] = s;

        // t = A · s_ntt (per row), invNTT, + e + V_b.
        polyvec t;
        for (int j = 0; j < kK; ++j) {
            polyvec_basemul_acc_montgomery(&t.vec[j], &A[j], &s);
        }
        polyvec_invntt_tomont(&t);
        polyvec_add(&t, &t, &e);
        polyvec_add(&t, &t, &V[b[i] ? 1 : 0]);
        polyvec_reduce(&t);

        polyvec_tobytes(send_t_batch.get() + (size_t)i * kRecvBytesPerOT, &t);
    }

    io->send_data(send_t_batch.get(), (size_t)length * kRecvBytesPerOT);

    // Second pass: receive (u, v, c) batch and decrypt the chosen
    // branch per OT.
    std::unique_ptr<uint8_t[]> recv_buf(
        new uint8_t[(size_t)length * kSendBytesPerOT]);
    io->recv_data(recv_buf.get(), (size_t)length * kSendBytesPerOT);

    for (int64_t i = 0; i < length; ++i) {
        const int chosen = b[i] ? 1 : 0;
        const uint8_t* branch_ptr = recv_buf.get()
                                  + (size_t)i * kSendBytesPerOT
                                  + (size_t)chosen * kSendBytesPerBranch;

        polyvec u;
        polyvec_decompress(&u, branch_ptr);
        poly v;
        poly_decompress(&v, branch_ptr + kPolyVecCompBytes);
        block c;
        std::memcpy(&c, branch_ptr + kPolyVecCompBytes + kPolyCompBytes,
                    sizeof(block));

        polyvec_ntt(&u);

        poly inner;
        polyvec_basemul_acc_montgomery(&inner, &s_ntt[i], &u);
        poly_invntt_tomont(&inner);

        poly_sub(&v, &v, &inner);
        poly_reduce(&v);

        uint8_t m_b[kSymBytes];
        poly_tomsg(m_b, &v);

        const block K = derive_output_key(sid_, i, chosen, m_b);
        data[i] = K ^ c;
    }
}

}  // namespace emp
