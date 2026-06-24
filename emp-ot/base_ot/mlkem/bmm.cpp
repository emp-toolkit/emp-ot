#include "emp-ot/base_ot/bmm.h"
#include "emp-ot/base_ot/mlkem/params.hpp"
#include "emp-ot/base_ot/mlkem/crs.hpp"

// The Regev/Kyber PKE underlying the BMM OT reuses Kyber's IND-CPA core:
//   Gen : pk = t = A·x + e,  sk = x        (x,e ← CBD_eta1)
//   Enc : u = A^T·ρ + e1, v = t^T·ρ + e2 + Encode(μ)   (ρ←eta1, e1,e2←eta2)
//   Dec : μ = Decode(v − x^T·u)
// "Encode"/"Decode" are Kyber's poly_frommsg / poly_tomsg (32 B ↔ R_q with
// the bit_i × ⌊(q+1)/2⌋ embedding). All called directly — no wrapper layer.

#include <cstdint>
#include <cstring>

namespace emp {

using namespace mlkem;

namespace {

// Per-OT wire sizes.
//   recv → send : r (uncompressed uniform R_q^K) + c_0 + c_1.
//   send → recv : per branch (compressed u_β, compressed v_β, mask_β).
constexpr int kRecvBytesPerOT     = kPolyVecBytes + 2 * (int)sizeof(block);   // 800
constexpr int kSendBytesPerBranch = kPolyVecCompBytes + kPolyCompBytes + (int)sizeof(block); // 784
constexpr int kSendBytesPerOT     = 2 * kSendBytesPerBranch;                  // 1568

// Expand the 16-byte sid into a 32-byte session seed via SHAKE-256;
// Kyber's CRS expanders consume 32 bytes.
inline void sid_to_session_seed(block sid, uint8_t out[kSymBytes]) {
    uint8_t in[sizeof(block)];
    std::memcpy(in, &sid, sizeof(block));
    shake256(out, kSymBytes, in, sizeof(in));
}

// Sample a polyvec under CBD_eta1 keyed by `seed` with per-component
// nonces `base..base+K-1`. (Kyber's poly_getnoise_eta1 is one
// SHAKE-256 PRF call per polynomial.)
inline void sample_polyvec_eta1(polyvec* p, const uint8_t seed[kSymBytes],
                                uint8_t base) {
    for (int j = 0; j < kK; ++j)
        poly_getnoise_eta1(&p->vec[j], seed, (uint8_t)(base + j));
}

// Same, under CBD_eta2 — used for the encryption errors e1, e2 (ML-KEM-512
// samples these with eta2; only x, e, ρ use eta1).
inline void sample_polyvec_eta2(polyvec* p, const uint8_t seed[kSymBytes],
                                uint8_t base) {
    for (int j = 0; j < kK; ++j)
        poly_getnoise_eta2(&p->vec[j], seed, (uint8_t)(base + j));
}

// Ĥ_β : {0,1}^κ → R_q^K, the hash into the public-key space. Realized as a
// uniform polyvec rejection-sampled from a SHAKE-256 seed over
// (sid, i, β, ĉ). Coefficient domain, in [0, q). Both parties compute the
// same vector for the same inputs, so the r ± Ĥ_β cancellation is exact mod q.
inline void hash_to_polyvec(polyvec* out, block sid, int64_t i, int beta,
                            const block& c_hat) {
    // Leading 0x02 tag domain-separates Ĥ from the matrix-A CRS expansion
    // (which uses tag 0x01 in crs_expand_matrix) — explicit so the split
    // survives refactors, not just the distinct SHAKE-256 input structure.
    uint8_t in[1 + sizeof(block) + sizeof(uint64_t) + 1 + sizeof(block)];
    size_t off = 0;
    in[off++] = 0x02;
    std::memcpy(in + off, &sid, sizeof(block));         off += sizeof(block);
    uint64_t ii = (uint64_t)i;
    std::memcpy(in + off, &ii, sizeof(uint64_t));       off += sizeof(uint64_t);
    in[off++] = (uint8_t)beta;
    std::memcpy(in + off, &c_hat, sizeof(block));       off += sizeof(block);

    uint8_t seed[kSymBytes];
    shake256(seed, kSymBytes, in, off);
    for (int j = 0; j < kK; ++j)
        crs_detail::poly_uniform_from_seed(&out->vec[j], seed, (uint8_t)j, 0);
}

// H_β : R_q^K × {0,1}^κ → {0,1}^κ, the correlation-breaker oracle. `r_bytes`
// are r's on-the-wire serialization (kPolyVecBytes), hashed verbatim so both
// parties absorb identical bytes.
inline block h_correlation(block sid, int64_t i, int beta,
                           const uint8_t* r_bytes, const block& c) {
    return RO("emp-ot:bmm:cb", sid)
               .absorb((uint64_t)i)
               .absorb((uint64_t)beta)
               .absorb(r_bytes, kPolyVecBytes)
               .absorb(c)
               .squeeze_block();
}

// Output pad K = H(sid, i, β, μ) truncated to 128 bits. Per-(i,β) domain
// separation defeats MRR21-style batching attacks.
inline block out_key(block sid, int64_t i, int beta, const uint8_t m[kSymBytes]) {
    return RO("emp-ot:bmm:out-key", sid)
               .absorb((uint64_t)i)
               .absorb((uint64_t)beta)
               .absorb(m, kSymBytes)
               .squeeze_block();
}

}  // anonymous namespace

BMM::BMM(IOChannel* io_) { this->io = io_; }

// ----- Receiver (R in the paper). Round 1 send, Round 2 recv + decrypt. -----
void BMM::recv(block* data, const bool* b, int64_t length) {
    if (length <= 0) return;

    uint8_t session_seed[kSymBytes];
    sid_to_session_seed(sid.value(), session_seed);

    // CRS: A (non-transposed), NTT domain — for t = A·x.
    polyvec A[kK];
    crs_expand_matrix(A, session_seed, /*transposed=*/false);
    for (int j = 0; j < kK; ++j) polyvec_ntt(&A[j]);

    // Per-OT secret x (NTT domain), reused at decryption.
    default_init_vector<polyvec> x_ntt(length);

    // Round 1 payload: (r, c_0, c_1) per OT.
    default_init_vector<uint8_t> send_buf((size_t)length * kRecvBytesPerOT);

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        const int bb = b[i] ? 1 : 0;

        // Gen: x, e ← eta1 ; pk = t = A·x + e (coefficient domain).
        uint8_t noise_seed[kSymBytes];
        prg.random_data_unaligned(noise_seed, kSymBytes);
        polyvec x, e;
        sample_polyvec_eta1(&x, noise_seed, /*base=*/0);
        sample_polyvec_eta1(&e, noise_seed, /*base=*/kK);
        polyvec_ntt(&x);
        x_ntt[i] = x;

        polyvec t;
        for (int j = 0; j < kK; ++j)
            polyvec_basemul_acc_montgomery(&t.vec[j], &A[j], &x);
        polyvec_invntt_tomont(&t);
        polyvec_add(&t, &t, &e);
        polyvec_reduce(&t);

        // ĉ_b, c_b ← {0,1}^κ ; r = t − Ĥ_b(ĉ_b) ; c_{1−b} = ĉ_b ⊕ H_b(r, c_b).
        block c_hat_b, c_b;
        prg.random_block(&c_hat_b, 1);
        prg.random_block(&c_b, 1);

        polyvec Hhat;
        hash_to_polyvec(&Hhat, sid.value(), i, bb, c_hat_b);
        polyvec r;
        for (int j = 0; j < kK; ++j)
            poly_sub(&r.vec[j], &t.vec[j], &Hhat.vec[j]);
        polyvec_reduce(&r);

        uint8_t* out = send_buf.data() + (size_t)i * kRecvBytesPerOT;
        polyvec_tobytes(out, &r);

        const block h        = h_correlation(sid.value(), i, bb, out, c_b);
        const block c_other  = c_hat_b ^ h;            // c_{1−b}
        const block c0       = (bb == 0) ? c_b : c_other;
        const block c1       = (bb == 0) ? c_other : c_b;
        std::memcpy(out + kPolyVecBytes,                  &c0, sizeof(block));
        std::memcpy(out + kPolyVecBytes + sizeof(block),  &c1, sizeof(block));
    }

    io->send_data(send_buf.data(), (size_t)length * kRecvBytesPerOT);
    io->flush();

    // Round 2 (S→R): (ct_0, mask_0, ct_1, mask_1) per OT. Decrypt branch b.
    default_init_vector<uint8_t> recv_buf((size_t)length * kSendBytesPerOT);
    io->recv_data(recv_buf.data(), (size_t)length * kSendBytesPerOT);

    for (int64_t i = 0; i < length; ++i) {
        const int bb = b[i] ? 1 : 0;
        const uint8_t* branch = recv_buf.data()
                              + (size_t)i * kSendBytesPerOT
                              + (size_t)bb * kSendBytesPerBranch;

        polyvec u;
        polyvec_decompress(&u, branch);
        poly v;
        poly_decompress(&v, branch + kPolyVecCompBytes);
        block mask;
        std::memcpy(&mask, branch + kPolyVecCompBytes + kPolyCompBytes, sizeof(block));

        polyvec_ntt(&u);
        poly inner;
        polyvec_basemul_acc_montgomery(&inner, &x_ntt[i], &u);
        poly_invntt_tomont(&inner);
        poly_sub(&v, &v, &inner);
        poly_reduce(&v);

        uint8_t m_b[kSymBytes];
        poly_tomsg(m_b, &v);
        const block K = out_key(sid.value(), i, bb, m_b);
        data[i] = K ^ mask;
    }
}

// ----- Sender (S in the paper). Round 1 recv, Round 2 send. -----
void BMM::send(const block* data0, const block* data1, int64_t length) {
    if (length <= 0) return;

    uint8_t session_seed[kSymBytes];
    sid_to_session_seed(sid.value(), session_seed);

    // CRS: A^T, NTT domain — for u = A^T·ρ.
    polyvec AT[kK];
    crs_expand_matrix(AT, session_seed, /*transposed=*/true);
    for (int j = 0; j < kK; ++j) polyvec_ntt(&AT[j]);

    // Round 1 (R→S): pull the (r, c_0, c_1) batch.
    default_init_vector<uint8_t> recv_buf((size_t)length * kRecvBytesPerOT);
    io->recv_data(recv_buf.data(), (size_t)length * kRecvBytesPerOT);

    default_init_vector<uint8_t> send_buf((size_t)length * kSendBytesPerOT);

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        const uint8_t* in      = recv_buf.data() + (size_t)i * kRecvBytesPerOT;
        const uint8_t* r_bytes = in;
        block c0, c1;
        std::memcpy(&c0, in + kPolyVecBytes,                 sizeof(block));
        std::memcpy(&c1, in + kPolyVecBytes + sizeof(block), sizeof(block));

        polyvec r;
        polyvec_frombytes(&r, r_bytes);   // coefficient domain, [0, q)

        // ĉ_0 = c_1 ⊕ H_0(r,c_0) ; ĉ_1 = c_0 ⊕ H_1(r,c_1).
        const block c_hat[2] = {
            c1 ^ h_correlation(sid.value(), i, 0, r_bytes, c0),
            c0 ^ h_correlation(sid.value(), i, 1, r_bytes, c1)
        };

        uint8_t* out = send_buf.data() + (size_t)i * kSendBytesPerOT;

        for (int beta = 0; beta < 2; ++beta) {
            // pk_β = r + Ĥ_β(ĉ_β), then NTT for the basemuls.
            polyvec Hhat;
            hash_to_polyvec(&Hhat, sid.value(), i, beta, c_hat[beta]);
            polyvec pk;
            polyvec_add(&pk, &r, &Hhat);
            polyvec_reduce(&pk);
            polyvec_ntt(&pk);

            // μ_β (256-bit message) and a noise seed.
            uint8_t m[kSymBytes], noise_seed[kSymBytes];
            prg.random_data_unaligned(m, kSymBytes);
            prg.random_data_unaligned(noise_seed, kSymBytes);

            polyvec rho, err1;
            poly err2;
            sample_polyvec_eta1(&rho,  noise_seed, /*base=*/0);     // ρ  ~ eta1
            sample_polyvec_eta2(&err1, noise_seed, /*base=*/kK);    // e1 ~ eta2
            poly_getnoise_eta2(&err2, noise_seed, (uint8_t)(2 * kK)); // e2 ~ eta2
            polyvec_ntt(&rho);

            // u_β = A^T·ρ + e1.
            polyvec u;
            for (int j = 0; j < kK; ++j)
                polyvec_basemul_acc_montgomery(&u.vec[j], &AT[j], &rho);
            polyvec_invntt_tomont(&u);
            polyvec_add(&u, &u, &err1);
            polyvec_reduce(&u);

            // v_β = pk_β^T·ρ + e2 + Encode(μ_β).
            poly v;
            polyvec_basemul_acc_montgomery(&v, &pk, &rho);
            poly_invntt_tomont(&v);
            poly_add(&v, &v, &err2);
            poly enc;
            poly_frommsg(&enc, m);
            poly_add(&v, &v, &enc);
            poly_reduce(&v);

            polyvec_compress(out, &u);
            out += kPolyVecCompBytes;
            poly_compress(out, &v);
            out += kPolyCompBytes;

            // mask_β = H(sid,i,β,μ_β) ⊕ data_β[i].
            const block K      = out_key(sid.value(), i, beta, m);
            const block masked = K ^ (beta == 0 ? data0[i] : data1[i]);
            std::memcpy(out, &masked, sizeof(block));
            out += sizeof(block);
        }
    }

    io->send_data(send_buf.data(), (size_t)length * kSendBytesPerOT);
    io->flush();
}

}  // namespace emp
