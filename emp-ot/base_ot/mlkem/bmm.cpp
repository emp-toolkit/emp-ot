#include "emp-ot/base_ot/bmm.h"
#include "emp-ot/base_ot/mlkem/params.hpp"
#include "emp-ot/base_ot/mlkem/crs.hpp"

// The Regev/Kyber PKE underlying the BMM OT reuses Kyber's IND-CPA core:
//   Gen : pk = t = A·x + e,  sk = x        (x,e ← CBD_eta1)
//   Enc : u = A^T·ρ + e1, v = t^T·ρ + e2 + Encode(m)   (ρ←eta1, e1,e2←eta2)
//   Dec : m = Decode(v − x^T·u)
// "Encode"/"Decode" are Kyber's poly_frommsg / poly_tomsg (32 B ↔ R_q with
// the bit_i × ⌊(q+1)/2⌋ embedding). A 128-bit OT message occupies the first
// 16 bytes of m; the remaining 16 bytes are zero. There is no KEM–DEM wrapper.

#include <cstdint>
#include <cstring>
#include <limits>

namespace emp {

using namespace mlkem;

namespace {

// Symmetric security parameter λ = 256 bits. The correlation-breaker strings
// c_0, c_1, ĉ_β and the H_β oracle outputs live in {0,1}^λ; with λ=256 the
// multi-user birthday/guessing terms q²/2^λ stay ≤ 2^{-128} against a malicious
// receiver making q ≈ 2^64 random-oracle queries (the q² candidate keys it can
// induce is what the malicious-receiver proof must rule out). λ is the SYMMETRIC
// parameter only — the lattice stays at ML-KEM-512, and the delivered OT message
// is a 128-bit `block` (the base-OT → 128-bit-extension contract).
constexpr int kLambdaBytes = 32;            // λ = 256 bits

// 256-bit field for the correlation breaker.
struct lam_t { uint8_t v[kLambdaBytes]; };
inline lam_t lam_xor(const lam_t& a, const lam_t& b) {
    lam_t r;
    for (int i = 0; i < kLambdaBytes; ++i) r.v[i] = a.v[i] ^ b.v[i];
    return r;
}

// Per-OT wire sizes.
//   recv → send : r (uncompressed uniform R_q^K) + c_0 + c_1 (λ-bit each).
//   send → recv : per branch (compressed u_β, compressed v_β).
constexpr int kRecvBytesPerOT     = kPolyVecBytes + 2 * kLambdaBytes; // 832
constexpr int kSendBytesPerBranch = kPolyVecCompBytes + kPolyCompBytes; // 768
constexpr int kSendBytesPerOT     = 2 * kSendBytesPerBranch; // 1536

// Derive an independent 32-byte public matrix seed for OT i. The leading tag
// gives this use its own domain even before crs_expand_matrix applies its 0x01
// sub-seed tag.
inline void sid_index_to_matrix_seed(block sid, int64_t i,
                                     uint8_t out[kSymBytes]) {
    uint8_t in[1 + sizeof(block) + sizeof(uint64_t)];
    in[0] = 0x03;
    std::memcpy(in + 1, &sid, sizeof(block));
    const uint64_t ii = static_cast<uint64_t>(i);
    std::memcpy(in + 1 + sizeof(block), &ii, sizeof(ii));
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

// Ĥ_β : {0,1}^λ → R_q^K, the hash into the public-key space. Realized as a
// uniform polyvec rejection-sampled from a SHAKE-256 seed over
// (sid, i, β, ĉ). Coefficient domain, in [0, q). Both parties compute the
// same vector for the same inputs, so the r ± Ĥ_β cancellation is exact mod q.
inline void hash_to_polyvec(polyvec* out, block sid, int64_t i, int beta,
                            const lam_t& c_hat) {
    // Leading 0x02 tag domain-separates Ĥ from the matrix-A CRS expansion
    // (which uses tag 0x01 in crs_expand_matrix) — explicit so the split
    // survives refactors, not just the distinct SHAKE-256 input structure.
    uint8_t in[1 + sizeof(block) + sizeof(uint64_t) + 1 + kLambdaBytes];
    size_t off = 0;
    in[off++] = 0x02;
    std::memcpy(in + off, &sid, sizeof(block));         off += sizeof(block);
    uint64_t ii = (uint64_t)i;
    std::memcpy(in + off, &ii, sizeof(uint64_t));       off += sizeof(uint64_t);
    in[off++] = (uint8_t)beta;
    std::memcpy(in + off, c_hat.v, kLambdaBytes);       off += kLambdaBytes;

    uint8_t seed[kSymBytes];
    shake256(seed, kSymBytes, in, off);
    for (int j = 0; j < kK; ++j)
        crs_detail::poly_uniform_from_seed(&out->vec[j], seed, (uint8_t)j, 0);
}

// H_β : R_q^K × {0,1}^λ → {0,1}^λ, the correlation-breaker oracle (λ=256-bit
// output). `r_bytes` are r's on-the-wire serialization (kPolyVecBytes), hashed
// verbatim so both parties absorb identical bytes.
inline lam_t h_correlation(block sid, int64_t i, int beta,
                           const uint8_t* r_bytes, const lam_t& c) {
    lam_t out;
    RO("emp-ot:bmm:cb", sid)
        .absorb((uint64_t)i)
        .absorb((uint64_t)beta)
        .absorb(r_bytes, kPolyVecBytes)
        .absorb(c.v, kLambdaBytes)
        .squeeze_digest(out.v);
    return out;
}

// Decode r only if its 12-bit coefficients are the canonical representatives
// in [0,q). Kyber's polyvec_frombytes deliberately accepts all 12-bit values;
// BMM instead hashes and adds an element of R_q^K, whose wire representation
// must be unique for the random-oracle proof to use the same domain as the
// implementation.
inline bool polyvec_frombytes_canonical(polyvec* out, const uint8_t* in) {
    polyvec_frombytes(out, in);
    for (int j = 0; j < kK; ++j) {
        for (int k = 0; k < kN; ++k) {
            if (out->vec[j].coeffs[k] < 0 || out->vec[j].coeffs[k] >= kQ)
                return false;
        }
    }
    return true;
}

}  // anonymous namespace

BMM::BMM(IOChannel* io_) { this->io = io_; }

// ----- Receiver (R in the paper). Round 1 send, Round 2 recv + decrypt. -----
void BMM::recv(block* data, const bool* b, int64_t length) {
    expect_ot_args(length, data, b,
                   "BMM::recv: invalid length or null buffer");
    // Per-OT payloads are wider than a block; kSendBytesPerOT is the larger
    // element size, so this bound covers both byte-count products below.
    expecting(length <= std::numeric_limits<int64_t>::max() / kSendBytesPerOT,
              "BMM::recv: payload byte count overflow");
    const int64_t recv_bytes = length * kRecvBytesPerOT;
    const int64_t send_bytes = length * kSendBytesPerOT;
    if (length == 0) return;

    // Per-OT public matrix A_i, in NTT domain when used for t = A_i·x.
    polyvec A[kK];

    // Per-OT secret x (NTT domain), reused at decryption.
    default_init_vector<polyvec> x_ntt(static_cast<size_t>(length));

    // Round 1 payload: (r, c_0, c_1) per OT.
    default_init_vector<uint8_t> send_buf(static_cast<size_t>(recv_bytes));

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        const int bb = b[i] ? 1 : 0;

        uint8_t matrix_seed[kSymBytes];
        sid_index_to_matrix_seed(sid.value(), i, matrix_seed);
        crs_expand_matrix(A, matrix_seed, /*transposed=*/false);
        for (int j = 0; j < kK; ++j) polyvec_ntt(&A[j]);

        // Gen: x, e ← eta1 ; pk = t = A_i·x + e (coefficient domain).
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

        // ĉ_b, c_b ← {0,1}^λ ; r = t − Ĥ_b(ĉ_b) ; c_{1−b} = ĉ_b ⊕ H_b(r, c_b).
        lam_t c_hat_b, c_b;
        prg.random_data_unaligned(c_hat_b.v, kLambdaBytes);
        prg.random_data_unaligned(c_b.v,     kLambdaBytes);

        polyvec Hhat;
        hash_to_polyvec(&Hhat, sid.value(), i, bb, c_hat_b);
        polyvec r;
        for (int j = 0; j < kK; ++j)
            poly_sub(&r.vec[j], &t.vec[j], &Hhat.vec[j]);
        polyvec_reduce(&r);

        uint8_t* out = send_buf.data() + (size_t)i * kRecvBytesPerOT;
        polyvec_tobytes(out, &r);

        const lam_t h        = h_correlation(sid.value(), i, bb, out, c_b);
        const lam_t c_other  = lam_xor(c_hat_b, h);    // c_{1−b}
        const lam_t c0       = (bb == 0) ? c_b : c_other;
        const lam_t c1       = (bb == 0) ? c_other : c_b;
        std::memcpy(out + kPolyVecBytes,                c0.v, kLambdaBytes);
        std::memcpy(out + kPolyVecBytes + kLambdaBytes, c1.v, kLambdaBytes);
    }

    io->send_data(send_buf.data(), recv_bytes);
    io->flush();

    // Round 2 (S→R): (ct_0, ct_1) per OT. Decrypt branch b.
    default_init_vector<uint8_t> recv_buf(static_cast<size_t>(send_bytes));
    io->recv_data(recv_buf.data(), send_bytes);

    for (int64_t i = 0; i < length; ++i) {
        const int bb = b[i] ? 1 : 0;
        const uint8_t* branch = recv_buf.data()
                              + (size_t)i * kSendBytesPerOT
                              + (size_t)bb * kSendBytesPerBranch;

        polyvec u;
        polyvec_decompress(&u, branch);
        poly v;
        poly_decompress(&v, branch + kPolyVecCompBytes);

        polyvec_ntt(&u);
        poly inner;
        polyvec_basemul_acc_montgomery(&inner, &x_ntt[i], &u);
        poly_invntt_tomont(&inner);
        poly_sub(&v, &v, &inner);
        poly_reduce(&v);

        uint8_t m_b[kSymBytes];
        poly_tomsg(m_b, &v);
        std::memcpy(&data[i], m_b, sizeof(block));
    }
}

// ----- Sender (S in the paper). Round 1 recv, Round 2 send. -----
void BMM::send(const block* data0, const block* data1, int64_t length) {
    expect_ot_args(length, data0, data1,
                   "BMM::send: invalid length or null buffer");
    // Per-OT payloads are wider than a block; kSendBytesPerOT is the larger
    // element size, so this bound covers both byte-count products below.
    expecting(length <= std::numeric_limits<int64_t>::max() / kSendBytesPerOT,
              "BMM::send: payload byte count overflow");
    const int64_t recv_bytes = length * kRecvBytesPerOT;
    const int64_t send_bytes = length * kSendBytesPerOT;
    if (length == 0) return;

    // Per-OT public matrix A_i^T, in NTT domain when used for u = A_i^T·ρ.
    polyvec AT[kK];

    // Round 1 (R→S): pull the (r, c_0, c_1) batch.
    default_init_vector<uint8_t> recv_buf(static_cast<size_t>(recv_bytes));
    io->recv_data(recv_buf.data(), recv_bytes);

    default_init_vector<uint8_t> send_buf(static_cast<size_t>(send_bytes));

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        uint8_t matrix_seed[kSymBytes];
        sid_index_to_matrix_seed(sid.value(), i, matrix_seed);
        crs_expand_matrix(AT, matrix_seed, /*transposed=*/true);
        for (int j = 0; j < kK; ++j) polyvec_ntt(&AT[j]);

        const uint8_t* in      = recv_buf.data() + (size_t)i * kRecvBytesPerOT;
        const uint8_t* r_bytes = in;
        lam_t c0, c1;
        std::memcpy(c0.v, in + kPolyVecBytes,                kLambdaBytes);
        std::memcpy(c1.v, in + kPolyVecBytes + kLambdaBytes, kLambdaBytes);

        polyvec r;
        expecting(polyvec_frombytes_canonical(&r, r_bytes),
                  "BMM::send: noncanonical r encoding");

        // ĉ_0 = c_1 ⊕ H_0(r,c_0) ; ĉ_1 = c_0 ⊕ H_1(r,c_1).
        const lam_t c_hat[2] = {
            lam_xor(c1, h_correlation(sid.value(), i, 0, r_bytes, c0)),
            lam_xor(c0, h_correlation(sid.value(), i, 1, r_bytes, c1))
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

            // Directly embed the 128-bit OT message in Kyber's 256-bit
            // plaintext space. IND-CPA permits this fixed zero padding.
            uint8_t m[kSymBytes] = {};
            const block& message = (beta == 0) ? data0[i] : data1[i];
            std::memcpy(m, &message, sizeof(block));
            uint8_t noise_seed[kSymBytes];
            prg.random_data_unaligned(noise_seed, kSymBytes);

            polyvec rho, err1;
            poly err2;
            sample_polyvec_eta1(&rho,  noise_seed, /*base=*/0);     // ρ  ~ eta1
            sample_polyvec_eta2(&err1, noise_seed, /*base=*/kK);    // e1 ~ eta2
            poly_getnoise_eta2(&err2, noise_seed, (uint8_t)(2 * kK)); // e2 ~ eta2
            polyvec_ntt(&rho);

            // u_β = A_i^T·ρ + e1.
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
        }
    }

    io->send_data(send_buf.data(), send_bytes);
    io->flush();
}

}  // namespace emp
