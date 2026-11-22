#include "emp-ot/base_ot/bmm.h"
#include "emp-ot/base_ot/mlkem/mlkem.h"

// The PKE underlying the BMM OT is ML-KEM's IND-CPA core, FIPS 203's K-PKE,
// at the chosen parameter set, run by the vendored mlkem-native (mlkem.h):
//   Gen : t̂ = Â·ŝ + ê, sk = ŝ        (s, e ← CBD_eta1; Â from the seed rho)
//   Enc : K-PKE.Encrypt((t̂, rho), m)  (u = A^T·y + e1, v = t^T·y + e2 + Decompress1(m))
//   Dec : K-PKE.Decrypt(ŝ, (u, v))
// Public keys and the Ĥ oracle live in the NTT domain, as t̂ does in an
// ML-KEM public key. A 128-bit OT message occupies the first 16 bytes of the
// 32-byte plaintext; the remaining 16 bytes are zero. There is no KEM–DEM
// wrapper.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>

namespace emp {

namespace {

// One ML-KEM level's K-PKE sizes and operations (mlkem.h).
template <int Level> struct Mlkem;
#define EMP_BMM_MLKEM_LEVEL(N)                                                 \
    template <> struct Mlkem<N> {                                              \
        static constexpr int kPolyVecBytes = EMP_MLKEM##N##_POLYVECBYTES;      \
        static constexpr int kPkBytes      = EMP_MLKEM##N##_PKBYTES;           \
        static constexpr int kSkBytes      = EMP_MLKEM##N##_SKBYTES;           \
        static constexpr int kCtBytes      = EMP_MLKEM##N##_CTBYTES;           \
        static constexpr auto receiver_key = &emp_mlkem##N##_bmm_receiver_key; \
        static constexpr auto sender_keys  = &emp_mlkem##N##_bmm_sender_keys;  \
        static constexpr auto encrypt      = &emp_mlkem##N##_encrypt;          \
        static constexpr auto decrypt      = &emp_mlkem##N##_decrypt;          \
    };
EMP_BMM_MLKEM_LEVEL(512)
EMP_BMM_MLKEM_LEVEL(768)
EMP_BMM_MLKEM_LEVEL(1024)
#undef EMP_BMM_MLKEM_LEVEL

constexpr int kSymBytes = EMP_MLKEM_SYMBYTES;  // 32: seeds, coins
constexpr int kMsgBytes = EMP_MLKEM_MSGBYTES;  // 32: plaintext

// Symmetric security parameter λ = 256 bits. The correlation-breaker strings
// c_0, c_1, ĉ_β and the H_β oracle outputs live in {0,1}^λ; with λ=256 the
// multi-user birthday/guessing terms q²/2^λ stay ≤ 2^{-128} against a malicious
// receiver making q ≈ 2^64 random-oracle queries (the q² candidate keys it can
// induce is what the malicious-receiver proof must rule out). λ is the SYMMETRIC
// parameter only — the lattice is the chosen ML-KEM level, and the delivered OT
// message is a 128-bit `block` (the base-OT → 128-bit-extension contract).
constexpr int kLambdaBytes = 32;            // λ = 256 bits

// 256-bit field for the correlation breaker.
struct lam_t { uint8_t v[kLambdaBytes]; };
inline lam_t lam_xor(const lam_t& a, const lam_t& b) {
    lam_t r;
    for (int i = 0; i < kLambdaBytes; ++i) r.v[i] = a.v[i] ^ b.v[i];
    return r;
}

// Per-OT wire sizes.
//   recv → send : r (a uniform element of R_q^K, NTT domain) + c_0 + c_1.
//   send → recv : one K-PKE ciphertext per branch.
template <int Level> struct Wire {
    static constexpr int kRecvBytesPerOT     = Mlkem<Level>::kPolyVecBytes + 2 * kLambdaBytes;
    static constexpr int kSendBytesPerBranch = Mlkem<Level>::kCtBytes;
    static constexpr int kSendBytesPerOT     = 2 * kSendBytesPerBranch;
};

// Both parties stream: each sends an OT's message as soon as it has computed
// it, so the sender works on OT i while the receiver computes later first
// messages, and the receiver decrypts OT i while the sender works on later
// OTs. Each direction carries the bytes of the batched two-flow protocol in
// the same order; only the timing of one direction against the other moves.
//
// Both parties flush after every kFlushEvery OTs and after their last one.
// The receiver sends OT j's first message only once it has decrypted OT
// j - kWindow. That bounds the unread data in either direction by kWindow
// OTs' messages, so neither party can block on a full transport while the
// other blocks the same way, and it keeps the receiver's secret keys in a
// kWindow-slot ring. kWindow >= 2 * kFlushEvery puts every reply the
// receiver waits for into a sender flush whose inputs the receiver has
// already flushed.
constexpr int64_t kFlushEvery = 8;
constexpr int64_t kWindow     = 32;
static_assert(kWindow >= 2 * kFlushEvery,
              "BMM: the receiver window must span two flush groups");

// The 32-byte matrix seed rho of OT i: both parties expand OT i's public
// matrix Â_i from it, as K-PKE expands Â from the rho of a public key. The
// leading tag separates this use from Ĥ's seeds (tag 0x02).
inline void matrix_seed(block sid, int64_t i, uint8_t out[kSymBytes]) {
    uint8_t in[1 + sizeof(block) + sizeof(uint64_t)];
    in[0] = 0x03;
    std::memcpy(in + 1, &sid, sizeof(block));
    const uint64_t ii = static_cast<uint64_t>(i);
    std::memcpy(in + 1 + sizeof(block), &ii, sizeof(ii));
    emp_mlkem_shake256(out, kSymBytes, in, sizeof(in));
}

// Ĥ_β : {0,1}^λ → R_q^K, the hash into the public-key space, a uniform
// element of R_q^K in the NTT domain. It is sampled (mlkem.h) from this
// seed, a SHAKE-256 digest over (sid, i, β, ĉ). Both parties derive the same
// element for the same inputs, so the r ± Ĥ_β cancellation is exact mod q.
inline void hhat_seed(block sid, int64_t i, int beta, const lam_t& c_hat,
                      uint8_t seed[kSymBytes]) {
    uint8_t in[1 + sizeof(block) + sizeof(uint64_t) + 1 + kLambdaBytes];
    size_t off = 0;
    in[off++] = 0x02;
    std::memcpy(in + off, &sid, sizeof(block));         off += sizeof(block);
    uint64_t ii = (uint64_t)i;
    std::memcpy(in + off, &ii, sizeof(uint64_t));       off += sizeof(uint64_t);
    in[off++] = (uint8_t)beta;
    std::memcpy(in + off, c_hat.v, kLambdaBytes);       off += kLambdaBytes;
    emp_mlkem_shake256(seed, kSymBytes, in, off);
}

// H_β : R_q^K × {0,1}^λ → {0,1}^λ, the correlation-breaker oracle (λ=256-bit
// output). `r_bytes` are r's on-the-wire serialization (r_len bytes), hashed
// verbatim so both parties absorb identical bytes.
inline lam_t h_correlation(block sid, int64_t i, int beta,
                           const uint8_t* r_bytes, size_t r_len, const lam_t& c) {
    lam_t out;
    RO("emp-ot:bmm:cb", sid)
        .absorb((uint64_t)i)
        .absorb((uint64_t)beta)
        .absorb(r_bytes, r_len)
        .absorb(c.v, kLambdaBytes)
        .squeeze_digest(out.v);
    return out;
}

}  // anonymous namespace

template <int Level>
BMM_T<Level>::BMM_T(IOChannel* io_) { this->io = io_; }

// ----- Receiver (R in the paper). Round 1 send, Round 2 recv + decrypt. -----
template <int Level>
void BMM_T<Level>::recv(block* data, const bool* b, int64_t length) {
    using M = Mlkem<Level>;
    using W = Wire<Level>;
    expect_ot_args(length, data, b,
                   "BMM::recv: invalid length or null buffer");
    fix_sid_();
    // Per-OT payloads are wider than a block; kSendBytesPerOT is the larger
    // element size, so this bound keeps both directions' byte counts in range.
    expecting(length <= std::numeric_limits<int64_t>::max() / W::kSendBytesPerOT,
              "BMM::recv: payload byte count overflow");
    if (length == 0) return;
    const int64_t window = std::min(kWindow, length);

    // The secret key ŝ of each OT whose reply is outstanding; OT i uses slot
    // i % window.
    struct sk_t { uint8_t v[M::kSkBytes]; };
    default_init_vector<sk_t> sk(static_cast<size_t>(window));

    // Round 2 (S→R): (ct_0, ct_1) for OT i. Decrypt branch b.
    auto decrypt = [&](int64_t i) {
        const int bb = b[i] ? 1 : 0;
        uint8_t in[W::kSendBytesPerOT];
        io->recv_data(in, W::kSendBytesPerOT);
        uint8_t m_b[kMsgBytes];
        expecting(M::decrypt(m_b, in + (size_t)bb * W::kSendBytesPerBranch,
                             sk[(size_t)(i % window)].v) == 0,
                  "BMM::recv: decryption failed");
        std::memcpy(&data[i], m_b, sizeof(block));
    };

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        const int bb = b[i] ? 1 : 0;

        uint8_t rho[kSymBytes];
        matrix_seed(sid.value(), i, rho);

        // Gen's noise coins, then ĉ_b, c_b ← {0,1}^λ.
        uint8_t noise_seed[kSymBytes];
        prg.random_data_unaligned(noise_seed, kSymBytes);
        lam_t c_hat_b, c_b;
        prg.random_data_unaligned(c_hat_b.v, kLambdaBytes);
        prg.random_data_unaligned(c_b.v,     kLambdaBytes);

        // (t̂, ŝ) ← Gen ; r = t̂ − Ĥ_b(ĉ_b).
        uint8_t h_seed[kSymBytes];
        hhat_seed(sid.value(), i, bb, c_hat_b, h_seed);
        uint8_t out[W::kRecvBytesPerOT];
        M::receiver_key(out, sk[(size_t)(i % window)].v, rho, noise_seed, h_seed);

        // c_{1−b} = ĉ_b ⊕ H_b(r, c_b). Round 1 (R→S): OT i's (r, c_0, c_1).
        const lam_t h        = h_correlation(sid.value(), i, bb, out, M::kPolyVecBytes, c_b);
        const lam_t c_other  = lam_xor(c_hat_b, h);    // c_{1−b}
        const lam_t c0       = (bb == 0) ? c_b : c_other;
        const lam_t c1       = (bb == 0) ? c_other : c_b;
        std::memcpy(out + M::kPolyVecBytes,                c0.v, kLambdaBytes);
        std::memcpy(out + M::kPolyVecBytes + kLambdaBytes, c1.v, kLambdaBytes);
        io->send_data(out, W::kRecvBytesPerOT);
        if ((i + 1) % kFlushEvery == 0 || i + 1 == length) io->flush();

        // OT i + 1's first message waits for this decryption (kWindow).
        if (i + 1 >= window) decrypt(i + 1 - window);
    }
    // The last window - 1 replies.
    for (int64_t i = length - window + 1; i < length; ++i) decrypt(i);
}

// ----- Sender (S in the paper). Round 1 recv, Round 2 send. -----
template <int Level>
void BMM_T<Level>::send(const block* data0, const block* data1, int64_t length) {
    using M = Mlkem<Level>;
    using W = Wire<Level>;
    expect_ot_args(length, data0, data1,
                   "BMM::send: invalid length or null buffer");
    fix_sid_();
    // Per-OT payloads are wider than a block; kSendBytesPerOT is the larger
    // element size, so this bound keeps both directions' byte counts in range.
    expecting(length <= std::numeric_limits<int64_t>::max() / W::kSendBytesPerOT,
              "BMM::send: payload byte count overflow");
    if (length == 0) return;

    // One OT's Round 1 payload (r, c_0, c_1) and Round 2 reply (ct_0, ct_1).
    uint8_t in[W::kRecvBytesPerOT];
    uint8_t reply[W::kSendBytesPerOT];

    PRG prg;

    for (int64_t i = 0; i < length; ++i) {
        uint8_t rho[kSymBytes];
        matrix_seed(sid.value(), i, rho);

        // Round 1 (R→S): OT i's (r, c_0, c_1).
        io->recv_data(in, W::kRecvBytesPerOT);
        const uint8_t* r_bytes = in;
        lam_t c0, c1;
        std::memcpy(c0.v, in + M::kPolyVecBytes,                kLambdaBytes);
        std::memcpy(c1.v, in + M::kPolyVecBytes + kLambdaBytes, kLambdaBytes);

        // ĉ_0 = c_1 ⊕ H_0(r,c_0) ; ĉ_1 = c_0 ⊕ H_1(r,c_1).
        const lam_t c_hat[2] = {
            lam_xor(c1, h_correlation(sid.value(), i, 0, r_bytes, M::kPolyVecBytes, c0)),
            lam_xor(c0, h_correlation(sid.value(), i, 1, r_bytes, M::kPolyVecBytes, c1))
        };

        // pk_β = (r + Ĥ_β(ĉ_β), rho). r must be the canonical encoding of an
        // element of R_q^K: BMM hashes it and adds to it, so its wire
        // representation has to be unique for the random-oracle proof to use
        // the same domain as the implementation.
        uint8_t h_seed[2][kSymBytes];
        hhat_seed(sid.value(), i, 0, c_hat[0], h_seed[0]);
        hhat_seed(sid.value(), i, 1, c_hat[1], h_seed[1]);
        uint8_t pk[2][M::kPkBytes];
        expecting(M::sender_keys(pk[0], pk[1], r_bytes, rho, h_seed[0], h_seed[1]) == 0,
                  "BMM::send: noncanonical r encoding");

        for (int beta = 0; beta < 2; ++beta) {
            // Directly embed the 128-bit OT message in K-PKE's 256-bit
            // plaintext space. IND-CPA permits this fixed zero padding.
            uint8_t m[kMsgBytes] = {};
            const block& message = (beta == 0) ? data0[i] : data1[i];
            std::memcpy(m, &message, sizeof(block));
            uint8_t coins[kSymBytes];
            prg.random_data_unaligned(coins, kSymBytes);
            expecting(M::encrypt(reply + (size_t)beta * W::kSendBytesPerBranch,
                                 m, pk[beta], coins) == 0,
                      "BMM::send: encryption failed");
        }

        io->send_data(reply, W::kSendBytesPerOT);
        if ((i + 1) % kFlushEvery == 0 || i + 1 == length) io->flush();
    }
}

template class BMM_T<512>;
template class BMM_T<768>;
template class BMM_T<1024>;

}  // namespace emp
