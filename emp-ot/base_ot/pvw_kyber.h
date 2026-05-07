#ifndef EMP_OT_PVW_KYBER_H__
#define EMP_OT_PVW_KYBER_H__

#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"

namespace emp {

/*
 * Peikert-Vaikuntanathan-Waters base OT instantiated with Kyber's
 * Module-LWE primitives (post-quantum analogue of OTPVW '08, which
 * lives in emp-ot/base_ot/pvw.h and uses elliptic-curve groups).
 * [REF] PVW '08, "A Framework for Efficient and Composable Oblivious
 *       Transfer", https://eprint.iacr.org/2007/348.
 *       Kyber / ML-KEM-512 (FIPS 203).
 *
 * Setup. Both parties derive A in R_q^{KxK} and V_0, V_1 in R_q^K from
 * a shared 16-byte session id `sid` via SHAKE-256, with one-byte
 * domain-separation tags. The CRS is sampled uniformly (no DH structure)
 * — "messy mode" PVW: sender-statistically-secure, receiver-secure
 * under DMLWE. No trapdoors, no decryption-mode CRS.
 *
 *   Recv (choice b in {0,1}):
 *     s, e <- CBD_eta1 in R_q^K ; send t = A·s + e + V_b.
 *   Send:
 *     for β in {0,1}:
 *       sample m_β ∈ {0,1}^{256}, ρ_β, err1_β <- CBD_eta1, err2_β <- CBD_eta2;
 *       u_β = A^T·ρ_β + err1_β ;
 *       v_β = (t - V_β)^T·ρ_β + err2_β + Encode(m_β) ;
 *       K_β = H(sid || i || β || m_β)        // 128-bit output key
 *       c_β = K_β ⊕ data_β[i]                // chosen-input XOR mask
 *     send (u_0, v_0, u_1, v_1, c_0, c_1).
 *   Recv:
 *     decode m_b from v_b - s^T·u_b ;  K_b = H(sid || i || b || m_b) ;
 *     output data[i] = K_b ⊕ c_b.
 *
 * The output-hash domain separation (sid || i || β || m_β) defeats the
 * MRR21 batching attack (eprint 2021/682).
 *
 * Wire bytes per OT (Kyber IND-CPA compression on (u_β, v_β); t stays
 * uncompressed since compressing it would add noise on the sender
 * side and require a PVW-specific re-derivation of the bound):
 *   recv → send  :  768 B (t)
 *   send → recv  : 1568 B per OT
 *                  = 2 × (640 B compressed u_β + 128 B compressed v_β
 *                       + 16 B chosen-input mask c_β)
 *
 * Correctness. After receiver computes w = v_b - s^T·u_b, the noise
 * is e^T·ρ_b + err2_b - s^T·err1_b — exactly Kyber's decryption-noise
 * shape (FIPS 203 §5.5; ML-KEM-512 failure rate ≈ 2^{-139} per coeff).
 * Wrong-branch hiding follows from DMLWE on the (V_b - V_β) shift.
 */
class OTPVWKyber : public OT {
public:
    // Messy-mode PVW over Module-LWE: receiver-secure under DMLWE
    // against a malicious sender; sender statistically secure against
    // a malicious receiver. Same security shape as OTPVW (DDH-based)
    // but post-quantum.
    bool is_malicious_secure() const override { return true; }

    // `sid` must be agreed out-of-band by both parties (e.g., via the
    // calling protocol's session counter). Distinct sids yield
    // independent CRSs.
    OTPVWKyber(IOChannel* io_, block sid);
    ~OTPVWKyber() override = default;

    void send(const block* data0, const block* data1, int64_t length) override;
    void recv(block* data, const bool* b, int64_t length) override;

private:
    IOChannel* io;
    block sid_;
};

}  // namespace emp

#endif  // EMP_OT_PVW_KYBER_H__
