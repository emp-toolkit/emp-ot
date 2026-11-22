#ifndef EMP_OT_BMM_H__
#define EMP_OT_BMM_H__

#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"

namespace emp {

/*
 * Badrinarayanan-Masny-Mukherjee (BMM) base OT, instantiated with ML-KEM's
 * Module-LWE PKE at any of FIPS 203's three parameter sets: BMM_T<512>
 * (= BMM, NIST category 1), BMM_T<768> (= BMM768, category 3) and
 * BMM_T<1024> (= BMM1024, category 5).
 * [REF] Badrinarayanan, Masny, Mukherjee. "Efficient and Tight Oblivious
 *       Transfer from PKE with Tight Multi-User Security."
 *       https://eprint.iacr.org/2022/415  (Protocol 2 / Fig. 2)
 *       ML-KEM (FIPS 203).
 *
 * A 2-message, UC-secure 1-out-of-2 OT in the (programmable) random oracle
 * model from any PKE with pseudorandom public keys. The receiver freely
 * chooses one public key while the second is fixed by the random oracle via
 * a "correlation breaker", which is what lets the reduction be tight (no
 * guess-the-query rewinding, unlike Masny-Rindal).
 *
 * Setup. For every OT index i, both parties independently derive a matrix
 * seed rho_i from (`sid`, i) via SHAKE-256 (public coins) and expand the
 * public matrix Â_i in R_q^{KxK} from it, as ML-KEM expands Â from a public
 * key's rho. The PKE is ML-KEM's IND-CPA core, FIPS 203's K-PKE, run by
 * the vendored mlkem-native (third_party/mlkem-native): pk = t̂ = Â_i·ŝ + ê in
 * the NTT domain (pseudorandom under DMLWE), sk = ŝ; Enc/Dec are K-PKE's,
 * with its ciphertext compression. Ĥ_β maps into the same NTT-domain
 * public-key space. The 128-bit base-OT string is embedded directly in the
 * first half of the PKE's 256-bit message; the second half is zero.
 *
 * Symmetric security parameter λ = 256 (the {0,1}^λ correlation-breaker
 * strings and the H_β outputs): the malicious-receiver argument tolerates a
 * receiver that induces up to q² candidate keys from q random-oracle queries,
 * and λ = 256 keeps the q²/2^λ birthday/guessing terms ≤ 2^{-128} (for
 * q ≈ 2^64). λ governs the symmetric side only — the lattice is the chosen
 * ML-KEM level, and the delivered OT message is a 128-bit block.
 *
 * Random oracles (all bind sid and the instance index i):
 *   - H_β   : R_q^K × {0,1}^λ → {0,1}^λ   (correlation breaker, λ=256)
 *   - Ĥ_β   : {0,1}^λ → R_q^K             (hash to public-key space)
 *
 *   Recv (choice b):
 *     (pk_b=t_b, sk_b=x_b) ← Gen ; ĉ_b, c_b ← {0,1}^λ ;
 *     r := t_b − Ĥ_b(ĉ_b) ;  c_{1−b} := ĉ_b ⊕ H_b(r, c_b) ;
 *     send (r, c_0, c_1).
 *   Send:
 *     ĉ_0 := c_1 ⊕ H_0(r,c_0) ; ĉ_1 := c_0 ⊕ H_1(r,c_1) ;
 *     pk_β := r + Ĥ_β(ĉ_β) ;
 *     ct_β := Enc(pk_β, data_β) ; send (ct_0, ct_1).
 *   Recv:
 *     data[i] := Dec(sk_b, ct_b).
 *
 * Wire bytes per OT. r is a uniform element of R_q^K in the NTT domain,
 * uncompressible; the c_β are λ=256-bit; ct_β = (u_β, v_β) is K-PKE's
 * ciphertext with its compression (du, dv):
 *                 K  (du,dv)   recv → send            send → recv
 *   BMM_T<512>    2  (10,4)     832 B = 768 + 2×32    1536 B = 2 × (640 + 128)
 *   BMM_T<768>    3  (10,4)    1216 B = 1152 + 2×32   2176 B = 2 × (960 + 128)
 *   BMM_T<1024>   4  (11,5)    1600 B = 1536 + 2×32   3136 B = 2 × (1408 + 160)
 *
 * This is a 2-round protocol with no third-flow extraction check (the
 * tightness comes from the correlation breaker, not from a challenge), so
 * it is a plain `OT`: supports_deferred_check() stays false and an OT
 * extension drives it through the blocking base_ot->send/recv path.
 */
template <int Level>
class BMM_T : public OT {
    static_assert(Level == 512 || Level == 768 || Level == 1024,
                  "BMM_T: the ML-KEM parameter set is 512, 768 or 1024");
public:
    // 2-message UC OT: malicious-secure under DMLWE (pseudorandom ML-KEM
    // public keys) in the random-oracle model.
    bool is_malicious_secure() const override { return true; }

    // sid is the inherited OT::sid: the one set via OT::set_sid before first
    // use, else the channel's next session id, taken at first use (ot.h).
    // Together with the OT index, it seeds the per-OT matrix expansion and the
    // H/Ĥ oracles. io is the inherited OT::io (set in the ctor).
    explicit BMM_T(IOChannel* io_);
    ~BMM_T() override = default;

    void send(const block* data0, const block* data1, int64_t length) override;
    void recv(block* data, const bool* b, int64_t length) override;
};

// The three levels are compiled into libemp-ot (bmm.cpp).
extern template class BMM_T<512>;
extern template class BMM_T<768>;
extern template class BMM_T<1024>;

using BMM     = BMM_T<512>;
using BMM768  = BMM_T<768>;
using BMM1024 = BMM_T<1024>;

}  // namespace emp

#endif  // EMP_OT_BMM_H__
