#ifndef EMP_OT_BMM_H__
#define EMP_OT_BMM_H__

#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"

namespace emp {

/*
 * Badrinarayanan-Masny-Mukherjee (BMM) base OT, instantiated with
 * Kyber's / ML-KEM-512 Module-LWE PKE.
 * [REF] Badrinarayanan, Masny, Mukherjee. "Efficient and Tight Oblivious
 *       Transfer from PKE with Tight Multi-User Security."
 *       https://eprint.iacr.org/2022/415  (Protocol 2 / Fig. 2)
 *       Kyber / ML-KEM-512 (FIPS 203).
 *
 * A 2-message, UC-secure 1-out-of-2 OT in the (programmable) random oracle
 * model from any PKE with pseudorandom public keys. The receiver freely
 * chooses one public key while the second is fixed by the random oracle via
 * a "correlation breaker", which is what lets the reduction be tight (no
 * guess-the-query rewinding, unlike Masny-Rindal).
 *
 * Setup. Both parties derive the shared matrix A in R_q^{KxK} from the
 * 16-byte session id `sid` via SHAKE-256 (a public-coin CRS). The PKE is
 * Regev/Kyber: pk = t = A·x + e in R_q^K (pseudorandom under DMLWE),
 * sk = x; Enc/Dec are Kyber's IND-CPA core (with ciphertext compression).
 * The OT-string space is the PKE message; for a base OT we encrypt a random
 * 256-bit μ and use K = H(sid,i,β,μ) as the pad (c = K ⊕ data, KEM-style).
 *
 * Symmetric security parameter λ = 256 (the {0,1}^λ correlation-breaker
 * strings and the H_β outputs): the malicious-receiver argument tolerates a
 * receiver that induces up to q² candidate keys from q random-oracle queries,
 * and λ = 256 keeps the q²/2^λ birthday/guessing terms ≤ 2^{-128} (for
 * q ≈ 2^64). λ governs the symmetric side only — the lattice stays at
 * ML-KEM-512, and the delivered OT message is a 128-bit block.
 *
 * Random oracles (all bind sid and the instance index i):
 *   - H_β   : R_q^K × {0,1}^λ → {0,1}^λ   (correlation breaker, λ=256)
 *   - Ĥ_β   : {0,1}^λ → R_q^K             (hash to public-key space)
 *   - out-key H : (μ) → {0,1}^128         (the delivered block pad)
 *
 *   Recv (choice b):
 *     (pk_b=t_b, sk_b=x_b) ← Gen ; ĉ_b, c_b ← {0,1}^λ ;
 *     r := t_b − Ĥ_b(ĉ_b) ;  c_{1−b} := ĉ_b ⊕ H_b(r, c_b) ;
 *     send (r, c_0, c_1).
 *   Send:
 *     ĉ_0 := c_1 ⊕ H_0(r,c_0) ; ĉ_1 := c_0 ⊕ H_1(r,c_1) ;
 *     pk_β := r + Ĥ_β(ĉ_β) ;
 *     ct_β := Enc(pk_β, μ_β) ; mask_β := H(sid,i,β,μ_β) ⊕ data_β ;
 *     send (ct_0, mask_0, ct_1, mask_1).
 *   Recv:
 *     μ_b := Dec(sk_b, ct_b) ; data[i] := H(sid,i,b,μ_b) ⊕ mask_b.
 *
 * Wire bytes per OT (Kyber IND-CPA compression du=10, dv=4 at K=2; r is
 * a uniform R_q^K element, uncompressible; c_β are λ=256-bit):
 *   recv → send  :  832 B  =  768 B (r)  +  2 × 32 B (c_β)
 *   send → recv  : 1568 B  =  2 × (640 B u_β + 128 B v_β + 16 B mask_β)
 *
 * This is a 2-round protocol with no third-flow extraction check (the
 * tightness comes from the correlation breaker, not from a challenge), so
 * it is a plain `OT`: supports_deferred_check() stays false and an OT
 * extension drives it through the blocking base_ot->send/recv path.
 */
class BMM : public OT {
public:
    // 2-message UC OT: malicious-secure under DMLWE (pseudorandom Kyber
    // public keys) in the random-oracle model.
    bool is_malicious_secure() const override { return true; }

    // sid is the inherited OT::sid (default zero_block); set via OT::set_sid
    // before first use. It seeds the CRS expansion, the H/Ĥ oracles, and the
    // output-key derivation. io is the inherited OT::io (set in the ctor).
    explicit BMM(IOChannel* io_);
    ~BMM() override = default;

    void send(const block* data0, const block* data1, int64_t length) override;
    void recv(block* data, const bool* b, int64_t length) override;
};

}  // namespace emp

#endif  // EMP_OT_BMM_H__
