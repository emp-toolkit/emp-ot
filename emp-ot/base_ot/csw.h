#ifndef EMP_CSW_H__
#define EMP_CSW_H__
#include <emp-tool/emp-tool.h>
#include <memory>
#include <vector>
#include "emp-ot/ot.h"
#include "emp-ot/base_ot/csw_base_ot.h"
#include "emp-ot/base_ot/sfrot_check.h"
namespace emp {

/*
 * Canetti-Sarkar-Wang "Blazing Fast OT" — base OT realising π_ot^ℓ
 * instances of F_SFROT.
 * [REF] Canetti, Sarkar, Wang. "Blazing Fast OT for Three-Round UC OT
 *       Extension." (Fig. SFROT_Prot in SFOT.tex)
 *
 * 3-message base OT under CDH in the observable RO model. ℓ batched
 * OTs share a single (seed, T, z) setup; per-OT cost ≈ 1 EC exp/side.
 *
 * Layered as:
 *   Phase A (CO-style key agreement): seed → T = H_1(sid, seed);
 *     B_i = g^{α_i} · T^{b_i}; z = g^r; pads p_{i,b} = H_2(sid, i, ρ_{i,b})
 *     where ρ_{i,0} = B_i^r and ρ_{i,1} = (B_i / T)^r.
 *   Phase B (challenge-prove-response over ℓ-batch): per-OT challenges
 *     χ_i = H_3(sid, p_{i,0}) ⊕ H_3(sid, p_{i,1}); aggregate response
 *     otans = H_4(sid, H_3(sid, p_{1,0}), …, H_3(sid, p_{ℓ,0})); proof
 *     Π = H_3(sid, otans). Receiver recomputes otans' from its p_{i,b_i};
 *     verifies H_3(sid, otans') == Π; sends otans' back; sender accepts
 *     iff otans' == otans. Hash-only analogue of IKNP's chi-fold check.
 *
 * Chosen-input encoding: per-OT ciphertexts c_{i,b} = p_{i,b} ⊕ data_{i,b}
 * ride inside the round-2 payload, so the OT::send / OT::recv API stays
 * at 3 messages (matching the random-OT version).
 *
 * `length` must be ≥ 80 (≈ 2σ for σ = 40); the sender-input extraction
 * argument needs ℓ > 2σ 
 */
class CSW : public CSWBaseOT { public:
	// UC-secure under CDH in the random oracle model.
	bool is_malicious_secure() const override { return true; }

	ECGroup G;

	// sid is the inherited OT::sid (default zero_block); set via OT::set_sid
	// before first use. It is the leading bytes of every RO input below.
	CSW(IOChannel * io_) {this->io = io_;}

private:
	// Per-instance state stashed by *_core for the deferred *_check (the
	// extension calls core in begin() and check at the end of end()). For
	// the standalone send/recv (= core+check back-to-back, inherited from
	// CSWBaseOT) these just bridge the two halves within one call.
	int64_t length_ = 0;
	std::vector<block> p0_, p1_;        // sender pads p_{i,0}, p_{i,1}
	std::vector<block> p_bi_;           // receiver chosen pads p_{i,b_i}
	std::vector<uint8_t> b_copy_;       // receiver choices, copied: the caller's
	                                    // b[] need not outlive the deferred check

	// ===== Random oracles. Each uses a distinct domain string and binds
	// sid; all are independent and session-bound. =====
	//
	// H_1 (to-curve) is called inline at its send/recv sites via RO
	// directly. H_2 (pad) keeps a helper — more call sites, and pad has a
	// multi-field order. The challenge–prove–response oracles (formerly the
	// H_3/H_4 helpers here) now live in the shared sfrot_check.h.
	static constexpr char kDomToCurve[] = "emp-ot:csw-base-ot:to-curve";

	// H_2(sid, i, P) → block. P is a curve point (the DH share ρ).
	block H_pad(int64_t i, Point & P) {
		return RO("emp-ot:csw-base-ot:pad", sid.value())
		           .absorb((uint64_t)i).absorb(P).squeeze_block();
	}

public:
	// ----- Sender side. Plays the OT sender role (S in the paper). -----
	// Messy core only: Round 1 recv + Round 2 core bytes (z, {c}). Stashes
	// p0_/p1_ for the deferred check and does NOT flush — the core bytes stay
	// buffered so an extension can bundle them with its first message.
	void send_core(const block * data0, const block * data1, int64_t length) override {
		assert(length >= 80 &&
		       "CSW: length must be ≥ 80 (paper requires ℓ > 2σ for σ=40)");
		length_ = length;

		// Round 1 (R→S): receive seed, {B_i}.
		block seed;
		io->recv_block(&seed, 1);
		std::vector<Point> B(length);
		io->recv_pt(&G, B.data(), length);

		// Sender params: T = H_1(sid, seed); r ← Z_q; z = g^r.
		// Amortize T^r over the batch: ρ_{i,1} = (B_i/T)^r = B_i^r · (T^r)^{-1}
		// = ρ_{i,0} + (-T_r). One mul/OT instead of two.
		Point T = RO(kDomToCurve, sid.value()).absorb(seed).squeeze_point(G);
		Scalar r = G.rand_scalar();
		Point z = G.mul_gen(r);
		Point T_r_neg = T.mul(r).inv();                // -(T^r), reused per OT

		// Per-OT pads p_{i,0}, p_{i,1} (the random seed-OT outputs).
		p0_.resize(length);
		p1_.resize(length);
		for (int64_t i = 0; i < length; ++i) {
			Point rho0 = B[i].mul(r);                  // ρ_{i,0} = B_i^r
			Point rho1 = rho0.add(T_r_neg);            // ρ_{i,1} = B_i^r · (T^r)^{-1}
			p0_[i] = H_pad(i, rho0);
			p1_[i] = H_pad(i, rho1);
		}

		// Chosen-input ciphertexts c_{i,b} = p_{i,b} ⊕ data_{i,b}.
		std::vector<block> c0(length);
		std::vector<block> c1(length);
		for (int64_t i = 0; i < length; ++i) {
			c0[i] = p0_[i] ^ data0[i];
			c1[i] = p1_[i] ^ data1[i];
		}

		// Round 2 (S→R): core bytes (z, {c_{i,0}, c_{i,1}}), buffered (no flush).
		io->send_pt(&z);
		io->send_block(c0.data(), length);
		io->send_block(c1.data(), length);
	}

	// Deferred Round-2-tail + Round-3 check ({χ_i}, Π; recv otans' and verify),
	// over the pads stashed by send_core. Aborts on mismatch.
	void send_check() override {
		sfrot_check_send(io, sid.value(), p0_.data(), p1_.data(), length_);
	}

	// ----- Receiver side. Plays the OT receiver role (R in the paper). -----
	// Messy core only: Round 1 send, Round 2 recv + decrypt. Stashes the chosen
	// pads p_bi_ and a copy of b for the deferred check, and decrypts the
	// outputs (local — the deferred check, not the decrypt, is what gates
	// acceptance; the extension's own check + this base check both run before
	// any output is consumed). Does NOT flush.
	void recv_core(block * data, const bool * b, int64_t length) override {
		assert(length >= 80 && "CSW: length must be ≥ 80");
		length_ = length;
		b_copy_.resize(length);
		for (int64_t i = 0; i < length; ++i) b_copy_[i] = b[i] ? 1 : 0;

		// Receiver params: seed ← {0,1}^κ; T = H_1(sid, seed).
		// Round 1 (R→S): send seed, {B_i}.
		block seed;
		PRG prg;
		prg.random_block(&seed, 1);
		Point T = RO(kDomToCurve, sid.value()).absorb(seed).squeeze_point(G);
		io->send_block(&seed, 1);

		// Per-OT receiver msg: α_i ← Z_q; B_i = g^{α_i} · T^{b_i}.
		std::vector<Scalar> alpha(length);
		std::vector<Point> B(length);
		for (int64_t i = 0; i < length; ++i) {
			alpha[i] = G.rand_scalar();
			B[i] = G.mul_gen(alpha[i]);
			if (b[i])
				B[i] = B[i].add(T);
			io->send_pt(&B[i], 1);
		}


		// Round 2 (S→R): recv core bytes (z, {c_{i,0}, c_{i,1}}). The pads
		// p_bi[i] depend only on (z, alpha), so compute them right after
		// recv'ing z while the bulk c0/c1 payload is still in flight (the
		// EC exp is the cost; the check's hash of p_bi runs later).
		Point z;
		io->recv_pt(&G, &z);

		p_bi_.resize(length);              // chosen pads; used by the check and decryption
		for (int64_t i = 0; i < length; ++i) {
			Point z_alpha = z.mul(alpha[i]);
			p_bi_[i] = H_pad(i, z_alpha);
		}

		std::vector<block> c0(length);
		std::vector<block> c1(length);
		io->recv_block(c0.data(), length);
		io->recv_block(c1.data(), length);

		// Decrypt outputs from the chosen pad.
		for (int64_t i = 0; i < length; ++i) {
			block c = b[i] ? c1[i] : c0[i];
			data[i] = c ^ p_bi_[i];
		}
	}

	// Deferred challenge–prove–response check (recvs {χ_i}, Π; verifies against
	// the stashed chosen pads; sends otans' as Round 3). Aborts on a malformed
	// challenge — covers honest abort and the selective-failure-detected case.
	// The trailing flush pushes otans' (and the bundled buffer) to the sender.
	void recv_check() override {
		sfrot_check_recv(io, sid.value(), p_bi_.data(),
		                 reinterpret_cast<const bool*>(b_copy_.data()), length_);
		io->flush();
	}
};

}  // namespace emp
#endif  // EMP_CSW_H__
