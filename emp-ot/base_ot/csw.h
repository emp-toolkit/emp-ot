#ifndef EMP_OTCSW_H__
#define EMP_OTCSW_H__
#include <emp-tool/emp-tool.h>
#include <memory>
#include <vector>
#include "emp-ot/ot.h"
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
 * argument needs ℓ > 2σ (paper sec 4 / overview.tex).
 */
class OTCSW : public OT { public:
	// UC-secure under CDH in the random oracle model, with selective-
	// failure resistance via the aggregated-proof check (length ≥ 80).
	bool is_malicious_secure() const override { return true; }

	IOChannel * io;
	Group * G = nullptr;
	bool delete_G = true;
	block sid;

	OTCSW(IOChannel * io_, block sid_, Group * G_ = nullptr) : sid(sid_) {
		this->io = io_;
		if (G_ == nullptr)
			G = new Group();
		else {
			G = G_;
			delete_G = false;
		}
	}

	~OTCSW() override {
		if (delete_G)
			delete G;
	}

	// ===== Random oracles (each tagged with a 1-byte domain separator,
	// prefixed by sid; all four ROs are independent and session-bound). =====

	// H_1(sid, seed) → curve point T. Programmable in the CDH reduction.
	void H_to_curve(const block & seed, Point & T_out) {
		unsigned char buf[1 + sizeof(block) + sizeof(block)];
		buf[0] = '1';
		memcpy(buf + 1, &sid, sizeof(block));
		memcpy(buf + 1 + sizeof(block), &seed, sizeof(block));
		G->hash_to_point((const char *)buf, sizeof(buf), T_out);
	}

	// H_2(sid, i, P) → block. P is a curve point (the DH share ρ).
	// Stack buffer (no heap alloc per call). P-256 uncompressed = 65 B;
	// total max ≈ 90 B; 128 B is comfortably above that and aligns nicely.
	block H_pad(int64_t i, Point & P) {
		alignas(16) unsigned char buf[128];
		size_t plen = P.size();
		assert(1 + sizeof(block) + sizeof(int64_t) + plen <= sizeof(buf));
		buf[0] = '2';
		memcpy(buf + 1, &sid, sizeof(block));
		memcpy(buf + 1 + sizeof(block), &i, sizeof(int64_t));
		P.to_bin(buf + 1 + sizeof(block) + sizeof(int64_t), plen);
		return Hash::hash_for_block(buf,
			(int)(1 + sizeof(block) + sizeof(int64_t) + plen));
	}

	// H_3(sid, x) → block. x is a single block (used both for hashing
	// individual p_{i,b} and for the Π = H_3(sid, otans) proof).
	block H_short(const block & x) {
		unsigned char buf[1 + sizeof(block) + sizeof(block)];
		buf[0] = '3';
		memcpy(buf + 1, &sid, sizeof(block));
		memcpy(buf + 1 + sizeof(block), &x, sizeof(block));
		return Hash::hash_for_block(buf, sizeof(buf));
	}

	// H_4(sid, h_1, …, h_ℓ) → block. Aggregates ℓ blocks into one.
	// For typical ℓ = 128 the buffer is 1 + 16 + 2048 = 2065 B — heap
	// alloc once is fine since H_aggregate is called twice per batch.
	block H_aggregate(const block * hs, int64_t ell) {
		size_t hlen = 1 + sizeof(block) + (size_t)ell * sizeof(block);
		std::unique_ptr<unsigned char[]> buf(new unsigned char[hlen]);
		buf[0] = '4';
		memcpy(buf.get() + 1, &sid, sizeof(block));
		memcpy(buf.get() + 1 + sizeof(block), hs, (size_t)ell * sizeof(block));
		return Hash::hash_for_block(buf.get(), (int)hlen);
	}

	// ----- Sender side. Plays the OT sender role (S in the paper). -----
	void send(const block * data0, const block * data1, int64_t length) override {
		assert(length >= 80 &&
		       "OTCSW: length must be ≥ 80 (paper requires ℓ > 2σ for σ=40)");

		// Round 1 (R→S): receive seed, {B_i}.
		block seed;
		io->recv_data(&seed, sizeof(block));
		std::vector<Point> B(length);
		io->recv_pt(G, B.data(), length);

		// Sender params: T = H_1(sid, seed); r ← Z_q; z = g^r.
		// Amortize T^r over the batch: ρ_{i,1} = (B_i/T)^r = B_i^r · (T^r)^{-1}
		// = ρ_{i,0} + (-T_r). One mul/OT instead of two.
		Point T;
		H_to_curve(seed, T);
		BigInt r;
		G->get_rand_bn(r);
		Point z = G->mul_gen(r);
		Point T_r_neg = T.mul(r).inv();                // -(T^r), reused per OT

		// Per-OT pads p_{i,0}, p_{i,1} and h0_i = H_3(sid, p_{i,0}).
		std::vector<block> p0(length);
		std::vector<block> p1(length);
		std::vector<block> h0(length);
		for (int64_t i = 0; i < length; ++i) {
			Point rho0 = B[i].mul(r);                  // ρ_{i,0} = B_i^r
			Point rho1 = rho0.add(T_r_neg);            // ρ_{i,1} = B_i^r · (T^r)^{-1}
			p0[i] = H_pad(i, rho0);
			p1[i] = H_pad(i, rho1);
			h0[i] = H_short(p0[i]);
		}

		// Aggregate otans = H_4(sid, h0_1, …, h0_ℓ) and proof Π = H_3(sid, otans).
		block otans = H_aggregate(h0.data(), length);
		block proof = H_short(otans);

		// Per-OT challenge χ_i = H_3(sid, p_{i,0}) ⊕ H_3(sid, p_{i,1});
		// chosen-input ciphertexts c_{i,b} = p_{i,b} ⊕ data_{i,b}.
		std::vector<block> chi(length);
		std::vector<block> c0(length);
		std::vector<block> c1(length);
		for (int64_t i = 0; i < length; ++i) {
			block h1 = H_short(p1[i]);
			chi[i] = h0[i] ^ h1;
			c0[i] = p0[i] ^ data0[i];
			c1[i] = p1[i] ^ data1[i];
		}

		// Round 2 (S→R): send (z, {χ_i}, Π, {c_{i,0}, c_{i,1}}).
		io->send_pt(&z);
		io->send_block(chi.data(), length);
		io->send_block(&proof, 1);
		io->send_block(c0.data(), length);
		io->send_block(c1.data(), length);
		io->flush();

		// Round 3 (R→S): receive otans' and verify against otans.
		block otans_prime;
		io->recv_block(&otans_prime, 1);
		if (!cmpBlock(&otans, &otans_prime, 1))
			error("OTCSW::send: otans verification failed (receiver misbehavior)");
	}

	// ----- Receiver side. Plays the OT receiver role (R in the paper). -----
	void recv(block * data, const bool * b, int64_t length) override {
		assert(length >= 80 && "OTCSW: length must be ≥ 80");

		// Receiver params: seed ← {0,1}^κ; T = H_1(sid, seed).
		block seed;
		PRG prg;
		prg.random_block(&seed, 1);
		Point T;
		H_to_curve(seed, T);

		// Per-OT receiver msg: α_i ← Z_q; B_i = g^{α_i} · T^{b_i}.
		std::vector<BigInt> alpha(length);
		std::vector<Point> B(length);
		for (int64_t i = 0; i < length; ++i) {
			G->get_rand_bn(alpha[i]);
			B[i] = G->mul_gen(alpha[i]);
			if (b[i])
				B[i] = B[i].add(T);
		}

		// Round 1 (R→S): send seed, {B_i}.
		io->send_data(&seed, sizeof(block));
		io->send_pt(B.data(), length);
		io->flush();

		// Round 2 (S→R): recv (z, {χ_i}, Π, {c_{i,0}, c_{i,1}}).
		// α_i·z, p_bi[i], H_short(p_bi[i]) depend only on (z, alpha), so
		// compute them right after recv'ing z and while the bulk
		// chi/proof/c0/c1 payload is still in flight. The XOR with chi[i]
		// that produces otresp[i] runs after chi is in hand.
		Point z;
		io->recv_pt(G, &z);

		std::vector<block> p_bi(length);   // saved for decryption after Π verification
		std::vector<block> h_bi(length);   // H_short(p_bi[i]); xored with chi[i] later
		for (int64_t i = 0; i < length; ++i) {
			Point z_alpha = z.mul(alpha[i]);
			p_bi[i] = H_pad(i, z_alpha);
			h_bi[i] = H_short(p_bi[i]);
		}

		std::vector<block> chi(length);
		block proof;
		std::vector<block> c0(length);
		std::vector<block> c1(length);
		io->recv_block(chi.data(), length);
		io->recv_block(&proof, 1);
		io->recv_block(c0.data(), length);
		io->recv_block(c1.data(), length);

		// Per-OT response: otresp_i = H_3(sid, p_{i,b_i}) ⊕ (b_i · χ_i).
		std::vector<block> otresp(length);
		for (int64_t i = 0; i < length; ++i)
			otresp[i] = b[i] ? (h_bi[i] ^ chi[i]) : h_bi[i];

		// Aggregate otans' and verify Π. Aborts on mismatch — covers
		// both honest abort (sender malformed χ_i) and the
		// selective-failure-detected case from the paper.
		block otans_prime = H_aggregate(otresp.data(), length);
		block proof_check = H_short(otans_prime);
		if (!cmpBlock(&proof, &proof_check, 1))
			error("OTCSW::recv: proof verification failed (sender misbehavior or selective-failure attack)");

		// Decrypt outputs.
		for (int64_t i = 0; i < length; ++i) {
			block c = b[i] ? c1[i] : c0[i];
			data[i] = c ^ p_bi[i];
		}

		// Round 3 (R→S): send otans'.
		io->send_block(&otans_prime, 1);
		io->flush();
	}
};

}  // namespace emp
#endif  // EMP_OTCSW_H__
