#ifndef EMP_IKNP_H__
#define EMP_IKNP_H__
#include <cassert>
#include <memory>
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/pvw.h"

namespace emp {

/*
 * IKNP OT Extension — RandomCOT backend.
 * [REF] "Extending oblivious transfers efficiently"
 *       https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf
 * [REF] "More Efficient Oblivious Transfer and Extensions for Faster Secure Computation"
 *       https://eprint.iacr.org/2013/552.pdf
 * [REF] Active security via "Actively Secure OT Extension with Optimal Overhead"
 *       https://eprint.iacr.org/2015/546.pdf  (send_check / recv_check)
 *
 * Streaming Fiat-Shamir: each rcot_*_next derives a per-chunk chi seed
 * by snapshotting the IOChannel FS transcript (io->get_digest()) after
 * the chunk's u-matrix bytes have crossed the wire — they are absorbed
 * automatically by send_data/recv_data, no per-row puts needed. The
 * chunk's packed F_{2^128} elements fold into running accumulators
 * (check_q on the sender, check_t / check_x on the receiver) right
 * after sse_trans, while `out` is still cache-hot. rcot_send_end /
 * rcot_recv_end run a final 128-OT chunk (folded with chi from the
 * same continuing transcript) before the (x, t) io exchange and
 * check_q ⊕ x·Δ == t compare. Each _next writes exactly chunk_ots()
 * = block_size = 2048 blocks; the OTExtension base class wraps the
 * streaming API into a one-shot rcot_send / rcot_recv with a leftover
 * buffer for callers whose `num` isn't a multiple of block_size.
 *
 * Bit-0 choice encoding: with the invariant bit_0(Δ) = 1, row 0 of the
 * IKNP matrix collapses. Sender forces q[0] = 0 (memset row 0 of t,
 * loop starts at i=1). Receiver samples r internally via choice_prg
 * and pins t[0] = r before sse_trans; after transpose, bit_0(M_k) =
 * bit_k(r) = choice_k and bit_0(K_k) = 0, so Q ^ T = r·Δ holds at bit
 * 0 with zero post-processing. RandomCOT's online correction reads
 * getLSB(M_k) = choice_k, so the LSB convention lines up with no
 * extra work. Row 0 is dropped on the wire and in the FS transcript
 * (both sides know it's zeros), saving 1/128 of the u-matrix
 * bandwidth and keeping chi snapshots aligned without sending dead
 * bytes.
 */
class IKNP : public OTExtension { public:
	// ===== State =====
	static constexpr int64_t block_size = 1024 * 2;
	bool s[128];
	PRG prg, G0[128], G1[128];
	PRG choice_prg;
	bool malicious = true;
	bool is_sender = false;
	// Tracks whether setup_send / setup_recv has been called. The
	// OTExtension::rcot_send / rcot_recv wrappers auto-run the
	// matching setup on first call via ensure_setup_for_*().
	bool setup_done = false;
	// Packs 128 consecutive COT outputs into a single F_{2^128} element
	// via the gadget (1, X, ..., X^{127}). Lets the malicious check
	// chi-combine 128x fewer elements than the unpacked version.
	GaloisFieldPacking packer;
	// Running malicious-check accumulators, reset at each rcot_*_begin.
	// Sender uses check_q; receiver uses check_t and check_x.
	block check_q, check_t, check_x;

	// User-supplied base OT, owned by IKNP. Defaults to OTPVW (DDH
	// messy-mode PVW '08 — malicious-secure). Pass a different one
	// (e.g., OTCSW or OTPVWKyber) via the third ctor arg to swap the
	// bootstrap base.
	std::unique_ptr<OT> base_ot;

	IKNP() = default;
	explicit IKNP(IOChannel *io_, bool malicious_ = true,
	              std::unique_ptr<OT> base_ot_ = nullptr) : malicious(malicious_) {
		this->io = io_;
		base_ot = base_ot_ ? std::move(base_ot_)
		                   : std::unique_ptr<OT>(new OTPVW(io_));
	}

	// ===== Setup =====
	// Sender role with explicit Δ (caller must ensure delta_bool_in[0] = true).
	void setup_send(const bool *delta_bool_in);
	// Sender role with random Δ; forces bit_0 = 1 internally.
	void setup_send();
	// Receiver role.
	void setup_recv();

	// ===== OTExtension contract =====
	int64_t chunk_ots() const override { return block_size; }

protected:
	void do_rcot_send_begin() override;
	void do_rcot_send_next(block *out) override;
	void do_rcot_send_end() override;
	void do_rcot_recv_begin() override;
	void do_rcot_recv_next(block *out) override;
	void do_rcot_recv_end() override;

	void ensure_setup_for_send() override {
		if (!setup_done) setup_send();
	}
	void ensure_setup_for_recv() override {
		if (!setup_done) setup_recv();
	}

public:
	// ===== Internal helpers (chi-fold per chunk) =====
	void combine_send(block *out);
	void combine_recv(block *out, block *r);
};

}  // namespace emp
#endif
