#ifndef EMP_IKNP_H__
#define EMP_IKNP_H__
#include <cassert>
#include "emp-ot/cot.h"
#include "emp-ot/base_ot/co.h"

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
 * Streaming Fiat-Shamir: each pre_block call snapshots the transcript
 * after putting its u-matrix bytes (Hash::digest with reset_after=false),
 * derives a per-chunk chi seed, and folds the chunk's packed F_{2^128}
 * elements into running accumulators (check_q on the sender, check_t /
 * check_x on the receiver) right after sse_trans, while `out` is still
 * cache-hot. rcot_send_end / rcot_recv_end run a final 128-OT chunk
 * (folded with chi from the same continuing transcript) before the
 * (x, t) io exchange and check_q ⊕ x·Δ == t compare. The streaming API
 * is stateless — *_begin() just resets transcript and accumulators; the
 * caller drives the chunk loop, picking length per call (must be a
 * multiple of 128 and ≤ block_size, since rcot_*_next writes
 * ((len+127)/128)*128 blocks directly into the caller buffer). The
 * single-call rcot_send / rcot_recv wrappers drive one full session
 * each and handle the non-aligned tail with stack scratch for callers
 * that don't need chunk-by-chunk streaming.
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
class IKNP : public RandomCOT { public:
	// ===== State =====
	static constexpr int64_t block_size = 1024 * 2;
	bool s[128];
	PRG prg, G0[128], G1[128];
	PRG choice_prg;
	bool malicious = true;
	bool is_sender = false;
	// Tracks whether setup_send / setup_recv has been called. rcot_send /
	// rcot_recv auto-run the matching setup on first call so callers
	// without a specific Δ to pin can just construct + use.
	bool setup_done = false;
	// Fiat-Shamir transcript over the OT-extension u-matrix bytes. Both
	// sides absorb the same byte stream during rcot_*_next; snapshots
	// (reset_after=false) yield matching per-chunk chi seeds.
	Hash transcript;
	// Packs 128 consecutive COT outputs into a single F_{2^128} element
	// via the gadget (1, X, ..., X^{127}). Lets the malicious check
	// chi-combine 128x fewer elements than the unpacked version.
	GaloisFieldPacking packer;
	// Running malicious-check accumulators, reset at each rcot_*_begin.
	// Sender uses check_q; receiver uses check_t and check_x.
	block check_q, check_t, check_x;
	// Session flags: rcot_*_begin sets, rcot_*_end clears, rcot_*_next
	// asserts. Catches forgotten begin/end and double-begin in debug
	// builds.
	bool in_send_session = false;
	bool in_recv_session = false;

	IKNP() = default;
	explicit IKNP(IOChannel *io_, bool malicious_ = true) : malicious(malicious_) {
		this->io = io_;
	}

	~IKNP() {
		assert(!in_send_session && "~IKNP: send session active — missing rcot_send_end");
		assert(!in_recv_session && "~IKNP: recv session active — missing rcot_recv_end");
	}

	// ===== Setup =====
	// Sender role with explicit Δ (caller must ensure delta_bool_in[0] = true).
	void setup_send(const bool *delta_bool_in);
	// Sender role with random Δ; forces bit_0 = 1 internally.
	void setup_send();
	// Receiver role.
	void setup_recv();

	// ===== RandomCOT one-shot =====
	// Run one full random COT session of `num` outputs. Auto-runs the
	// matching setup on first call.
	void rcot_send(block *data, int64_t num) override;
	void rcot_recv(block *data, int64_t num) override;

	// ===== Streaming API =====
	// External streaming consumers: *_begin → loop *_next (length must
	// be a multiple of 128 and ≤ block_size) → *_end. Setup must already
	// be done (no auto-setup at this layer).
	void rcot_send_begin();
	void rcot_send_next(block *out, int64_t len);
	void rcot_send_end();

	void rcot_recv_begin();
	void rcot_recv_next(block *out, int64_t len);
	void rcot_recv_end();

	// ===== Internal helpers (chi-fold per chunk) =====
	void combine_send(block *out, int64_t rounded_len);
	void combine_recv(block *out, block *r, int64_t rounded_len);
};

}  // namespace emp
#endif
