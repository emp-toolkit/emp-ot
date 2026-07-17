#ifndef EMP_IKNP_H__
#define EMP_IKNP_H__
#include <memory>
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/tuning.h"

namespace emp {

// Default base OT for IKNP. Change here to swap; OTExtension's contract
// just needs any malicious-secure (when malicious_=true) OT subclass.
using IKNPBaseOT = CSW;

/*
 * IKNP OT Extension — RandomCOT backend.
 * [REF] "Extending oblivious transfers efficiently"
 *       https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf
 * [REF] "More Efficient Oblivious Transfer and Extensions for Faster Secure Computation"
 *       https://eprint.iacr.org/2013/552.pdf
 * [REF] Active security via "Actively Secure OT Extension with Optimal Overhead"
 *       https://eprint.iacr.org/2015/546.pdf  (send_check / recv_check)
 *
 * Streaming Fiat-Shamir: each next() derives a per-chunk chi seed by
 * snapshotting the IOChannel FS transcript (io->get_digest()) after
 * the chunk's u-matrix bytes have crossed the wire — they are absorbed
 * automatically by send_data/recv_data, no per-row puts needed. The
 * chunk's packed F_{2^128} elements fold into running accumulators
 * (check_q on the sender, check_t / check_x on the receiver) right
 * after sse_trans, while `out` is still cache-hot. end() runs a final
 * 128-OT chunk (folded with chi from the same continuing transcript)
 * before the (x, t) io exchange and the check_q ⊕ x·Δ == t compare.
 * Each next() writes exactly chunk_size() = block_size = 2048 blocks;
 * the StreamingExtension base wraps it into a one-shot rcot() with a
 * leftover buffer for callers whose `num` isn't a multiple of
 * block_size.
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
	explicit IKNP(int party_, IOChannel *io_, bool malicious_ = true,
	              std::unique_ptr<OT> base_ot_ = nullptr)
	    : OTExtension(party_, io_, malicious_,
	                  base_ot_ ? std::move(base_ot_)
	                           : std::unique_ptr<OT>(new IKNPBaseOT(io_))) {}

	// ===== StreamingExtension contract =====
	int64_t chunk_size() const override { return block_size; }
	void begin() override;
	void next(block *out) override;
	void end() override;

	// Per-chunk extend direction: the OT-sender role is recv-dominant
	// (send_next_ recv_data's the receiver's matrix correction); the receiver
	// send-dominant. Same as SoftSpoken.
	static constexpr bool kSenderSendsOnExtend = false;

private:
	// ===== State =====
	static constexpr int64_t block_size = tuning::iknp_chunk_ots;
	// Per-row PRG streams. The base-class choice_prg samples the
	// bit-packed choice vector r on the receiver. The sender-side Δ
	// bool form lives on the base as `delta_bool[]` and is read in
	// send_next_.
	PRG G0[128], G1[128];
	// Packs 128 consecutive COT outputs into a single F_{2^128} element
	// via the gadget (1, X, ..., X^{127}). Lets the malicious check
	// chi-combine 128x fewer elements than the unpacked version.
	GaloisFieldPacking packer;
	// Running malicious-check accumulators, reset at each begin().
	// Sender uses check_q; receiver uses check_t and check_x.
	block check_q, check_t, check_x;

	// ===== Internal helpers (chi-fold per chunk) =====
	void combine_send(block *out);
	void combine_recv(block *out, block *r);

	// Per-role bodies invoked from begin/next/end with inline
	// party-dispatch — IKNP's sender and receiver paths share no work.
	void send_begin_();
	void send_next_(block *out);
	void send_end_();
	void recv_begin_();
	void recv_next_(block *out);
	void recv_end_();
};

}  // namespace emp
#endif
