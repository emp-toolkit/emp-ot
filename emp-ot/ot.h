#ifndef EMP_OT_H__
#define EMP_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/tuning.h"
#include <limits>

namespace emp {

// Argument contract shared by every OT-shaped entry point: the count is
// non-negative and small enough that count * sizeof(block) fits in int64_t,
// and buffers are non-null whenever the count is nonzero. Single-buffer
// entries pass the same pointer twice.
inline void expect_ot_args(int64_t length, const void *buf0, const void *buf1,
                           const char *message) {
	expecting(length >= 0 &&
	              length <= std::numeric_limits<int64_t>::max() /
	                            static_cast<int64_t>(sizeof(block)) &&
	              (length == 0 || (buf0 != nullptr && buf1 != nullptr)),
	          message);
}

// Fiat-Shamir challenge seed for a malicious-mode check: the channel's
// transcript digest, bound to the session id of the object running the check.
// Both parties call it at the same transcript point with the same sid, so they
// draw the same seed without an extra message.
inline block fs_challenge(IOChannel *io, block sid) {
	return RO("emp-ot:fs-challenge", sid)
		.absorb(io->get_digest())
		.squeeze_block();
}

// Abstract 1-out-of-2 OT.
class OT {
public:
	virtual void send(const block* data0, const block* data1, int64_t length) = 0;
	virtual void recv(block* data, const bool* b, int64_t length)  = 0;
	virtual ~OT() {}

	// Security level of the OT protocol.
	virtual bool is_malicious_secure() const { return false; }

	// True iff this base OT exposes the messy-core + deferred extraction-check
	// split (CSW is the only one). An OT extension uses this to overlap the
	// base OT's last two flows with its own first message (3-round result); a
	// default (false) base OT gets the blocking path. Static capability trait,
	// mirroring is_malicious_secure().
	virtual bool supports_deferred_check() const { return false; }

	// Per-session domain separator. A sid set before the first use is kept.
	// Otherwise the first use takes the channel's next session id
	// (IOChannel::next_session_id()), or keeps the zero id on a channel without
	// a session root. First uses come in the order the parties run their
	// protocols, which both ends already share, so both draw the same ids.
	// Extensions forward a derived child sid to their base OT before it runs
	// (see OTExtension; Ferret gives it to the nested extension that takes
	// over its base OT), so only a top-level object draws from its channel.
	// Malicious-mode Fiat-Shamir challenges bind the sid (fs_challenge above).
	// The SessionID ctor is implicit, so set_sid(some_block) also works.
	// An id set here must not be shared with another object, as the channel's
	// ids never are: two objects with one id derive the same child ids.
	virtual void set_sid(SessionID s) {
		sid = s;
		sid_fixed_ = true;
	}
	// The sid in force. It reads zero until the first use fixes it, unless
	// set_sid() ran first.
	const SessionID &session_id() const { return sid; }
protected:
	// Fix the sid at the first use, as set_sid() describes; later calls do
	// nothing.
	void fix_sid_() {
		if (sid_fixed_) return;
		if (io != nullptr && io->has_session_root()) set_sid(io->next_session_id());
		sid_fixed_ = true;
	}
	IOChannel * io = nullptr;
	SessionID sid;
	bool sid_fixed_ = false;
};

// Correlated OT (sender's two messages differ by a fixed Δ). Subclasses
// provide send_cot / recv_cot; the chosen-input send/recv overrides
// here build the standard 1-bit-per-COT chosen-message correction wrapper
// on top of MITCCRH.
class COT : public OT { public:
	block Delta;     // sender's correlation; 

	virtual void send_cot(block* data0, int64_t length) = 0;
	virtual void recv_cot(block* data, const bool* b, int64_t length) = 0;

protected:
	// Role check for the role-explicit wrappers below. An OT extension has
	// one fixed role and overrides this to reject the other role's wrappers;
	// the default accepts both.
	virtual void expect_role_(bool sender, const char* message) const {
		(void)sender;
		(void)message;
	}

public:

	void send(const block* data0, const block* data1, int64_t length) override {
		expect_ot_args(length, data0, data1,
		               "COT::send: invalid length or null buffer");
		expect_role_(true, "COT::send: this extension is the receiver");
		BlockVec data(length);
		send_cot(data.data(), length);
		block s;prg.random_block(&s, 1);
		io->send_block(&s,1);
		mitccrh.setS(s);
		block pad[2*ot_bsize] = {};
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				pad[2*(j-i)] = data[j];
				pad[2*(j-i)+1] = data[j] ^ Delta;
			}
			mitccrh.hash<ot_bsize, 2>(pad);
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				pad[2*(j-i)] = pad[2*(j-i)] ^ data0[j];
				pad[2*(j-i)+1] = pad[2*(j-i)+1] ^ data1[j];
			}
			io->send_data(pad, 2*sizeof(block)*std::min(ot_bsize,length-i));
		}
		io->flush();
	}

	void recv(block* data, const bool* r, int64_t length) override {
		expect_ot_args(length, data, r,
		               "COT::recv: invalid length or null buffer");
		expect_role_(false, "COT::recv: this extension is the sender");
		recv_cot(data, r, length);
		block s;
		io->recv_block(&s,1);
		mitccrh.setS(s);

		block res[2*ot_bsize];
		block pad[ot_bsize] = {};
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, std::min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			io->recv_data(res, 2*sizeof(block)*std::min(ot_bsize,length-i));
			for(int64_t j = 0; j < ot_bsize and j < length-i; ++j) {
				data[i+j] = res[2*j+r[i+j]] ^ pad[j];
			}
		}
	}

	void send_rot(block* data0, block* data1, int64_t length) {
		expect_ot_args(length, data0, data1,
		               "COT::send_rot: invalid length or null buffer");
		expect_role_(true, "COT::send_rot: this extension is the receiver");
		send_cot(data0, length);
		block s; prg.random_block(&s, 1);
		io->send_block(&s,1);
		mitccrh.setS(s);
		io->flush();

		block pad[ot_bsize*2] = {};
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				pad[2*(j-i)] = data0[j];
				pad[2*(j-i)+1] = data0[j] ^ Delta;
			}
			mitccrh.hash<ot_bsize, 2>(pad);
			for(int64_t j = i; j < std::min(i+ot_bsize, length); ++j) {
				data0[j] = pad[2*(j-i)];
				data1[j] = pad[2*(j-i)+1];
			}
		}
	}

	void recv_rot(block* data, const bool* r, int64_t length) {
		expect_ot_args(length, data, r,
		               "COT::recv_rot: invalid length or null buffer");
		expect_role_(false, "COT::recv_rot: this extension is the sender");
		recv_cot(data, r, length);
		block s;
		io->recv_block(&s,1);
		mitccrh.setS(s);
		block pad[ot_bsize] = {};
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, std::min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			memcpy(data+i, pad, std::min(ot_bsize,length-i)*sizeof(block));
		}
	}
	
private:
	// Tile size for the chosen-input MITCCRH wrapper: each tile hashes
	// `ot_bsize` COT outputs in one MITCCRH call, under one key, as one
	// ParaEnc<1, H * ot_bsize> AES-NI call (H = 2 pads per output when
	// sending, 1 when receiving). Value lives in tuning.h; see
	// cot_chosen_input_tile for rationale. A short last tile still hashes
	// all ot_bsize lanes (the outputs of the unused ones are dropped), so the
	// pad buffers start zeroed.
	static constexpr int64_t ot_bsize = tuning::cot_chosen_input_tile;
	MITCCRH<> mitccrh;
protected:
	PRG prg;
};

// Random COT (random correlated OT). Subclasses produce LSB-encoded
// correlated outputs without choice bits: with LSB(Δ) = 1, the receiver's
// LSB is its choice bit and the sender's is 0. send_cot / recv_cot below add
// the standard 1-bit-per-COT correction so a chosen-correlation COT layer
// composes on top, and keep that encoding for the chosen bits.
class RandomCOT : public COT {
public:
	// Single role-implicit RCOT entry. The output is signature-symmetric
	// across sender and receiver (both fill an n-block buffer), so we
	// expose one method and the concrete backend dispatches by its own
	// party — no caller-side party check needed at this layer.
	virtual void rcot(block* data, int64_t num) = 0;

	void send_cot(block* data, int64_t length) override {
		expect_ot_args(length, data, data,
		               "RandomCOT::send_cot: invalid length or null buffer");
		expect_role_(true, "RandomCOT::send_cot: this extension is the receiver");
		rcot(data, length);
		// unsigned char (not bool) so the storage is one byte each —
		// matches the wire layout that `recv_bool` writes (and avoids
		// vector<bool>'s bit-packed specialization, which has no .data()).
		default_init_vector<unsigned char> bo(length);
		io->recv_bool(reinterpret_cast<bool*>(bo.data()), length);

		// Where the receiver's choice flips, XOR in Δ with its LSB cleared:
		// this side's LSB stays 0, and the receiver flips its own.
		const block flip = Delta ^ makeBlock(0, 1);
		block tab[2] = {zero_block, all_one_block};

		for (int64_t i = 0; i < length; ++i)
			data[i] ^= flip & tab[bo[i]];
	}

	void recv_cot(block* data, const bool* b, int64_t length) override {
		expect_ot_args(length, data, b,
		               "RandomCOT::recv_cot: invalid length or null buffer");
		expect_role_(false, "RandomCOT::recv_cot: this extension is the sender");
		rcot(data, length);
		// Where the choice flips, flip the LSB too, so it stays the choice bit.
		default_init_vector<unsigned char> bo(length);
		const block tab[2] = {zero_block, makeBlock(0, 1)};
		for (int64_t i = 0; i < length; ++i) {
			bo[i] = b[i] ^ getLSB(data[i]);
			data[i] ^= tab[bo[i]];
		}

		io->send_bool(reinterpret_cast<bool*>(bo.data()), length);
		io->flush();
	}
};

}  // namespace emp
#endif
