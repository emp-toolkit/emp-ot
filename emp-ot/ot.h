#ifndef EMP_OT_H__
#define EMP_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/tuning.h"

namespace emp {

// Abstract 1-out-of-2 OT.
class OT {
public:
	virtual void send(const block* data0, const block* data1, int64_t length) = 0;
	virtual void recv(block* data, const bool* b, int64_t length)  = 0;
	virtual ~OT() {}

	// Security level of the OT protocol.
	virtual bool is_malicious_secure() const { return false; }

	// True iff this is a "CSW-like" base OT that exposes the messy-core +
	// deferred extraction-check split (see CSWBaseOT). An OT extension uses
	// this to overlap the base OT's last two flows with its own first message
	// (3-round result); a default (false) base OT gets the blocking path.
	// Static capability trait, mirroring is_malicious_secure().
	virtual bool supports_deferred_check() const { return false; }

	// Per-session domain separator, default the zero id. Extensions forward a
	// derived child sid to their base OT (see OTExtension); callers may set a
	// session-unique value before first use, but are not required to. The
	// SessionID ctor is implicit, so set_sid(some_block) still works.
	virtual void set_sid(SessionID s) { sid = s; }
protected:
	IOChannel * io = nullptr;
	SessionID sid;
};

// Correlated OT (sender's two messages differ by a fixed Δ). Subclasses
// provide send_cot / recv_cot; the chosen-input send/recv overrides
// here build the standard 1-bit-per-COT chosen-message correction wrapper
// on top of MITCCRH.
class COT : public OT { public:
	block Delta;     // sender's correlation; 

	virtual void send_cot(block* data0, int64_t length) = 0;
	virtual void recv_cot(block* data, const bool* b, int64_t length) = 0;

	void send(const block* data0, const block* data1, int64_t length) override {
		BlockVec data(length);
		send_cot(data.data(), length);
		block s;prg.random_block(&s, 1);
		io->send_block(&s,1);
		mitccrh.setS(s);
		block pad[2*ot_bsize];
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
	}

	void recv(block* data, const bool* r, int64_t length) override {
		recv_cot(data, r, length);
		block s;
		io->recv_block(&s,1);
		mitccrh.setS(s);

		block res[2*ot_bsize];
		block pad[ot_bsize];
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
		send_cot(data0, length);
		block s; prg.random_block(&s, 1);
		io->send_block(&s,1);
		mitccrh.setS(s);
		io->flush();

		block pad[ot_bsize*2];
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
		recv_cot(data, r, length);
		block s;
		io->recv_block(&s,1);
		mitccrh.setS(s);
		block pad[ot_bsize];
		for(int64_t i = 0; i < length; i+=ot_bsize) {
			memcpy(pad, data+i, std::min(ot_bsize,length-i)*sizeof(block));
			mitccrh.hash<ot_bsize, 1>(pad);
			memcpy(data+i, pad, std::min(ot_bsize,length-i)*sizeof(block));
		}
	}
	
private:
	// Tile size for the chosen-input MITCCRH wrapper: each tile hashes
	// `ot_bsize` COT outputs in one ParaEnc<1, ot_bsize> AES-NI call.
	// Value lives in tuning.h; see cot_chosen_input_tile for rationale.
	static constexpr int64_t ot_bsize = tuning::cot_chosen_input_tile;
	MITCCRH<ot_bsize> mitccrh;
protected:
	PRG prg;
};

// Random COT (random correlated OT). Subclasses produce LSB-encoded
// correlated outputs without choice bits; send_cot / recv_cot below
// add the standard 1-bit-per-COT correction so a chosen-correlation
// COT layer composes on top.
class RandomCOT : public COT {
public:
	// Single role-implicit RCOT entry. The output is signature-symmetric
	// across sender and receiver (both fill an n-block buffer), so we
	// expose one method and the concrete backend dispatches by its own
	// party — no caller-side party check needed at this layer.
	virtual void rcot(block* data, int64_t num) = 0;

	void send_cot(block* data, int64_t length) override {
		rcot(data, length);
		// unsigned char (not bool) so the storage is one byte each —
		// matches the wire layout that `recv_bool` writes (and avoids
		// vector<bool>'s bit-packed specialization, which has no .data()).
		default_init_vector<unsigned char> bo(length);
		io->recv_bool(reinterpret_cast<bool*>(bo.data()), length);

		block tab[2] = {zero_block, all_one_block};

		for (int64_t i = 0; i < length; ++i)
			data[i] ^= Delta & tab[bo[i]];
	}

	void recv_cot(block* data, const bool* b, int64_t length) override {
		rcot(data, length);
		default_init_vector<unsigned char> bo(length);
		for (int64_t i = 0; i < length; ++i)
			bo[i] = b[i] ^ getLSB(data[i]);

		io->send_bool(reinterpret_cast<bool*>(bo.data()), length);
	}
};

}  // namespace emp
#endif
