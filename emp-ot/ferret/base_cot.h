#ifndef EMP_OT_BASE_COT_H__
#define EMP_OT_BASE_COT_H__

#include "emp-ot/iknp.h"
#include "emp-ot/ferret/constants.h"
#include "emp-ot/ferret/preot.h"
#include <memory>

namespace emp {

// IKNP-backed base-COT generator. Used by ferret to bootstrap the
// silent-OT pipeline: cot_gen_pre() runs IKNP setup, cot_gen() then
// produces batches of LSB-encoded base COTs (delta in bit 0; choice
// in receiver's bit 0).
class BaseCot { public:
	int party;
	block ot_delta;
	IOChannel *io;
	std::unique_ptr<IKNP> iknp;
	bool malicious = false;

	BaseCot(int party, IOChannel *io, bool malicious = false)
			: party(party), io(io),
			  iknp(std::make_unique<IKNP>(io, malicious)),
			  malicious(malicious) {}

	// Initialize IKNP. ALICE either takes `deltain` or, with the
	// default zero_block sentinel, samples a fresh delta with bit-0 = 1;
	// BOB just runs IKNP setup_recv.
	void cot_gen_pre(block deltain = zero_block) {
		if (party != ALICE) { iknp->setup_recv(); return; }
		if (cmpBlock(&deltain, &zero_block, 1)) {
			PRG prg;
			prg.random_block(&ot_delta, 1);
			ot_delta = (ot_delta & lsb_clear_mask) ^ lsb_only_mask;
		} else {
			ot_delta = deltain;
		}
		bool delta_bool[128];
		bits_to_bools(delta_bool, &ot_delta, 128);
		iknp->setup_send(delta_bool);
	}

	// Generate `size` LSB-encoded base COTs into ot_data.
	void cot_gen(block *ot_data, int64_t size, bool *pre_bool = nullptr) {
		bool *bits = produce_cots(ot_data, size, pre_bool);
		delete[] bits;  // delete[] nullptr is well-defined
	}

	// Same, then feed the result through pre_ot for downstream spcot.
	void cot_gen(OTPre *pre_ot, int64_t size, bool *pre_bool = nullptr) {
		block *ot_data = new block[size];
		bool  *bits    = produce_cots(ot_data, size, pre_bool);
		if (party == ALICE) pre_ot->send_pre(ot_data, ot_delta);
		else                pre_ot->recv_pre(ot_data, bits);
		delete[] bits;
		delete[] ot_data;
	}

private:
	// Shared body for both cot_gen overloads. ALICE runs IKNP send_cot
	// and masks bit 0; BOB picks choice bits (caller-supplied unless
	// malicious, in which case fresh PRG-sampled), runs IKNP recv_cot,
	// masks bit 0, then ORs the choice back in. Returns the choice-bit
	// array (BOB only; nullptr for ALICE) — caller frees.
	bool* produce_cots(block *ot_data, int64_t size, bool *pre_bool) {
		if (party == ALICE) {
			iknp->send_cot(ot_data, size);
			io->flush();
			for (int64_t i = 0; i < size; ++i)
				ot_data[i] = ot_data[i] & lsb_clear_mask;
			return nullptr;
		}
		bool *bits = new bool[size];
		if (pre_bool && !malicious) memcpy(bits, pre_bool, size);
		else                        PRG().random_bool(bits, size);
		iknp->recv_cot(ot_data, bits, size);
		const block ch[2] = { zero_block, lsb_only_mask };
		for (int64_t i = 0; i < size; ++i)
			ot_data[i] = (ot_data[i] & lsb_clear_mask) ^ ch[bits[i]];
		return bits;
	}
};

}  // namespace emp
#endif
