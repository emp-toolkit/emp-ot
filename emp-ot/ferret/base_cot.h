#ifndef EMP_OT_BASE_COT_H__
#define EMP_OT_BASE_COT_H__

#include "emp-ot/iknp.h"
#include "emp-ot/ferret/constants.h"
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

	// Generate `size` LSB-encoded base COTs into ot_data. Calls IKNP's
	// rcot_* directly (the chosen-message wrapper in cot.h::RandomCOT
	// adds a per-COT bit exchange that ferret doesn't need — pre_bool
	// is always nullptr at real call sites). IKNP's rcot already
	// satisfies the LSB-encoded convention out of the box:
	//   recv: bit_0(M_i) = b_i (pinned by IKNP::rcot_recv_next).
	//   send: bit_0(K_i) = bit_0(M_i) XOR b_i·bit_0(Δ) = b XOR b = 0,
	//         since cot_gen_pre forces bit_0(Δ) = 1.
	// pre_bool kept on the signature so call sites need no edits; it
	// is unused.
	void cot_gen(block *ot_data, int64_t size, bool * /*pre_bool*/ = nullptr) {
		if (party == ALICE) iknp->rcot_send(ot_data, size);
		else                iknp->rcot_recv(ot_data, size);
	}
};

}  // namespace emp
#endif
