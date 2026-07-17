#ifndef EMP_OTIDEAL_H__
#define EMP_OTIDEAL_H__
#include "emp-ot/ot.h"

namespace emp {
class OTIdeal: public COT { public:
	OTIdeal(IOChannel * io, const bool * delta = nullptr) {
		this->io = io;
		// Public, deterministic seed so both parties' OTIdeal PRGs agree
		// without exchanging anything. Test-only mock — not for production.
		prg.reseed(&zero_block);
		if (delta != nullptr) {
			expecting(delta[0], "OTIdeal: Delta.LSB must be 1");
			Delta = bool_to_block(delta);
		} else {
			prg.random_block(&Delta, 1);
			Delta = set_bit(Delta, 0);
		}
	}

	void send_cot(block* data, int64_t length) override {
		expect_ot_args(length, data, data,
		               "OTIdeal::send_cot: invalid length or null buffer");
		prg.random_block(data, length);
	}

	void recv_cot(block* data, const bool* b, int64_t length) override {
		expect_ot_args(length, data, b,
		               "OTIdeal::recv_cot: invalid length or null buffer");
		prg.random_block(data, length);
		for(int64_t i = 0; i < length; ++i)
			if(b[i])
				data[i] = data[i] ^ Delta;
	}
};
}//namespace
#endif// OT_IDEAL_H__
