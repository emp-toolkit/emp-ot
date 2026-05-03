#ifndef EMP_OT_BASE_COT_H__
#define EMP_OT_BASE_COT_H__

#include "emp-ot/iknp.h"
#include "emp-ot/ferret/constants.h"
#include "emp-ot/ferret/preot.h"

namespace emp {

class BaseCot { public:
	int party;
	block ot_delta;
	IOChannel *io;
	IKNP *iknp;
	bool malicious = false;

	BaseCot(int party, IOChannel *io, bool malicious = false) {
		this->party = party;
		this->io = io;
		this->malicious = malicious;
		iknp = new IKNP(io, malicious);
	}

	~BaseCot() {
		delete iknp;
	}

	void cot_gen_pre(block deltain) {
		if (this->party == ALICE) {
			this->ot_delta = deltain;
			bool delta_bool[128];
			bits_to_bools(delta_bool, &ot_delta, 128);
			iknp->setup_send(delta_bool);
		} else {
			iknp->setup_recv();
		}
	}

	void cot_gen_pre() {
		if (this->party == ALICE) {
			PRG prg;
			prg.random_block(&ot_delta, 1);
			ot_delta = (ot_delta & lsb_clear_mask) ^ lsb_only_mask;
			bool delta_bool[128];
			bits_to_bools(delta_bool, &ot_delta, 128);
			iknp->setup_send(delta_bool);
		} else {
			iknp->setup_recv();
		}
	}

	void cot_gen(block *ot_data, int64_t size, bool * pre_bool = nullptr) {
		if (this->party == ALICE) {
			iknp->send_cot(ot_data, size);
			io->flush();
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] = ot_data[i] & lsb_clear_mask;
		} else {
			PRG prg;
			bool *pre_bool_ini = new bool[size];
			if(pre_bool && !malicious)
				memcpy(pre_bool_ini, pre_bool, size);
			else
				prg.random_bool(pre_bool_ini, size);
			iknp->recv_cot(ot_data, pre_bool_ini, size);
			const block ch[2] = { zero_block, lsb_only_mask };
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] =
						(ot_data[i] & lsb_clear_mask) ^ ch[pre_bool_ini[i]];
			delete[] pre_bool_ini;
		}
	}

	void cot_gen(OTPre *pre_ot, int64_t size, bool * pre_bool = nullptr) {
		block *ot_data = new block[size];
		if (this->party == ALICE) {
			iknp->send_cot(ot_data, size);
			io->flush();
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] = ot_data[i] & lsb_clear_mask;
			pre_ot->send_pre(ot_data, ot_delta);
		} else {
			PRG prg;
			bool *pre_bool_ini = new bool[size];
			if(pre_bool && !malicious)
				memcpy(pre_bool_ini, pre_bool, size);
			else
				prg.random_bool(pre_bool_ini, size);
			iknp->recv_cot(ot_data, pre_bool_ini, size);
			const block ch[2] = { zero_block, lsb_only_mask };
			for(int64_t i = 0; i < size; ++i)
				ot_data[i] =
						(ot_data[i] & lsb_clear_mask) ^ ch[pre_bool_ini[i]];
			pre_ot->recv_pre(ot_data, pre_bool_ini);
			delete[] pre_bool_ini;
		}
		delete[] ot_data;
	}

	// debug
	bool check_cot(block *data, int64_t len) {
		if(party == ALICE) {
			io->send_block(&ot_delta, 1);
			io->send_block(data, len);
			io->flush();
			return true;
		} else {
			block * tmp = new block[len];
			block ch[2];
			io->recv_block(ch+1, 1);
			ch[0] = zero_block;
			io->recv_block(tmp, len);
			for(int64_t i = 0; i < len; ++i)
				tmp[i] = tmp[i] ^ ch[getLSB(data[i])];
			bool res = cmpBlock(tmp, data, len);
			delete[] tmp;
			return res;
		}
	}
};

}  // namespace emp
#endif
