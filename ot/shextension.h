#ifndef OT_SH_EXTENSION_H__
#define OT_SH_EXTENSION_H__
#include "ot.h"
#include "np.h"
/** @addtogroup OT
    @{
  */

class SHOTExtension: public OT<SHOTExtension> { public:
	OTNP * base_ot;
	PRG prg;
	PRP pi;
	const int l = 128;
	block *k0, *k1;
	bool *s;

	block * qT, block_s, *tT;
	bool setup = false;
	SHOTExtension(NetIO * io): OT(io) {
		this->base_ot = new OTNP(io);
		this->s = new bool[l];
		this->k0 = new block[l];
		this->k1 = new block[l];
	}

	~SHOTExtension() {
		delete base_ot;
		delete[] s;
		delete[] k0;
		delete[] k1;
	}

	void setup_send(block * in_k0 = nullptr, bool * in_s = nullptr){
		setup = true;
		if(in_s != nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(s, in_s, l);
			block_s = bool_to128(s);
			return;
		}
		prg.random_bool(s, l);
		base_ot->recv(k0, s, l);
		block_s = bool_to128(s);
	}

	void setup_recv(block * in_k0 = nullptr, block * in_k1 =nullptr) {
		setup = true;
		if(in_k0 !=nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(k1, in_k1, l*sizeof(block));
			return;
		}
		prg.random_block(k0, l);
		prg.random_block(k1, l);
		base_ot->send(k0, k1, l);
	}

	void send_pre(int length) {
		if (length%128 !=0) length = (length/128 + 1)*128;

		if(!setup) setup_send();
		setup = false;
		block * q = new block[length];
		qT = new block[length];
		//get u, compute q
		block *tmp = new block[length/128];
		PRG G;
		for(int i = 0; i < l; ++i) {
			io->recv_data(tmp, length/8);
			G.reseed(&k0[i]);
			G.random_data(q+(i*length/128), length/8);
			if (s[i])
				xorBlocks_arr(q+(i*length/128), q+(i*length/128), tmp, length/128);
		}
		sse_trans((uint8_t *)(qT), (uint8_t*)q, l, length);
		delete[] tmp;
		delete[] q;
	}

	void recv_pre(const bool* r, int length) {
		int old_length = length;
		if (length%128 !=0) length = (length/128 + 1)*128;

		if(!setup)setup_recv();
		setup = false;
		bool * r2 = new bool[length];
		memcpy(r2, r, old_length);
		block *block_r = new block[length/128];
		for(int i = 0; i < length/128; ++i) {
			block_r[i] = bool_to128(r2+i*128);
		}
		// send u
		block* t = new block[length];
		tT = new block[length];
		block* tmp = new block[length/128];
		PRG G;
		for(int i = 0; i < l; ++i) {
			G.reseed(&k0[i]);
			G.random_data(t+i*length/128, length/8);
			G.reseed(&k1[i]);
			G.random_data(tmp, length/8);
			xorBlocks_arr(tmp, t+(i*length/128), tmp, length/128);
			xorBlocks_arr(tmp, block_r, tmp, length/128);
			io->send_data(tmp, length/8);
		}

		sse_trans((uint8_t *)tT, (uint8_t*)t, l, length);

		delete[] t;
		delete[] tmp;
		delete[] block_r;
		delete[] r2;
	}

	void got_send_post(const block* data0, const block* data1, int length) {
		block pad[2];
		for(int i = 0; i < length; ++i) {
			pad[0] = qT[i];
			pad[1] = xorBlocks(qT[i], block_s);
			pi.H<2>(pad, pad, 2*i);
			pad[0] = xorBlocks(pad[0], data0[i]);
			pad[1] = xorBlocks(pad[1], data1[i]);
			io->send_data(pad, 2*sizeof(block));
		}
		delete[] qT;
	}

	void got_recv_post(block* data, const bool* r, int length) {
		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			if(r[i]) {
				data[i] = xorBlocks(res[1], pi.H(tT[i], 2*i+1));
			} else {
				data[i] = xorBlocks(res[0], pi.H(tT[i], 2*i));
			}
		}
		delete[] tT;
	}
	void send_impl(const block* data0, const block* data1, int length) {
		send_pre(length);
		got_send_post(data0, data1, length);
	}

	void recv_impl(block* data, const bool* b, int length) {
		recv_pre(b, length);
		got_recv_post(data, b, length);
	}

	void send_cot(block * data0, block delta, int length) {
		send_pre(length);
		cot_send_post(data0, delta, length);
	}
	void recv_cot(block* data, const bool* b, int length) {
		recv_pre(b, length);
		cot_recv_post(data, b, length);
	}
	void send_rot(block * data0, block * data1, int length) {
		send_pre(length);
		rot_send_post(data0, data1, length);
	}
	void recv_rot(block* data, const bool* b, int length) {
		recv_pre(b, length);
		rot_recv_post(data, b, length);
	}

	void cot_send_post(block* data0, block delta, int length) {
		block pad[2];
		for(int i = 0; i < length; ++i) {
			pad[0] = qT[i];
			pad[1] = xorBlocks(qT[i], block_s);
			pi.H<2>(pad, pad, 2*i);
			data0[i] = pad[0];
			pad[0] = xorBlocks(pad[0], delta);
			pad[0] = xorBlocks(pad[1], pad[0]);
			io->send_data(pad, sizeof(block));
		}
		delete[] qT;
	}

	void cot_recv_post(block* data, const bool* r, int length) {
		block res;
		for(int i = 0; i < length; ++i) {
			io->recv_data(&res, sizeof(block));
			if(r[i])
				data[i] = xorBlocks(res, pi.H(tT[i], 2*i+1));
			else 
				data[i] = pi.H(tT[i], 2*i);
		}
		delete[] tT;
	}
	
	void rot_send_post(block* data0, block* data1, int length) {
		block pad[2];
		for(int i = 0; i < length; ++i) {
			pad[0] = qT[i];
			pad[1] = xorBlocks(qT[i], block_s);
			pi.H<2>(pad, pad, 2*i);
			data0[i] = pad[0];
			data1[i] = pad[1];
		}
		delete[] qT;
	}

	void rot_recv_post(block* data, const bool* r, int length) {
		for(int i = 0; i < length; ++i)
			data[i] = pi.H(tT[i], 2*i+r[i]);
		delete[] tT;
	}
};
  /**@}*/
#endif// OT_EXTENSION_H__