#ifndef OT_SH_EXTENSION_H__
#define OT_SH_EXTENSION_H__
#include "ot.h"
#include "ot_np.h"

class SHOTExtension: public OT<SHOTExtension> { public:
	OTNP * base_ot;
	PRG prg;
	PRP pi;
	const int l = 128;
	block *k0, *k1;
	bool *s;

	block * qT, block_s;
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

	void H2(block * out, long id, block in1, block in2) {
		in1 = double_block(in1);
		in2 = double_block(in2);
		__m128i k_128 = _mm_loadl_epi64( (__m128i const *) (&id));
		in1 = xorBlocks(in1, k_128);
		++id;
		k_128 = _mm_loadl_epi64( (__m128i const *) (&id));
		in2 = xorBlocks(in2, k_128);
		out[0] = in1;
		out[1] = in2;
		pi.permute_block(out, 2);
		out[0] =  xorBlocks(in1, out[0]);
		out[1] =  xorBlocks(in2, out[1]);
	}

	block H(long id, block in) {
		in = double_block(in);
		__m128i k_128 = _mm_loadl_epi64( (__m128i const *) (&id));
		in = xorBlocks(in, k_128);
		block t = in;
		pi.permute_block(&t, 1);
		in =  xorBlocks(in, t);
		return in;	
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
		assert(length%8==0);
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

	void recv_pre(block * data, const bool* r, int length) {
		assert(length%8==0);
		if (length%128 !=0) length = (length/128 + 1)*128;

		if(!setup)setup_recv();
		setup = false;
		block *block_r = new block[length/128];
		for(int i = 0; i < length/128; ++i) {
			block_r[i] = bool_to128(r+i*128);
		}
		// send u
		block* t = new block[length];
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

		sse_trans((uint8_t *)data, (uint8_t*)t, l, length);

		delete[] t;
		delete[] tmp;
		delete[] block_r;
	}

	void got_send_post(const block* data0, const block* data1, int length) {
		block pad[2];
		for(int i = 0; i < length; ++i) {
			pad[1] = xorBlocks(qT[i], block_s);
			H2(pad, 2*i, qT[i], pad[1]);
			pad[0] = xorBlocks(pad[0], data0[i]);
			pad[1] = xorBlocks(pad[1], data1[i]);
			io->send_data(pad, 2*sizeof(block));
		}
	}

	void got_recv_post(block* data, const bool* r, int length) {
		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			//			block tmp = H(i, data[i]);
			if(r[i]) {
				data[i] = xorBlocks(res[1], H(2*i+1, data[i]));
			} else {
				data[i] = xorBlocks(res[0], H(2*i, data[i]));
			}
		}
	}
	void send_impl(const block* data0, const block* data1, int length) {
		send_pre(length);
		got_send_post(data0, data1, length);
		delete[] qT;
	}

	void recv_impl(block* data, const bool* b, int length) {
		recv_pre(data, b, length);
		got_recv_post(data, b, length);
	}

	void send_cot(block * data0, block delta, int length) {
		send_pre(length);
		cot_send_post(data0, delta, length);
		delete[] qT;
	}
	void recv_cot(block* data, const bool* b, int length) {
		recv_pre(data, b, length);
		cot_recv_post(data, b, length);
	}
	void send_rot(block * data0, block * data1, int length) {
		send_pre(length);
		rot_send_post(data0, data1, length);
		delete[] qT;
	}
	void recv_rot(block* data, const bool* b, int length) {
		recv_pre(data, b, length);
		rot_recv_post(data, b, length);
	}

	void cot_send_post(block* data0, block delta, int length) {
		block pad[2];
		for(int i = 0; i < length; ++i) {
			block tmp = xorBlocks(qT[i], block_s);
			H2(pad, 2*i, qT[i], tmp);
			data0[i] = pad[0];
			pad[0] = xorBlocks(pad[0], delta);
			pad[0] = xorBlocks(pad[1], pad[0]);
			io->send_data(pad, sizeof(block));
		}
	}

	void cot_recv_post(block* data, const bool* r, int length) {
		block res;
		for(int i = 0; i < length; ++i) {
			io->recv_data(&res, sizeof(block));
			if(r[i])
				data[i] = xorBlocks(res, H(2*i+1, data[i]));
			else 
				data[i] = H(2*i, data[i]);
		}
	}
	
	//hash function is inlined
	void rot_send_post(block* data0, block* data1, int length) {
		block * tmp0 = new block[length],
	 	      * tmp1 = new block[length];
		uint64_t id = 0;
		for(int i = 0; i < length; ++i) {
			data0[i] = double_block(qT[i]);
			data1[i] = double_block(xorBlocks(qT[i], block_s));
			tmp0[i] = data0[i] = xorBlocks(data0[i], _mm_loadl_epi64( (__m128i const *) (&id)));
			id++;
			tmp1[i] = data1[i] = xorBlocks(data1[i], _mm_loadl_epi64( (__m128i const *) (&id)));
			id++;
		}
		pi.permute_block(tmp0, length);
		pi.permute_block(tmp1, length);
		xorBlocks_arr(data0, data0, tmp0, length);
		xorBlocks_arr(data1, data1, tmp1, length);
		delete[] tmp0;
		delete[] tmp1;
	}

	//hash function is inlined
	void rot_recv_post(block* data, const bool* r, int length) {
		block * tmp = new block[length];
		for(int i = 0; i < length; ++i) {
			data[i] = double_block(data[i]);
			uint64_t id = 2*i+r[i];
			tmp[i] = data[i] = xorBlocks(data[i], _mm_loadl_epi64( (__m128i const *) (&id)));
		}
		pi.permute_block(tmp, length);
		xorBlocks_arr(data, data, tmp, length);
		delete[] tmp;
	}
};
#endif// OT_EXTENSION_H__