#ifndef OT_EXTENSION_H__
#define OT_EXTENSION_H__
#include "emp-ot/ot.h"
/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO, template<typename> class BaseOT, template<typename> class OTE>
class OTExtension: public OT<OTExtension<IO, BaseOT, OTE>> { public:
	BaseOT<IO> * base_ot;
	PRG prg;
	const int l = 128;
	const int block_size = 1024*16;

	block *k0 = nullptr, *k1 = nullptr, 
			* qT  = nullptr, *tT = nullptr, *tmp = nullptr, block_s;
	PRG *G0, *G1;
	bool *s = nullptr, * extended_r = nullptr, setup = false;
	IO *io = nullptr;
	int ssp;
	OTExtension(IO * io, int ssp = 0) {
		this->io = io;
		this->ssp = ssp;
		base_ot = new BaseOT<IO>(io);
		s = new bool[l];
		k0 = new block[l];
		k1 = new block[l];
		G0 = new PRG[l];
		G1 = new PRG[l];
		tmp = new block[block_size/128];
		extended_r = new bool[block_size];
	}

	~OTExtension() {
		delete base_ot;
		delete[] s;
		delete[] k0;
		delete[] k1;
		delete[] G0;
		delete[] G1;
		delete[] tmp;
		delete[] extended_r;
	}

	void setup_send(block * in_k0 = nullptr, bool * in_s = nullptr) {
		setup = true;
		if(in_s != nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(s, in_s, l);
			block_s = bool_to128(s);
		} else {
			prg.random_bool(s, l);
			base_ot->recv(k0, s, l);
			block_s = bool_to128(s);
		}
		for(int i = 0; i < l; ++i)
			G0[i].reseed(&k0[i]);
	}

	void setup_recv(block * in_k0 = nullptr, block * in_k1 =nullptr) {
		setup = true;
		if(in_k0 !=nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(k1, in_k1, l*sizeof(block));
		} else {
			prg.random_block(k0, l);
			prg.random_block(k1, l);
			base_ot->send(k0, k1, l);
		}
		for(int i = 0; i < l; ++i) {
			G0[i].reseed(&k0[i]);
			G1[i].reseed(&k1[i]);
		}
	}

	int padded_length(int length){
		return ((length + ssp + block_size - 1) / block_size) * block_size;
	}

	void send_pre(int length) {
		length = padded_length(length);
		block q[block_size];
		qT = new block[length];
		if(!setup) setup_send();

		for (int j = 0; j < length/block_size; ++j) {
			for(int i = 0; i < l; ++i) {
				G0[i].random_data(q+(i*block_size/128), block_size/8);
				io->recv_data(tmp, block_size/8);
				if (s[i])
					xorBlocks_arr(q+(i*block_size/128), q+(i*block_size/128), tmp, block_size/128);
			}
			sse_trans((uint8_t *)(qT+j*block_size), (uint8_t*)q, 128, block_size);
		}
	}

	void recv_pre(const bool* r, int length) {
		int old_length = length;
		length = padded_length(length);
		block t[block_size];
		tT = new block[length];

		if(not setup) setup_recv();

		bool * r2 = new bool[length];
		prg.random_bool(extended_r, block_size);
		memcpy(r2, r, old_length);
		memcpy(r2+old_length, extended_r, length - old_length);

		block *block_r = new block[length/128];
		for(int i = 0; i < length/128; ++i) {
			block_r[i] = bool_to128(r2+i*128);
		}

		for (int j = 0; j * block_size < length; ++j) {
			for(int i = 0; i < l; ++i) {
				G0[i].random_data(t+(i*block_size/128), block_size/8);
				G1[i].random_data(tmp, block_size/8);
				xorBlocks_arr(tmp, t+(i*block_size/128), tmp, block_size/128);
				xorBlocks_arr(tmp, block_r+(j*block_size/128), tmp, block_size/128);
				io->send_data(tmp, block_size/8);
			}
			sse_trans((uint8_t *)(tT+j*block_size), (uint8_t*)t, 128, block_size);
		}

		delete[] block_r;
		delete[] r2;
	}

	void send_impl(const block* data0, const block* data1, int length) {
		static_cast<OTE<IO>*>(this)->send_impl(data0, data1, length);
	}

	void recv_impl(block* data, const bool* b, int length) {
		static_cast<OTE<IO>*>(this)->recv_impl(data, b, length);
	}

};
  /**@}*/
}
#endif// OT_EXTENSION_H__
