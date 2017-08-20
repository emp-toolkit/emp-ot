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
	PRP pi;
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

	void got_send_post(const block* data0, const block* data1, int length) {
		const int bsize = AES_BATCH_SIZE;
		block pad[2*bsize];
		for(int i = 0; i < length; i+=bsize) {
			for(int j = i; j < i+bsize and j < length; ++j) {
				pad[2*(j-i)] = qT[j];
				pad[2*(j-i)+1] = xorBlocks(qT[j], block_s);
			}
			pi.H<2*bsize>(pad, pad, 2*i);
			for(int j = i; j < i+bsize and j < length; ++j) {
				pad[2*(j-i)] = xorBlocks(pad[2*(j-i)], data0[j]);
				pad[2*(j-i)+1] = xorBlocks(pad[2*(j-i)+1], data1[j]);
			}
			io->send_data(pad, 2*sizeof(block)*min(bsize,length-i));
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

	void cot_send_post(block* data0, block delta, int length) {
		const int bsize = AES_BATCH_SIZE;
		block pad[2*bsize];
		block tmp[2*bsize];
		for(int i = 0; i < length; i+=bsize) {
			for(int j = i; j < i+bsize and j < length; ++j) {
				pad[2*(j-i)] = qT[j];
				pad[2*(j-i)+1] = xorBlocks(qT[j], block_s);
			}
			pi.H<2*bsize>(pad, pad, 2*i);
			for(int j = i; j < i+bsize and j < length; ++j) {
				data0[j] = pad[2*(j-i)];
				pad[2*(j-i)] = xorBlocks(pad[2*(j-i)], delta);
				tmp[j-i] = xorBlocks(pad[2*(j-i)+1], pad[2*(j-i)]);
			}
			io->send_data(tmp, sizeof(block)*min(bsize,length-i));
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
		const int bsize = AES_BATCH_SIZE;
		block pad[2*bsize];
		for(int i = 0; i < length; i+=bsize) {
			for(int j = i; j < i+bsize and j < length; ++j) {
				pad[2*(j-i)] = qT[j];
				pad[2*(j-i)+1] = xorBlocks(qT[j], block_s);
			}
			pi.H<2*bsize>(pad, pad, 2*i);
			for(int j = i; j < i+bsize and j < length; ++j) {
				data0[j] = pad[2*(j-i)];
				data1[j] = pad[2*(j-i)+1];
			}
		}
		delete[] qT;
	}

	void rot_recv_post(block* data, const bool* r, int length) {
		for(int i = 0; i < length; ++i)
			data[i] = pi.H(tT[i], 2*i+r[i]);
		delete[] tT;
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
