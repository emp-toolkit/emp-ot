#ifndef OT_M_EXTENSION_ALSZ_H__
#define OT_M_EXTENSION_ALSZ_H__
#include "emp-ot/ot.h"
#include "emp-ot/co.h"

/** @addtogroup OT
    @{
  */
namespace emp {
template<typename IO>
class MOTExtension_ALSZ: public OT<MOTExtension_ALSZ<IO>> { public:
	OTCO<IO> * base_ot;
	PRG prg;
	PRP pi;
	int l, ssp;

	block *k0, *k1, * data_open = nullptr;
	bool *s;

	uint8_t * qT, *tT, *q = nullptr, **t, *block_s;
	int u = 0;
	bool setup = false;
	bool committing = false;
	char com[Hash::DIGEST_SIZE];
	IO* io = nullptr;
	MOTExtension_ALSZ(IO * io, bool committing = false, int ssp = 40): ssp(ssp){
		this->io = io;
		this->l = 192;
		u = 2;
		this->base_ot = new OTCO<IO>(io);
		this->s = new bool[l];
		this->k0 = new block[l];
		this->k1 = new block[l];
		block_s = new uint8_t[l/8];
		this->committing = committing;
	}

	~MOTExtension_ALSZ() {
		delete base_ot;
		delete[] s;
		delete[] k0;
		delete[] k1;
		delete[] block_s;
		if(data_open != nullptr) {
			delete[] data_open;
		}
	}

	void xor_arr (uint8_t * a, uint8_t * b, uint8_t * c, int n) {
		if(n%16 == 0)
			xorBlocks_arr((block*)a, (block *)b, (block*)c, n/16);
		else {
			uint8_t* end_a = a + n;
			for(;a!= end_a;)
				*(a++) = *(b++) ^ *(c++);
		}
	}

	block H(uint8_t* in, long id, int len) {
		block res = zero_block();
		for(int i = 0; i < len/16; ++i) {
			res = xorBlocks(res, pi.H(_mm_loadl_epi64((block *)(in)), id));
			in+=16;
		}
		return res;	
	}

	void bool_to_uint8(uint8_t * out, const bool*in, int len) {
		for(int i = 0; i < len/8; ++i)
			out[i] = 0;
		for(int i = 0; i < len; ++i)
			if(in[i])
				out[i/8]|=(1<<(i%8));
	}
	void setup_send(block * in_k0 = nullptr, bool * in_s = nullptr){
		setup = true;
		if(in_s != nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(s, in_s, l);
			bool_to_uint8(block_s, s, l);
			return;
		}
		prg.random_bool(s, l);
		base_ot->recv(k0, s, l);
		bool_to_uint8(block_s, s, l);
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
		setup = true;
	}

	void ot_extension_send_pre(int length) {
		assert(length%8==0);
		if (length%128 !=0) length = (length/128 + 1)*128;

		q = new uint8_t[length/8*l];
		if(!setup)setup_send();
		setup = false;
		if(committing) {
			Hash::hash_once(com, s, l);		
			io->send_data(com, Hash::DIGEST_SIZE);
		}
		//get u, compute q
		qT = new uint8_t[length/8*l];
		uint8_t * q2 = new uint8_t[length/8*l];
		uint8_t*tmp = new uint8_t[length/8];
		PRG G;
		for(int i = 0; i < l; ++i) {
			io->recv_data(tmp, length/8);
			G.reseed(&k0[i]);
			G.random_data(q+(i*length/8), length/8);
			if (s[i])
				xor_arr(q2+(i*length/8), q+(i*length/8), tmp, length/8);
			else
				memcpy(q2+(i*length/8), q+(i*length/8), length/8);
		}
		sse_trans(qT, q2, l, length);
		delete[] tmp;
		delete[] q2;
	}

	void ot_extension_recv_pre(block * data, const bool* r, int length) {
		int old_length = length;
		if (length%128 !=0) length = (length/128 + 1)*128;
		if(!setup)setup_recv();
		setup = false;
		if(committing) {
			io->recv_data(com, Hash::DIGEST_SIZE);
		}
		uint8_t *block_r = new uint8_t[length/8];
		bool_to_uint8(block_r, r, old_length);
		// send u
		t = new uint8_t*[2];
		t[0] = new uint8_t[length/8*l];
		t[1] = new uint8_t[length/8*l];
		tT = new uint8_t[length/8*l];
		uint8_t* tmp = new uint8_t[length/8];
		PRG G;
		for(int i = 0; i < l; ++i) {
			G.reseed(&k0[i]);
			G.random_data(&(t[0][i*length/8]), length/8);
			G.reseed(&k1[i]);
			G.random_data(t[1]+(i*length/8), length/8);
			xor_arr(tmp, t[0]+(i*length/8), t[1]+(i*length/8), length/8);
			xor_arr(tmp, block_r, tmp, length/8);
			io->send_data(tmp, length/8);
		}

		sse_trans(tT, t[0], l, length);

		delete[] tmp;
		delete[] block_r;
	}

	void ot_extension_send_post(const block* data0, const block* data1, int length) {
		int old_length = length;
		if (length%128 !=0) length = (length/128 + 1)*128;
		//	uint8_t *pad0 = new uint8_t[l/8];
		uint8_t *pad1 = new uint8_t[l/8];
		block pad[2];
		for(int i = 0; i < old_length; ++i) {
			xor_arr(pad1, qT+i*l/8, block_s, l/8);
			pad[0] = xorBlocks( H(qT+i*l/8, i, l/8), data0[i]);
			pad[1] = xorBlocks( H(pad1, i, l/8), data1[i]);
			io->send_data(pad, 2*sizeof(block));
		}
		delete[] pad1;
		delete[] qT;
	}

	void ot_extension_recv_check(int length) {
		if (length%128 !=0) length = (length/128 + 1)*128;
		block seed; PRG prg;int beta;
		uint8_t * tmp = new uint8_t[length/8];
		char dgst[Hash::DIGEST_SIZE];
		for(int i = 0; i < u; ++i) {
			io->recv_block(&seed, 1);
			prg.reseed(&seed);
			for(int j = 0; j < l; ++j) {
				prg.random_data(&beta, 4);
				beta = beta>0?beta:-1*beta;
				beta %= l;
				for(int k = 0; k < 2; ++k)
					for(int l = 0; l < 2; ++l) {
						xor_arr(tmp, t[k]+(j*length/8), t[l]+(beta*length/8), length/8);
						Hash::hash_once(dgst, tmp, length/8);
						io->send_data(dgst, Hash::DIGEST_SIZE);
					}
			}
		}
		delete []tmp;
	}

	void ot_extension_recv_post(block* data, const bool* r, int length) {
		int old_length = length;
		data_open = new block[length];
		if (length%128 !=0) length = (length/128 + 1)*128;
		block res[2];
		for(int i = 0; i < old_length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			block tmp = H(tT+i*l/8, i, l/8);
			if(r[i]) {
				data[i] = xorBlocks(res[1], tmp);
				data_open[i] = res[0];
			} else {
				data[i] = xorBlocks(res[0], tmp);
				data_open[i] = res[1];
			}
		}
		if(!committing) {
			delete[] tT;
			tT=nullptr;
		}
	}
	bool ot_extension_send_check(int length) {
		if (length%128 !=0) length = (length/128 + 1)*128;
		bool cheat = false;
		PRG prg, sprg; block seed;int beta;
		char dgst[2][2][Hash::DIGEST_SIZE]; char dgstchk[Hash::DIGEST_SIZE];
		uint8_t * tmp = new uint8_t[length/8];
		for(int i = 0; i < u; ++i) {
			prg.random_block(&seed, 1);
			io->send_block(&seed, 1);
			sprg.reseed(&seed);
			for(int j = 0; j < l; ++j) {
				sprg.random_data(&beta, 4);
				beta = beta>0?beta:-1*beta;
				beta %= l;
				io->recv_data(dgst[0][0], Hash::DIGEST_SIZE);
				io->recv_data(dgst[0][1], Hash::DIGEST_SIZE);
				io->recv_data(dgst[1][0], Hash::DIGEST_SIZE);
				io->recv_data(dgst[1][1], Hash::DIGEST_SIZE);

				int ind1 = s[j]? 1:0;
				int ind2 = s[beta]? 1:0;
				xor_arr(tmp, q+(j*length/8), q+(beta*length/8), length/8);
				Hash::hash_once(dgstchk, tmp, length/8);	
				if (strncmp(dgstchk, dgst[ind1][ind2], Hash::DIGEST_SIZE)!=0)
					cheat = true;
			}
		}
		delete[] tmp;
		return cheat;
	}

	void send_impl(const block* data0, const block* data1, int length) {
		ot_extension_send_pre(length);
		if (ot_extension_send_check(length)) {
      std::cerr << "ot_extension_send_check failed" << std::endl;
      exit(-1);
    }
		delete[] q; q = nullptr;
		ot_extension_send_post(data0, data1, length);
	}

	void recv_impl(block* data, const bool* b, int length) {
		ot_extension_recv_pre(data, b, length);
		ot_extension_recv_check(length);
		delete[] t[0];
		delete[] t[1];
		delete[] t;
		ot_extension_recv_post(data, b, length);
	}

	void open() {		
		io->send_data(s, l);		
	}		
	//return data[1-b]		
	void open(block * data, const bool * r, int length) {		
		io->recv_data(s, l);		
		char com_recv[Hash::DIGEST_SIZE];		
		Hash::hash_once(com_recv, s, l);		
		if (strncmp(com_recv, com, Hash::DIGEST_SIZE)!= 0)		
			assert(false);		
		bool_to_uint8(block_s, s, l);		
		for(int i = 0; i < length; ++i) {		
			xor_arr(tT+i*l/8, tT+i*l/8, block_s, l/8);		
			block tmp = H(tT+i*l/8, i, l/8);		
			data[i] = xorBlocks(data_open[i], tmp);		
		}		
		delete[] tT;
		delete[] data_open;
		tT=nullptr;	
		data_open = nullptr;	
	}
};
  /**@}*/
}
#endif// OT_M_EXTENSION_ALSZ_H__
