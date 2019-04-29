#ifndef DELTA_OT_H__
#define DELTA_OT_H__
#include "co.h"
#include <boost/align/aligned_alloc.hpp>
#include <immintrin.h>
namespace emp {

template<typename T>
	T* aalloc(int length) {
		return (T*)boost::alignment::aligned_alloc(sizeof(T), sizeof(T)*length);
	}
inline void afree(void* p) {
	boost::alignment::aligned_free(p);
}

class DeltaOT { 
public:

#ifdef __GNUC__
	#ifndef __clang__
		#pragma GCC push_options
		#pragma GCC optimize ("unroll-loops")
	#endif
#endif

	inline block bit_matrix_mul(const block * input) {
		uint8_t * tmp = (uint8_t *) (input);
		block res = pre_table[tmp[0] + (0<<8)];
		for(int i = 1; i < l/8; ++i)
			res = xorBlocks(res, pre_table[tmp[i] + (i<<8)]);
		return res;
	}

#ifdef __GNUC_
	#ifndef __clang___
		#pragma GCC pop_options
	#endif
#endif

	block *pre_table = nullptr;
	NetIO * io = nullptr;
	OTCO<NetIO> * base_ot = nullptr;
	PRG prg, *G0 = nullptr, *G1 = nullptr;
	PRP pi;
	bool setup = false;
	block *k0 = nullptr, *k1 = nullptr, *tmp = nullptr, *t = nullptr;
	bool *s = nullptr, *extended_r = nullptr;
	block  *tT = nullptr;
	block block_s[2];
	block Delta;
	int l = 128, ssp, sspover8;
	const static int block_size = 1024;
	DeltaOT(NetIO * io, block * pretable, int ssp = 40) {
		this->pre_table = pretable;
		this->io = io;
		this->ssp = ssp;
		this->base_ot = new OTCO<NetIO>(io);
		this->sspover8 = ssp/8;
		this->l +=ssp;
		this->s = new bool[l];
		this->k0 = aalloc<block>(l);
		this->k1 = aalloc<block>(l);
		this->G0 = new PRG[l];
		this->G1 = new PRG[l];
		this->tT = aalloc<block>(block_size*2);
		this->t = aalloc<block>(block_size*2);
		this->tmp = aalloc<block>(block_size/128);
		memset(t, 0, block_size * 32);
	}
	static block * preTable(int ssp) {
		block *pretable = aalloc<block>((1<<8) * 256/8);
		block * R = aalloc<block>(128*2);
		PRG prg2(fix_key);
		prg2.random_data(R, 128*256/8);
		uint64_t hi = 0ULL, lo = 0ULL;
		if(ssp <=64) {hi=0;lo=((1ULL<<ssp)-1);}
		block mask = makeBlock(hi,lo);
		for(int i = 0; i < 128; ++i)
			R[2*i+1] = andBlocks(R[2*i+1], mask);
		block tR[256];
		sse_trans((uint8_t *)(tR), (uint8_t*)R, 128, 256);
		for(int i = 0; i < 256/8; ++i)
			for (int j = 0; j < (1<<8); ++j) {
				pretable[j + (i<<8)] = zero_block();
				for(int k = 0; k < 8; ++k) {
					if (((j >> k ) & 0x1) == 1)
						pretable[j + (i<<8)] = xorBlocks(pretable[j+ (i<<8)], tR[i*8+k]);
				}
			}
		afree(R);
		return pretable;
	}

	block * out = nullptr;
	~DeltaOT() {
		delete base_ot;
		delete_array_null(s);
		delete_array_null(G0);
		delete_array_null(G1);
		afree(this->t);
		afree(this->tT);
		afree(k0);
		afree(k1);
		afree(tmp);
		delete_array_null(extended_r);
	}

	void bool_to256(const bool * in, block res[2]) {
		bool tmpB[256];
		for(int i = 0; i < 256; ++i)tmpB[i] = false;
		memcpy(tmpB, in, l);
		res[0] = bool_to128(tmpB);
		res[1] = bool_to128(tmpB+128);
	}

	void setup_send(const bool* in_s, block * in_k0 = nullptr) {
		setup = true;
		memcpy(s, in_s, l);
		if(in_k0 != nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
		} else {
			base_ot->recv(k0, s, l);
		}
		for(int i = 0; i < l; ++i)
			G0[i].reseed(&k0[i]);

		bool_to256(s, block_s);
		Delta = bit_matrix_mul(block_s);
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
		return ((length+128+ssp+block_size-1)/block_size)*block_size;
	}
	void send_pre(int length) {
		length = padded_length(length);
		assert(setup);

		for (int j = 0; j < length/block_size; ++j) {
			for(int i = 0; i < l; ++i) {
				io->recv_data(tmp, block_size/8);
				G0[i].random_data(t+(i*block_size/128), block_size/8);
				if (s[i])
					xorBlocks_arr(t+(i*block_size/128), t+(i*block_size/128), tmp, block_size/128);
			}
			sse_trans((uint8_t *)(tT), (uint8_t*)t, 256, block_size);
			for(int i = 0; i < block_size; ++i)
				out[j*block_size + i] = bit_matrix_mul(tT+2*i);
		}
	}

	void recv_pre(const bool* r, int length) {
		int old_length = length;
		length = padded_length(length);

		assert(setup);

		bool * r2 = new bool[length];
		memcpy(r2, r, old_length);
		delete_array_null(extended_r);
		extended_r = new bool[length - old_length];
		prg.random_bool(extended_r, length- old_length);
		memcpy(r2+old_length, extended_r, length - old_length);

		block *block_r = aalloc<block>(length/128);
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
			sse_trans((uint8_t *)tT, (uint8_t*)t, 256, block_size);

			for(int i = 0; i < block_size; ++i)
				out[j*block_size + i] = bit_matrix_mul(tT+2*i);
		}
		free(block_r);
		delete[] r2;
	}

	void send(block * data, int length) {
		out = aalloc<block>(padded_length(length));
		send_pre(length);
		if(!send_check(length))
			error("OT Extension check failed");
		memcpy(data, out, sizeof(block)*length);
		free(out);
	}
	void recv(block* data, const bool* b, int length) {
		out = aalloc<block>(padded_length(length));
		recv_pre(b, length);
		recv_check(b, length);
		memcpy(data, out, sizeof(block)*length);
		free(out);
	}

	bool send_check(int length) {
		int extended_length = padded_length(length);
		block seed2, x, t[2], q[2], tmp1, tmp2;
		io->recv_block(&seed2, 1);
		block *chi = aalloc<block>(extended_length);
		PRG prg2(&seed2);
		prg2.random_block(chi, extended_length);

		q[0] = zero_block();
		q[1] = zero_block();
		for(int i = 0; i < extended_length; ++i) {
			mul128(out[i], chi[i], &tmp1, &tmp2);
			q[0] = xorBlocks(q[0], tmp1);
			q[1] = xorBlocks(q[1], tmp2);
		}
		io->recv_block(&x, 1);
		io->recv_block(t, 2);

		mul128(x, Delta, &tmp1, &tmp2);
		q[0] = xorBlocks(q[0], tmp1);
		q[1] = xorBlocks(q[1], tmp2);

		free(chi);
		return block_cmp(q, t, 2);	
	}
	void recv_check(const bool* r, int length) {
		int extended_length = padded_length(length);
		block *chi = aalloc<block>(extended_length);
		block seed2, x = zero_block(), t[2], tmp1, tmp2;
		prg.random_block(&seed2,1);
		io->send_block(&seed2, 1);
		PRG prg2(&seed2);
		t[0] = t[1] = zero_block();
		prg2.random_block(chi,extended_length);
		for(int i = 0 ; i < length; ++i) {
			if(r[i])
				x = xorBlocks(x, chi[i]);
		}
		for(int i = 0 ; i < extended_length - length; ++i) {
			if(extended_r[i])
				x = xorBlocks(x, chi[i+length]);
		}

		io->send_block(&x, 1);
		for(int i = 0 ; i < extended_length; ++i) {
			mul128(chi[i], out[i], &tmp1, &tmp2);
			t[0] = xorBlocks(t[0], tmp1);
			t[1] = xorBlocks(t[1], tmp2);
		}
		io->send_block(t, 2);

		free(chi);
	}
};
}
#endif// ABIT_H__
