#ifndef OT_SH_EXTENSION_H__
#define OT_SH_EXTENSION_H__
#include "ot.h"
#include "ot_co.h"

class MOTExtension2: public OT<MOTExtension2> { public:
	OTCO * base_ot;
	PRG prg;
	PRP pi;
	const int l = 128;
	block *k0, *k1;
	bool *s;

	block * qT, block_s, *tT;
	bool setup = false;
	int ssp;
	bool * extended_r = nullptr;
	MOTExtension2(NetIO * io, int ssp = 40): OT(io) {
		this->base_ot = new OTCO(io);
		this->ssp = ssp;
		this->s = new bool[l];
		this->k0 = new block[l];
		this->k1 = new block[l];
	}

	~MOTExtension2() {
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
		length = ((length+128+ssp+127)/128)*128;

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
		length = ((length+128+ssp+127)/128)*128;

		if(!setup)setup_recv();
		setup = false;
		bool * r2 = new bool[length];
		memcpy(r2, r, old_length);
		extended_r = new bool[length - old_length];
		prg.random_bool(extended_r, length- old_length);
		memcpy(r2+old_length, extended_r, length - old_length);

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

	bool send_check(int length) {
		int extended_length = ((length+128+ssp+127)/128)*128;
		block seed2, x, t[2], q[2], tmp1, tmp2;
		io->recv_block(&seed2, 1);
		block *chi = new block[extended_length];
		PRG prg2(&seed2);
		prg2.random_block(chi, extended_length);

		q[0] = zero_block();
		q[1] = zero_block();
		for(int i = 0; i < extended_length; ++i) {
			mul128(qT[i], chi[i], &tmp1, &tmp2);
			q[0] = xorBlocks(q[0], tmp1);
			q[1] = xorBlocks(q[1], tmp2);
		}
		io->recv_block(&x, 1);
		io->recv_block(t, 2);

		mul128(x, block_s, &tmp1, &tmp2);
		q[0] = xorBlocks(q[0], tmp1);
		q[1] = xorBlocks(q[1], tmp2);

		delete[] chi;
		return block_cmp(q, t, 2);	
	}
	void recv_check(const bool* r, int length) {
		int extended_length = ((length+128+ssp+127)/128)*128;
		block *chi = new block[extended_length];
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
			mul128(chi[i], tT[i], &tmp1, &tmp2);
			t[0] = xorBlocks(t[0], tmp1);
			t[1] = xorBlocks(t[1], tmp2);
		}
		io->send_block(t, 2);

		delete[] chi;
		delete[] extended_r;
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
		delete[] qT;
	}

	void got_recv_post(block* data, const bool* r, int length) {
		block res[2];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			if(r[i]) {
				data[i] = xorBlocks(res[1], H(2*i+1, tT[i]));
			} else {
				data[i] = xorBlocks(res[0], H(2*i, tT[i]));
			}
		}
		delete[] tT;
	}
	void send_impl(const block* data0, const block* data1, int length) {
		send_pre(length);
		if(!send_check(length)) {
			cout <<"OT Extension check failed"<<endl<<flush;
			exit(0);
		}
		got_send_post(data0, data1, length);
	}

	void recv_impl(block* data, const bool* b, int length) {
		recv_pre(b, length);
		recv_check(b, length);
		got_recv_post(data, b, length);
	}

	void send_rot(block * data0, block * data1, int length) {
		send_pre(length);
		send_check(length);
		if(!send_check(length)) {
			cout <<"OT Extension check failed"<<endl<<flush;
			exit(0);
		}
		rot_send_post(data0, data1, length);
	}
	void recv_rot(block* data, const bool* b, int length) {
		recv_pre(b, length);
		recv_check(b, length);
		rot_recv_post(data, b, length);
	}

	void rot_send_post(block* data0, block* data1, int length) {
		for(int i = 0; i < length; ++i) {
			data0[i] = H(2*i, qT[i]);
			data1[i] = H(2*i+1, xorBlocks(qT[i], block_s));
		}
		delete[] qT;
	}

	void rot_recv_post(block* data, const bool* r, int length) {
		for(int i = 0; i < length; ++i)
			data[i] = H(2*i+r[i], tT[i]);
		delete[] tT;
	}

	/**
	  University of Bristol : Open Access Software Licence

	  Copyright (c) 2016, The University of Bristol, a chartered corporation having Royal Charter number RC000648 and a charity (number X1121) and its place of administration being at Senate House, Tyndall Avenue, Bristol, BS8 1TH, United Kingdom.

	  All rights reserved

	  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

	  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


	  Any use of the software for scientific publications or commercial purposes should be reported to the University of Bristol (OSI-notifications@bristol.ac.uk and quote reference 1914). This is for impact and usage monitoring purposes only.

	  Enquiries about further applications and development opportunities are welcome. Please contact nigel@cs.bris.ac.uk

	  Contact GitHub API Training Shop Blog About
	 */
	inline void mul128(__m128i a, __m128i b, __m128i *res1, __m128i *res2) {
	/*	block a0xora1 = xorBlocks(a, _mm_srli_si128(a, 8));
		block b0xorb1 = xorBlocks(b, _mm_srli_si128(b, 8));

		block a0b0 = _mm_clmulepi64_si128(a, b, 0x00);
		block a1b1 = _mm_clmulepi64_si128(a, b, 0x11);
		block ab = _mm_clmulepi64_si128(a0xora1, b0xorb1, 0x00);

		block tmp = xorBlocks(a0b0, a1b1);
		tmp = xorBlocks(tmp, ab);
		
		*res1 = xorBlocks(a1b1, _mm_srli_si128(tmp, 8));
		*res2 = xorBlocks(a0b0, _mm_slli_si128(tmp, 8));
	}*/
	    __m128i tmp3, tmp4, tmp5, tmp6;

    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    // initial mul now in tmp3, tmp6
    *res1 = tmp3;
    *res2 = tmp6;
}
	
	
};
#endif// OT_EXTENSION_H__