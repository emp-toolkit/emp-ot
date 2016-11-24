#ifndef OT_M_EXTENSION_KOS_H__
#define OT_M_EXTENSION_KOS_H__
#include "ot.h"
#include "co.h"

/** @addtogroup OT
  @{
 */
class MOTExtension_KOS: public OT<MOTExtension_KOS> { public:
	OTCO * base_ot;
	PRG prg;
	PRG * G0, *G1;
	PRP pi;
	const int l = 128;
	block *k0 = nullptr, *k1 = nullptr;
	bool *s = nullptr;

	block * qT = nullptr, block_s, *tT = nullptr, *open_data = nullptr;
	bool setup = false;
	int ssp;
	bool * extended_r = nullptr;
	bool committing = false;
	char dgst[Hash::DIGEST_SIZE];
	MOTExtension_KOS(NetIO * io, bool committing = false, int ssp = 40): OT(io) {
		this->base_ot = new OTCO(io);
		this->ssp = ssp;
		this->s = new bool[l];
		this->k0 = new block[l];
		this->k1 = new block[l];
		this->committing = committing;
		G0 = new PRG[l];
		G1 = new PRG[l];
	}

	~MOTExtension_KOS() {
		delete base_ot;
		delete_array_null(s);
		delete_array_null(k0);
		delete_array_null(k1);

		delete_array_null(qT);
		delete_array_null(tT);
		delete_array_null(open_data);
		delete_array_null(extended_r);
	}

	void setup_send(block * in_k0 = nullptr, bool * in_s = nullptr){
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
		for(int i = 0; i < l; ++i) {
			G0[i].reseed(&k0[i]);
		}
	}

	void setup_recv(block * in_k0 = nullptr, block * in_k1 =nullptr) {
		setup = true;
		if(in_k0 !=nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(k1, in_k1, l*sizeof(block));
		}else {
			prg.random_block(k0, l);
			prg.random_block(k1, l);
			base_ot->send(k0, k1, l);
		}
		for(int i = 0; i < l; ++i) {
			G0[i].reseed(&k0[i]);
			G1[i].reseed(&k1[i]);
		}

	}

	void send_pre(int length) {
		length = ((length+128+ssp+127)/128)*128;

		if(!setup) setup_send();
		setup = false;
		if (committing) {
			Hash::hash_once(dgst, &block_s, sizeof(block));
			io->send_data(dgst, Hash::DIGEST_SIZE);
		}
		block q[128], tmp;
		delete_array_null(qT);
		qT = new block[length];
		//get u, compute q
		for(int j = 0; j < length; j+=128) {
			for(int i = 0; i < l; ++i) {
				io->recv_data(&tmp, 16);
				G0[i].random_data(&q[i], 16);
				if (s[i])
					q[i] = xorBlocks(q[i], tmp);
			}
			sse_trans((uint8_t *)(qT+j), (uint8_t*)q, 128, 128);
			//	sse_transS((uint8_t *)(qT+j), (uint8_t*)q);
		}
	}

	void recv_pre(const bool* r, int length) {
		int old_length = length;
		length = ((length+128+ssp+127)/128)*128;

		if(!setup)setup_recv();
		setup = false;
		if (committing) {
			io->recv_data(dgst, Hash::DIGEST_SIZE);
		}
		bool * r2 = new bool[length];
		memcpy(r2, r, old_length);
		delete_array_null(extended_r);
		extended_r = new bool[length - old_length];
		prg.random_bool(extended_r, length- old_length);
		memcpy(r2+old_length, extended_r, length - old_length);

		block *block_r = new block[length/128];
		for(int i = 0; i < length/128; ++i) {
			block_r[i] = bool_to128(r2+i*128);
		}
		// send u
		block t[128], tmp;
		delete_array_null(tT);
		tT = new block[length];
		for(int j = 0; j < length; j+=128) {
			for(int i = 0; i < l; ++i) {
				G0[i].random_block(&t[i], 1);
				G1[i].random_block(&tmp, 1);
				tmp = xorBlocks(t[i], tmp);
				tmp = xorBlocks(tmp, block_r[j/128]);
				io->send_data(&tmp, 16);
			}
//			sse_transS((uint8_t *)(tT+j), (uint8_t*)t);
			sse_trans((uint8_t *)(tT+j), (uint8_t*)t, 128, 128);
		}

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
		delete[] qT; qT = nullptr;
	}

	void got_recv_post(block* data, const bool* r, int length) {
		block res[2];
		delete_array_null(open_data);
		open_data = new block[length];
		for(int i = 0; i < length; ++i) {
			io->recv_data(res, 2*sizeof(block));
			if(r[i]) {
				data[i] = xorBlocks(res[1], pi.H(tT[i], 2*i+1));
				open_data[i] = res[0];
			} else {
				data[i] = xorBlocks(res[0], pi.H(tT[i], 2*i));
				open_data[i] = res[1];
			}
		}
	}
	void send_impl(const block* data0, const block* data1, int length) {
		send_pre(length);
		if(!send_check(length))
			error("OT Extension check failed");
		got_send_post(data0, data1, length);
	}

	void recv_impl(block* data, const bool* b, int length) {
		recv_pre(b, length);
		recv_check(b, length);
		got_recv_post(data, b, length);
	}

	void send_rot(block * data0, block * data1, int length) {
		send_pre(length);
		if(!send_check(length))
			error("OT Extension check failed");
		rot_send_post(data0, data1, length);
	}
	void recv_rot(block* data, const bool* b, int length) {
		recv_pre(b, length);
		recv_check(b, length);
		rot_recv_post(data, b, length);
	}

	void rot_send_post(block* data0, block* data1, int length) {
		block pad[2];
		for(int i = 0; i < length; ++i) {
			pad[0] = qT[i];
			pad[1] = xorBlocks(qT[i], block_s);
			pi.H<2> (pad, pad, 2*i);
			data0[i] = pad[0];
			data1[i] = pad[1];
		}
	}

	void rot_recv_post(block* data, const bool* r, int length) {
		for(int i = 0; i < length; ++i)
			if(r[i])
				data[i] = pi.H(tT[i], 2*i+1);
			else
				data[i] = pi.H(tT[i], 2*i);
	}

	void open() {
		if (!committing)
			error("Committing not enabled");
		io->send_block(&block_s, 1);		
	}

	void open(block * data, const bool * r, int length) {		
		if (!committing)
			error("Committing not enabled");
		io->recv_block(&block_s, 1);		
		char com_recv[Hash::DIGEST_SIZE];		
		Hash::hash_once(com_recv, &block_s, sizeof(block));		
		if (strncmp(com_recv, dgst, 20)!= 0)
			error("invalid commitment");

		for(int i = 0; i < length; ++i) {	
			tT[i] = xorBlocks(tT[i], block_s);
			if(r[i])
				data[i] = xorBlocks(open_data[i], pi.H(tT[i], 2*i));
			else	
				data[i] = xorBlocks(open_data[i], pi.H(tT[i], 2*i+1));
		}		
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
		 *res2 = xorBlocks(a0b0, _mm_slli_si128(tmp, 8));*/
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

/**@}*/
#endif// OT_M_EXTENSION_KOS_H__
