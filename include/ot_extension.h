#ifndef OT_EXTENSION_H__
#define OT_EXTENSION_H__
#include "ot.h"
#include "ot_co.h"
#include "ot_np.h"
#include "ot_ideal.h"

void ot_extension_send(OT* ot, const block*, const block*, int length);
void ot_extension_recv(OT* ot, block* data, const bool* b, int length);

#define KAPPA 128
class OTExtension: public OT { public:
	OT * base_ot;
	PRG prg;
	PRP pi;
	int l, ssp;

	block *k0, *k1;
	bool *s;

	uint8_t * qT, *tT, *q=nullptr, **t, *block_s;
	int u = 0;
	bool setup = false;
	OTExtension(NetIO * io, int ssp = 0): OT(io) , ssp(ssp){
		type = OT_EXTENSION;
		send_internal = ot_extension_send;
		recv_internal = ot_extension_recv;
		if(ssp==40) {
			this->l = 192;
			u = 2;
			this->base_ot = new OTCO(io);
//			this->base_ot = new OTIdeal(io);
		} else if (ssp == 0) {
			this->l = KAPPA;
			this->base_ot = new OTNP(io);
		}
		this->s = new bool[l];
		this->k0 = new block[l];
		this->k1 = new block[l];
		block_s = new uint8_t[l/8];
	}

	~OTExtension() {
		delete base_ot;
		delete[] s;
		delete[] k0;
		delete[] k1;
		delete[] block_s;
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
		if(in_s != nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(s, in_s, l);
			bool_to_uint8(block_s, s, l);
			setup=true;
			return;
		}
		uint8_t * tmp = new uint8_t[l];
		prg.random_data(tmp, l);
		//base ot
		for(int i = 0; i < l; ++i) 
			s[i] = (tmp[i]%2==1);
		base_ot->recv(k0, s, l);
		bool_to_uint8(block_s, s, l);
		setup = true;
		delete[] tmp;
	}
	void setup_recv(block * in_k0 = nullptr, block * in_k1 =nullptr) {
		if(in_k0 !=nullptr) {
			memcpy(k0, in_k0, l*sizeof(block));
			memcpy(k1, in_k1, l*sizeof(block));
			setup=true;
			return;
		}
		prg.random_block(k0, l);
		prg.random_block(k1, l);
		base_ot->send(k0, k1, l);
		setup = true;
	}
};

void ot_extension_send_pre(OT* ot, int length) {
	assert(length%8==0);
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;

	ote->q = new uint8_t[length/8*ote->l];
	if(!ote->setup)ote->setup_send();
	ote->setup = false;
	//get u, compute q
	ote->qT = new uint8_t[length/8*ote->l];
	uint8_t * q2 = new uint8_t[length/8*ote->l];
	uint8_t*tmp = new uint8_t[length/8];
	PRG G;
	for(int i = 0; i < ote->l; ++i) {
		ote->io->recv_data(tmp, length/8);
		G.reseed(&ote->k0[i]);
		G.random_data(ote->q+(i*length/8), length/8);
		if (ote->s[i])
			ote->xor_arr(q2+(i*length/8), ote->q+(i*length/8), tmp, length/8);
		else
			memcpy(q2+(i*length/8), ote->q+(i*length/8), length/8);
	}
	sse_trans(ote->qT, q2, ote->l, length);
	delete[] tmp;
	delete[] q2;
}


void ot_extension_recv_pre(OT* ot, block * data, const bool* r, int length) {
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;
	if(!ote->setup)ote->setup_recv();
	ote->setup = false;
	uint8_t *block_r = new uint8_t[length/8];
	ote->bool_to_uint8(block_r, r, length);
	// send u
	ote->t = new uint8_t*[2];
	ote->t[0] = new uint8_t[length/8*ote->l];
	ote->t[1] = new uint8_t[length/8*ote->l];
	ote->tT = new uint8_t[length/8*ote->l];
	uint8_t* tmp = new uint8_t[length/8];
	PRG G;
	for(int i = 0; i < ote->l; ++i) {
		G.reseed(&ote->k0[i]);
		G.random_data(&(ote->t[0][i*length/8]), length/8);
		G.reseed(&ote->k1[i]);
		G.random_data(ote->t[1]+(i*length/8), length/8);
		ote->xor_arr(tmp, ote->t[0]+(i*length/8), ote->t[1]+(i*length/8), length/8);
		ote->xor_arr(tmp, block_r, tmp, length/8);
		ote->io->send_data(tmp, length/8);
	}

	sse_trans(ote->tT, ote->t[0], ote->l, length);

	delete[] tmp;
	delete[] block_r;
}

void ot_extension_send_post(OT* ot, const block* data0, const block* data1, int length) {
	int old_length = length;
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;
	//	uint8_t *pad0 = new uint8_t[ote->l/8];
	uint8_t *pad1 = new uint8_t[ote->l/8];
	block pad[2];
	for(int i = 0; i < old_length; ++i) {
		ote->xor_arr(pad1, ote->qT+i*ote->l/8, ote->block_s, ote->l/8);
		pad[0] = xorBlocks( ote->H(ote->qT+i*ote->l/8, i, ote->l/8), data0[i]);
		pad[1] = xorBlocks( ote->H(pad1, i, ote->l/8), data1[i]);
		ote->io->send_data(pad, 2*sizeof(block));
	}
	delete[] pad1;
	delete[] ote->qT;
}

void ot_extension_recv_post(OT* ot, block* data, const bool* r, int length) {
	int old_length = length;
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;
	block res[2];
	for(int i = 0; i < old_length; ++i) {
		ote->io->recv_data(res, 2*sizeof(block));
		block tmp = ote->H(ote->tT+i*ote->l/8, i, ote->l/8);
		if(r[i]) {
			data[i] = xorBlocks(res[1], tmp);
		} else {
			data[i] = xorBlocks(res[0], tmp);
		}
	}
	delete[] ote->tT;
}

void cot_extension_send_post(OT* ot, const block* data0, const block* data1, int length) {
	int old_length = length;
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;
	//	uint8_t *pad0 = new uint8_t[ote->l/8];
	uint8_t *pad1 = new uint8_t[ote->l/8];
	block pad[2];
	for(int i = 0; i < old_length; ++i) {
		ote->xor_arr(pad1, ote->qT+i*ote->l/8, ote->block_s, ote->l/8);
		pad[0] = xorBlocks( ote->H(ote->qT+i*ote->l/8, i, ote->l/8), data0[i]);
		pad[1] = xorBlocks( ote->H(pad1, i, ote->l/8), data1[i]);
		ote->io->send_data(pad, 2*sizeof(block));
	}
	delete[] pad1;
	delete[] ote->qT;
}

void cot_extension_recv_post(OT* ot, block* data, const bool* r, int length) {
	int old_length = length;
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;
	block res[2];
	for(int i = 0; i < old_length; ++i) {
		ote->io->recv_data(res, 2*sizeof(block));
		block tmp = ote->H(ote->tT+i*ote->l/8, i, ote->l/8);
		if(r[i]) {
			data[i] = xorBlocks(res[1], tmp);
		} else {
			data[i] = xorBlocks(res[0], tmp);
		}
	}
	delete[] ote->tT;
}

/*
void cot_extension_send_post(OT* ot, block* data0, block delta, int length) {
  OTExtension *ote = (OTExtension* )ot;
  block pad[2];
  for(int i = 0; i < length; ++i) {
  pad[1] = xorBlocks(ote->qT[i], ote->block_s);
  ote->H2(pad, i, ote->qT[i], pad[1]);
  data0[i] = pad[0];
  pad[0] = xorBlocks(pad[0], delta);
  pad[0] = xorBlocks(pad[1], pad[0]);
  ote->io->send_data(pad, sizeof(block));
  }
  delete[] ote->qT;
  }

  void cot_extension_recv_post(OT* ot, block* data, const bool* r, int length) {
  OTExtension *ote = (OTExtension* )ot;
  block res;
  for(int i = 0; i < length; ++i) {
  ote->io->recv_data(&res, sizeof(block));
  if(r[i]) {
  data[i] = xorBlocks(res, ote->H(i, data[i]));
  } else {
  data[i] = ote->H(i, data[i]);
  }
  }
  }
 */
void ot_extension_recv_check(OT*ot, int length) {
	if (length%128 !=0) length = (length/128 + 1)*128;
	OTExtension *ote = (OTExtension* )ot;
	block seed; PRG prg;int beta;
	uint8_t * tmp = new uint8_t[length/8];
	char dgst[20];
	for(int i = 0; i < ote->u; ++i) {
		ote->io->recv_block(&seed, 1);
		prg.reseed(&seed);
		for(int j = 0; j < ote->l; ++j) {
			prg.random_data(&beta, 4);
			beta = beta>0?beta:-1*beta;
			beta %= ote->l;
			for(int k = 0; k < 2; ++k)
				for(int l = 0; l < 2; ++l) {
					ote->xor_arr(tmp, ote->t[k]+(j*length/8), ote->t[l]+(beta*length/8), length/8);
					Hash::hash_once(dgst, tmp, length/8);
					ote->io->send_data(dgst, 20);
				}
		}
	}
	delete []tmp;
}

bool ot_extension_send_check(OT*ot, int length) {
	if (length%128 !=0) length = (length/128 + 1)*128;
	bool cheat = false;
	OTExtension *ote = (OTExtension* )ot;
	PRG prg, sprg; block seed;int beta;
	char dgst[2][2][20]; char dgstchk[20];
	uint8_t * tmp = new uint8_t[length/8];
	for(int i = 0; i < ote->u; ++i) {
		prg.random_block(&seed, 1);
		ote->io->send_block(&seed, 1);
		sprg.reseed(&seed);
		for(int j = 0; j < ote->l; ++j) {
			sprg.random_data(&beta, 4);
			beta = beta>0?beta:-1*beta;
			beta %= ote->l;
			ote->io->recv_data(dgst[0][0], 20);
			ote->io->recv_data(dgst[0][1], 20);
			ote->io->recv_data(dgst[1][0], 20);
			ote->io->recv_data(dgst[1][1], 20);

			int ind1 = ote->s[j]? 1:0;
			int ind2 = ote->s[beta]? 1:0;
			ote->xor_arr(tmp, ote->q+(j*length/8), ote->q+(beta*length/8), length/8);
			Hash::hash_once(dgstchk, tmp, length/8);	
			if (strncmp(dgstchk, dgst[ind1][ind2], 20)!=0)
				cheat = true;
		}
	}
	delete[] tmp;
	return cheat;
}

void ot_extension_send(OT*ot, const block* data0, const block* data1, int length) {
	OTExtension *ote = (OTExtension* )ot;
	ot_extension_send_pre(ot, length);
	if(ote->ssp!=0)
		assert(!ot_extension_send_check(ot, length)?"T":"F");
	delete[] ote->q; ote->q = nullptr;
	ot_extension_send_post(ot, data0, data1, length);
}

void ot_extension_recv(OT* ot, block* data, const bool* b, int length) {
	OTExtension *ote = (OTExtension* )ot;
	ot_extension_recv_pre(ot, data, b, length);
	if(ote->ssp!=0)
		ot_extension_recv_check(ot, length);
	delete[] ote->t[0];
	delete[] ote->t[1];
	delete[] ote->t;
	ot_extension_recv_post(ot, data, b, length);
}
#endif// OT_EXTENSION_H__