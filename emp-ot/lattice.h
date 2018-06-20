#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>

#include "emp-ot/ot.h"


struct LWEPublicKey {
	long q;
	long n;
	long m;
	NTL::Mat<NTL::ZZ_p> A;
	NTL::Vec<NTL::ZZ_p> p;
};

struct LWEPrivateKey {
	LWEPublicKey pk;
	NTL::Vec<NTL::ZZ_p> s;
};

struct LWECiphertext {
	NTL::Vec<NTL::ZZ_p> u;
	NTL::ZZ_p c;
};




/** @addtogroup OT
    @{
  */
namespace emp { 
template<typename IO> 
class OTLattice: public OT<OTLattice<IO>> { public:
	int cnt = 0;
	IO* io = nullptr;
	block* pkey = nullptr; // Public key from receiver
	block* tmp = nullptr;
	PRG prg;
	bool* branch = nullptr;
	const long q = 1723, n = 608, m = 960;
	//const int pkey_block_count = 8; // Number of 128 bit blocks for the public key


	OTLattice(IO * io) {
		this->io = io;
		NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(q));
	}

	bool* send_pre(int length) {
		// Set up the block count so there is enough to store 'length' bits
		int pkey_block_count = (length - (length % 128) + 128) / 128;
		bool padded[pkey_block_count * 128]; // Padded result.
		pkey = new block[pkey_block_count];
		io->recv_block(pkey, pkey_block_count);

		for (int j = 0; j < pkey_block_count; j++) {
			__int64_t first = _mm_extract_epi64(pkey[j], 0);
			__int64_t second = _mm_extract_epi64(pkey[j], 1);
			int64_to_bool(padded + 64*j, first, 64);
			int64_to_bool(padded + 64*j + 64, second, 64);
		}

		bool* request = new bool[length];
		memcpy(request, padded, length);
		return request;
	}

	void send_impl(const block* data0, const block* data1, int length) {
		bool* requested_secrets = send_pre(length);
		cnt+=length;
		
		block* composed = new block[length]; // Store the blocks from data0 and data1 to send
		for (int j = 0; j < length; j++) {
			if (requested_secrets[j]) {
				composed[j] = data1[j];
			}
			else {
				composed[j] = data0[j];
			}
		}

		io->send_block(composed, length);
		//io->send_block(data0, length);
		//io->send_block(data1, length);
	}

	void recv_pre(const bool* b, int length) {
		int pkey_block_count = (length - (length % 128) + 128) / 128;
		pkey = new block[pkey_block_count];
		bool* padded = new bool[pkey_block_count * 128];
		memcpy(padded, b, length);


		for (int j = 0; j < pkey_block_count; j++) {
			pkey[j] = bool_to128(padded + 128*j);
		}
		io->send_block(pkey, pkey_block_count);
	}

	void recv_impl(block* data, const bool* b, int length) {
		recv_pre(b, length);
		cnt+=length;
		block *data1 = new block[length];
		io->recv_block(data, length);
		
		/*
		io->recv_block(data1, length);
		for(int i = 0; i < length; ++i)
			if(b[i])
				data[i] = data1[i];
		*/
		delete []data1;

	}
};
/**@}*/
}
#endif// OT_LATTICE_H__
