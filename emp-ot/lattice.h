#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <cmath>  // std::log2
#include "emp-ot/ot.h"
#include <vector>
#include <iostream>




struct LWEPrivateKey {
	NTL::Vec<NTL::ZZ_p> pk; // public key
	NTL::Vec<NTL::ZZ_p> s;	// secret key
};

struct LWECiphertext {
	NTL::Vec<NTL::ZZ_p> u;
	NTL::ZZ_p c;
};

// struct OTRefStr
// {
// 	long q;
// 	long n;
// 	long m;
// 	NTL::Mat<NTL::ZZ_p> A;
// 	NTL::Vec<NTL::ZZ_p> v[2];
// };

struct OTKey
{
	NTL::Vec<NTL::ZZ_p> pk;
	NTL::Vec<NTL::ZZ_p> s;
};




/** @addtogroup OT
    @{
  */
namespace emp { 
template<typename IO> 
class OTLattice: public OT<OTLattice<IO>> { public:
	int cnt = 0;
	IO* io = nullptr;
	// Note that for vector serialization, q must not be larger than MAXINT
	const long q = 1723, n = 608, m = 960;
	NTL::Mat<NTL::ZZ_p> A;
	NTL::Vec<NTL::ZZ_p> v[2];


	// populate A, v0, v1 using a fixed-key PRG
	// and rejection sampling (for now)
	void InitializeCrs() {
		PRG crs_prg(fix_key);

		A.SetDims(n, m);
		v[0].SetLength(m);
		v[1].SetLength(m);

		long rnd;
		const long nbits_q = 1 + std::floor(std::log2(q));
		const long nbytes_q = 1 + std::floor(std::log2(q)/8);

		for (int i = 0; i < n; ++i) {
			for (int j = 0; j < m; ++j) {
				do {
					rnd = 0;
					crs_prg.random_data(&rnd, nbytes_q);
					rnd &= ((1 << nbits_q) - 1);
				} while (rnd >= q);
				A[i][j] = rnd;
			}
		}

		for (int i = 0; i < n; ++i) {
			do {
				rnd = 0;
				crs_prg.random_data(&rnd, nbytes_q);
				rnd &= ((1 << nbits_q) - 1);
			} while (rnd >= q);
			v[0][i] = rnd;
		}

		for (int i = 0; i < n; ++i) {
			do {
				rnd = 0;
				crs_prg.random_data(&rnd, nbytes_q);
				rnd &= ((1 << nbits_q) - 1);
			} while (rnd >= q);
			v[1][i] = rnd;
		}
	}


	
	void OTSetup() {
		// Make this pseudorandom
		random(A, n, m);
		random(v[0], m);
		random(v[1], m);
	}

	LWECiphertext LWEEnc(NTL::Vec<NTL::ZZ_p> &pk, bool b) {
		NTL::Vec<NTL::ZZ_p> e;
		random(e, m); // discrete Gaussian over lattice
		NTL::Vec<NTL::ZZ_p> u = A*e;
		NTL::ZZ_p c = pk*e + b*q/2;
		LWECiphertext ct = {u, c};
		return ct;
	}

	bool LWEDec(LWEPrivateKey &sk, LWECiphertext &ct) {
		long bp;
		conv(bp, ct.c - sk.s*ct.u);
		return bp > q/4 && bp <= 3*q/4;
	}
	
	OTKey OTKeyGen(int sigma) {
		NTL::Vec<NTL::ZZ_p> s, x;
		random(s, n);
		x.SetLength(m); // discrete Gaussian error
		NTL::Vec<NTL::ZZ_p> pk = transpose(A)*s + x - v[sigma];
		OTKey sk = {pk, s};
		return sk;
	}

	LWECiphertext OTEnc(NTL::Vec<NTL::ZZ_p> pk, int sigma, bool b) {
		NTL::Vec<NTL::ZZ_p> p = pk + v[sigma];
		LWECiphertext ct = LWEEnc(p, b);
		return ct;
	}

	bool OTDec(OTKey sk, LWECiphertext ct) {
		bool b = LWEDec(sk, ct);
		return b;
	}

	OTLattice(IO * io) {
		this->io = io;
		NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(q));
		OTSetup();
	}

	// std::vector<block> vector_serialize(NTL::Vec<NTL::ZZ_p> v) {

	// 	int length = v.length();
	// 	int nblocks = std::ceil(length / 4.0);
	// 	std::vector<block> serialized(nblocks);


	// 	// Fill the blocks that are guaranteed to have all four values
	// 	for (int b = 0; b < nblocks - 1; b++) {
	// 		serialized[b] = _mm_setr_epi32(v[4*b], v[4*b+1], v[4*b+2], v[4*b+3]);
	// 	}

	// 	// Fill the last block with the values that are left
	// 	int lastBlock[4] = {0,0,0,0};
	// 	for (int pos = 4 * (nblocks - 1); pos < length; pos++) {
	// 		lastBlock[pos] = v[pos];
	// 	}
	// 	serialized[nblocks - 1] = _mm_setr_epi32(lastBlock[0], lastBlock[1],
	// 	                                         lastBlock[2], lastBlock[3]);
		
	// 	return serialized;
	// }

	// NTL::Vec<NTL::ZZ_p> vector_deserialize(block* serialized, int length) {
	// 	// Where length is the number of values, not the number of blocks
	// 	NTL::Vec<NTL::ZZ_p> result;
	// 	result.SetLength(length);

	// 	for (int i = 0; i < length; i++) {
	// 		result[i] = _mm_extract_epi32(block[i / 4], i % 4);
	// 	}

	// 	return result;
	// }

	void send_impl(const block* data0, const block* data1, int length) {
		// data0 and data1 are the sender's two secrets
		// length is the length in blocks of each secret
		cnt+=length;
		bool secret0 = _mm_extract_epi32(*data0, 0) & 1;
		bool secret1 = _mm_extract_epi32(*data1, 0) & 1;

		// Receive the public key
		uint32_t pk_array[m];
		io->recv_data(pk_array, sizeof(uint32_t) * m);

		// Convert the public key to an NTL vector
		NTL::Vec<NTL::ZZ_p> pk;
		pk.SetLength(m);
		for (int i = 0; i < m; i++) {
			pk[i] = NTL::conv<NTL::ZZ_p>(pk_array[i]);
		}

		std::cout << "Sender recieved pk " << pk << endl;
		

	}

	void recv_impl(block* data, const bool* b, int length) {
		// data gets the received data from the sender
		// b is the choice of which secret to receive
		// length is the length in blocks of the received data

		// Generate the public key from the choice bit b
		OTKey sk = OTKeyGen(*b);
		
		// Convert the pkey to an int array so it can be sent
		uint32_t pk_array[m];
		for (int i = 0; i < m; i++) {
			pk_array[i] = NTL::conv<uint32_t>(sk.pk[i]);
		}

		// Send the public key
		io->send_data(pk_array, sizeof(uint32_t) * m);

		std::cout << "Receiver sent pk " << sk.pk << endl;

		//block choice = _mm_setr_epi32(0, 0, 0, *b);
		//io->send_block(&choice, 1);
		
		

		
	}
};
/**@}*/
}
#endif// OT_LATTICE_H__
