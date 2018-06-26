#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <Eigen/Dense>
#include <cmath>  // std::log2, std::floor
#include <vector>
#include <iostream>  // debug printlns
#include "emp-ot/ot.h"
extern "C" {
	//https://github.com/malb/dgs
	#include <dgs/dgs_gauss.h>
}




bool DEBUG = 0;

/** @addtogroup OT
    @{
*/

// Parameters for LWE
// N and M are the matrix dimensions
// Q is the modulus
// See https://frodokem.org/files/FrodoKEM-specification-20171130.pdf
// page 16, 21-23
#define Q 65536 // max of uint16_t is the implicit modulus.
#define N 640
#define M 640
#define SIGMA 7 // something I made up.
namespace emp {


typedef Eigen::Matrix<uint16_t, Eigen::Dynamic, Eigen::Dynamic> MatrixModQ;
typedef Eigen::Matrix<uint16_t, Eigen::Dynamic, 1> VectorModQ;

using LWEPublicKey = VectorModQ;
using OTPublicKey  = LWEPublicKey;

using LWESecretKey = VectorModQ;
using OTSecretKey  = LWESecretKey;

using LWEKeypair   = struct { LWEPublicKey pk; LWESecretKey sk; };
using OTKeypair    = LWEKeypair;

using Branch     = int;
using Plaintext  = int;

class LWECiphertext {
public:
	LWECiphertext(VectorModQ uinit, uint16_t cinit) : u(uinit), c(cinit) {
	}
	LWECiphertext() {
		u.resize(M);
	}
	VectorModQ u;
	uint16_t c;
};


using OTCiphertext = LWECiphertext;
template<typename IO>
class OTLattice: public OT<OTLattice<IO>> { public:
	IO* io = nullptr;

	MatrixModQ A;
	MatrixModQ AT; // A transpose is stored for speed
	VectorModQ v[2];
	dgs_disc_gauss_dp_t *discrete_gaussian;

	// post: populates A, AT, v0, v1 using a fixed-key EMP-library PRG
	//       and rejection sampling
	void InitializeCrs() {
		PRG crs_prg(fix_key);  // emp::fix_key is a library-specified constant

		A.resize(N, M);
		AT.resize(M, N);
		v[0].resize(M);
		v[1].resize(M);

		int rnd;  // to hold samples
		// min # bits (resp. bytes) to hold q
		const int nbits_q = 1 + std::floor(std::log2(Q));
		const int nbytes_q = 1 + std::floor(std::log2(Q)/8);

		// populate A and AT
		for (int i = 0; i < N; ++i) {
			for (int j = 0; j < M; ++j) {
				do {
					rnd = 0;
					crs_prg.random_data(&rnd, nbytes_q);
					rnd &= ((1 << nbits_q) - 1);  // to minimize waste,
					// only sample less than
					// the next-greater power of 2
				} while (rnd >= Q);
				A(i, j) = rnd;
				AT(j, i) = rnd;
			}
		}

		// populate v0, v1
		for (int vv = 0; vv <= 1; ++vv) {
			for (int i = 0; i < N; ++i) {
				do {
					rnd = 0;
					crs_prg.random_data(&rnd, nbytes_q);
					rnd &= ((1 << nbits_q) - 1);
				} while (rnd >= Q);
				v[vv](i) = rnd;
			}
		}
	}

	// TODO: change to sample error from discrete Gaussian
	// TODO: not sure - how should we represent a single bit? bool?
	//       (NB: NTL's documentation says many arithmetic operations
	//            are faster with longs -- is this true?)
	LWECiphertext LWEEnc(VectorModQ &pk, Plaintext mu) {
		//NTL::Vec<NTL::ZZ_p> e;
		VectorModQ e;
		e.resize(M);  // FIXME - use Gaussian instead of uniform{0,1}
		for (int i = 0; i < M; ++i) {
			e(i) = (uint16_t) discrete_gaussian->call(discrete_gaussian);
		}
		
		VectorModQ u = A*e;
		uint16_t c = pk.dot(e) + mu*Q/2; // c := <p, e> + mu*floor(Q/2)

		if (DEBUG)
			std::cout << "(Debug) ciphertext: " << u << ", " << c << std::endl;
		return {u, c};
		//std::cout << "Discrete Gaussian Sample: " << discrete_gaussian->call(discrete_gaussian) << std::endl;

	}

	// pre : sk is of length n, ct is of the form (u, c) of length (n, 1)
	// post: decrypts the ciphertext `ct` using the secret key `sk`
	//       by computing b' := c - <sk, u> and returning
	//       - 0 if b' is closer to 0 (mod Q) than to Q/2
	//       - 1 otherwise
	bool LWEDec(LWESecretKey &sk, LWECiphertext &ct) {
		uint16_t bprime;
		bprime = ct.c - sk.dot(ct.u);
		//std::cout << "bprime: " <<  bprime << endl;
		return bprime > Q/4 && bprime <= 3*Q/4;
	}

	// pre : b (currently 0 or 1) is the request bit
	// post: generates a key pair messy under branch (1 - b)
	//       and decryptable under branch b
	// TODO: change to sample from LWE noise distribution
	//       (discretized Gaussian \bar{\Psi}_\alpha)
	OTKeypair OTKeyGen(Branch sigma) {
		VectorModQ s;
		VectorModQ x = VectorModQ::Zero(M); // FIXME - use Gaussian instead of zeroes

		s = VectorModQ::Random(N);
		//NTL::Vec<NTL::ZZ_p> pk = transpose(A)*s + x - v[sigma];
		
		VectorModQ pk = AT*s + x - v[sigma];

		// if (DEBUG)
		// 	std::cout << "(Receiver) Debug: pk = " << pk << ", sk = " << s << endl;
		return {pk, s};
	}

	// pre : sigma indicates the branch to encrypt to
	OTCiphertext OTEnc(OTPublicKey pk, Branch sigma, Plaintext msg) {
		LWEPublicKey BranchPk = pk + v[sigma];
		return LWEEnc(BranchPk, msg);
	}

	Plaintext OTDec(OTSecretKey sk, OTCiphertext ct) {
		return LWEDec(sk, ct);
	}

	explicit OTLattice(IO * io) {
		this->io = io;
		//NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(Q));
		InitializeCrs();

		// Sigma, c, tau, algorithm
		// c is the center
		// I think tau determines accuracy? I'm not sure.
		discrete_gaussian = dgs_disc_gauss_dp_init(SIGMA, 0, 100, DGS_DISC_GAUSS_UNIFORM_TABLE);
		if (DEBUG)
			std::cout << "Initialized!" << std::endl;  // DEBUG
	}

	// (Note: When initializing an OT object, the EMP API doesn't explicitly
	// specify whether it's in the role of sender or receiver; rather,
	// it will call either `send_impl` or `recv_impl`, according to the
	// protocol participant)

	// pre : `data0`[i] and `data1`[i] are the sender's two inputs
	//       for the `i`th OT transmission
	//       Since we're only implementing bit OT,
	//       we interpret the LSB of data0[i]
	//       as the `i`th 0-indexed input
	//       and the LSB of data1[i] as the `i`th 1-indexed input
	// post: waits for a public key `pk` from the receiver;
	//       encrypts each input under the received key and the corresponding branch;
	//       and sends the ciphertexts to the receiver
	void send_impl(const block* data0, const block* data1, int length) {
		for (int ot_iter = 0; ot_iter < length; ++ot_iter) {
			if (ot_iter and (ot_iter % 500 == 499 or ot_iter == length - 1))
				std::cout << ot_iter + 1 << ' ' << std::flush;
			if (ot_iter == length - 1)
				std::cout << std::endl << std::flush;

			Plaintext secret0 = _mm_extract_epi32(data0[ot_iter], 0) & 1;
			Plaintext secret1 = _mm_extract_epi32(data1[ot_iter], 0) & 1;

			if (DEBUG)
				std::cout << "(Sender, iteration " << ot_iter << ") Initialized with values x0=" << secret0 << ", x1=" << secret1 << std::endl;

			// Receive the public key as a stream of `m` int32's
			uint16_t pk_array[M];
			io->recv_data(pk_array, sizeof(uint16_t) * M);

			// Convert the public key to an Eigen vector (not eigenvector)
			OTPublicKey pk;
			pk.resize(M);
			for (int i = 0; i < M; ++i) {
				pk(i) = pk_array[i];
			}

			if (DEBUG)
				std::cout << "(Sender) Encrypting..." << std::endl;

			// Encrypt the two inputs
			OTCiphertext ct[2];
			ct[0] = OTEnc(pk, 0, secret0);
			ct[1] = OTEnc(pk, 1, secret1);

			if (DEBUG)
				std::cout << "(Sender) Encrypted. Serializing ciphertexts..." << std::endl;

			// Send to the receiver
			uint16_t serialized_cts[2][N+1] = {{0}};
			for (int cti = 0; cti <= 1; ++cti) {
				for (int ui = 0; ui < N; ++ui) {
					serialized_cts[cti][ui] = ct[cti].u(ui);
					
				}
				serialized_cts[cti][N] = ct[cti].c;
			}

			if (DEBUG)
				std::cout << "(Sender) Serialized ciphertexts. Sending..." << std::endl;

			io->send_data(serialized_cts, sizeof(uint16_t) * (2*(N+1)));
		}
	}

	// pre : `out_data` indicates the location where the received value
	//         will be stored;
	//       `b` indicates the location of the choice of which secret to receive;
	//       `length` indicates the number of OT executions to be
	//       performed
	void recv_impl(block* out_data, const bool* b, int length) {
		for (int ot_iter = 0; ot_iter < length; ++ot_iter) {
			// Generate the public key from the choice bit b
			OTKeypair keypair = OTKeyGen(b[ot_iter]);

			// Convert the pkey to an int array so it can be sent
			uint16_t pk_array[M];
			for (int i = 0; i < M; i++) {
				pk_array[i] = keypair.pk(i);
			}

			// Send the public key
			io->send_data(pk_array, sizeof(uint16_t) * M);

			if (DEBUG)
				std::cout << "(Receiver) Sent public key; waiting for ctexts" << std::endl;

			uint16_t serialized_cts[2][N+1] = {{0}};
			io->recv_data(serialized_cts, sizeof(uint16_t) * (2*(N+1)));

			if (DEBUG)
				std::cout << "(Receiver) Received serialized ciphertexts." << std::endl;

			// Parse serialized inputs into NTL objects
			OTCiphertext ct[2];

			for (int cti = 0; cti <= 1; ++cti) {
				ct[cti].u.resize(N);
				for (int ui = 0; ui < N; ++ui) {
					ct[cti].u(ui) = serialized_cts[cti][ui];
				}
				ct[cti].c = serialized_cts[cti][N];
			}

			// if (DEBUG) {
			// 	std::cout << "Parsed serialized ciphertexts, receiving: " << std::endl
			// 		  << "Ciphertext 0: (" << ct[0].u << ", " << ct[0].c << ")\n"
			// 		  << "Ciphertext 1: (" << ct[1].u << ", " << ct[1].c << ")\n";
			// }

			// Decrypt and output
			// Plaintext OTDec(OTKey sk, OTCiphertext ct) {
			Plaintext p = OTDec(keypair.sk, ct[b[ot_iter]]);  // choose ciphertext according to selection bit

			if (DEBUG)
				std::cout << "(Receiver, iteration " << ot_iter << ") Decrypted branch " << b[ot_iter] << " to get plaintext " << p << std::endl;

			out_data[ot_iter] = _mm_set_epi32(0, 0, 0, p);
		}
	}
};
/**@}*/  // doxygen end of group
}  // namespace emp
#endif// OT_LATTICE_H__
