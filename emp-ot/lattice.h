#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <cmath>  // std::log2, std::floor
#include <vector>
#include <iostream>  // debugging
#include "emp-ot/ot.h"

/** @addtogroup OT
    @{
  */
namespace emp {

using LWEPublicKey = NTL::Vec<NTL::ZZ_p>;
using OTPublicKey  = LWEPublicKey;

using LWESecretKey = NTL::Vec<NTL::ZZ_p>;
using OTSecretKey  = LWESecretKey;

using LWEKeypair   = struct { LWEPublicKey pk; LWESecretKey sk; };
using OTKeypair    = LWEKeypair;

using Branch     = uint8_t;
using Plaintext  = uint8_t;

struct LWECiphertext {
	NTL::Vec<NTL::ZZ_p> u;
	NTL::ZZ_p c;
};

using OTCiphertext = LWECiphertext;

template<typename IO>
class OTLattice: public OT<OTLattice<IO>> { public:
	IO* io = nullptr;

	// Note that for vector serialization, q must not be larger than MAXINT
	const uint64_t q = 100, n = 500, m = 600;  // DEBUG
//	const uint64_t q = 1723, n = 608, m = 960;
	NTL::Mat<NTL::ZZ_p> A;
	NTL::Vec<NTL::ZZ_p> v[2];

	// post: populates A, v0, v1 using a fixed-key EMP-library PRG
	//       and rejection sampling
	void InitializeCrs() {
		PRG crs_prg(fix_key);  // emp::fix_key is a library-specified constant

		A.SetDims(n, m);
		v[0].SetLength(m);
		v[1].SetLength(m);

		uint64_t rnd;  // to hold samples
    // min # bits (resp. bytes) to hold q
		const size_t nbits_q = 1 + std::floor(std::log2(q));
		const size_t nbytes_q = 1 + std::floor(std::log2(q)/8);

    // populate A
		for (size_t i = 0; i < n; ++i) {
			for (size_t j = 0; j < m; ++j) {
				do {
					rnd = 0;
					crs_prg.random_data(&rnd, nbytes_q);
					rnd &= ((1 << nbits_q) - 1);  // to minimize waste,
                                        // only sample less than
                                        // the next-greater power of 2
				} while (rnd >= q);
				A[i][j] = rnd;
			}
		}

    // populate v0, v1
    for (size_t vv = 0; vv <= 1; ++vv) {
      for (size_t i = 0; i < n; ++i) {
        do {
          rnd = 0;
          crs_prg.random_data(&rnd, nbytes_q);
          rnd &= ((1 << nbits_q) - 1);
        } while (rnd >= q);
        v[vv][i] = rnd;
      }
    }
	}

  // TODO: change to sample error from discrete Gaussian
  // TODO: not sure - how should we represent a single bit? bool?
  //       (NB: NTL's documentation says many arithmetic operations
  //            are faster with longs -- is this true?)
	LWECiphertext LWEEnc(NTL::Vec<NTL::ZZ_p> &pk, Plaintext mu) {
		NTL::Vec<NTL::ZZ_p> e;
    e.SetLength(m);  // FIXME - use Gaussian instead of uniform{0,1}
    int64_t rnd;
    for (size_t i = 0; i < m; ++i) {
      NTL::RandomBnd(rnd, 2);  // set entry ~ Unif({0,1})
      NTL::conv(e[i], rnd);
    }
		NTL::Vec<NTL::ZZ_p> u = A*e;
		NTL::ZZ_p c = pk*e + mu*q/2;  // c := <p, e> + mu*floor(q/2)
    std::cout << "(Debug) ciphertext: " << u << ", " << c << std::endl;
		return {u, c};
	}

  // pre : sk is of length n, ct is of the form (u, c) of length (n, 1)
  // post: decrypts the ciphertext `ct` using the secret key `sk`
  //       by computing b' := c - <sk, u> and returning
  //       - 0 if b' is closer to 0 (mod q) than to q/2
  //       - 1 otherwise
	bool LWEDec(LWESecretKey &sk, LWECiphertext &ct) {
		uint64_t bprime;
    NTL::conv(bprime, ct.c - sk*ct.u);
		return bprime > q/4 && bprime <= 3*q/4;
	}

  // pre : b (currently 0 or 1) is the request bit
  // post: generates a key pair messy under branch (1 - b)
  //       and decryptable under branch b
  // TODO: change to sample from LWE noise distribution
  //       (discretized Gaussian \bar{\Psi}_\alpha)
	OTKeypair OTKeyGen(Branch sigma) {
		NTL::Vec<NTL::ZZ_p> s, x;
		x.SetLength(m);  // FIXME - use Gaussian instead of zeroes
    NTL::random(s, n);
		NTL::Vec<NTL::ZZ_p> pk = transpose(A)*s + x - v[sigma];
    std::cout << "(Receiver) Debug: pk = " << pk << ", sk = " << s << endl;
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
		NTL::ZZ_p::init(NTL::conv<NTL::ZZ>(q));
		InitializeCrs();
    std::cout << "Initialized!" << std::endl;  // DEBUG
	}

  // (Note: When initializing an OT object, the EMP API doesn't explicitly
  // specify whether it's in the role of sender or receiver; rather,
  // it will call either `send_impl` or `recv_impl`, according to the
  // protocol participant)

  // pre : `data0` and `data1` are the sender's two inputs
  //       Usually, `length` indicates the length of each input,
  //       in 128-bit blocks, but currently, since we're only
  //       implementing bit OT, we interpret the LSB
  //       of *data0 as the 0-indexed input
  //       and the LSB of *data1 as the 1-indexed input
  // post: waits for a public key `pk` from the receiver;
  //       encrypts each input under the received key and the corresponding branch;
  //       and sends the ciphertexts to the receiver
	void send_impl(const block* data0, const block* data1, int length) {
		Plaintext secret0 = _mm_extract_epi32(*data0, 0) & 1;
		Plaintext secret1 = _mm_extract_epi32(*data1, 0) & 1;

		// Receive the public key as a stream of `m` uint32's
		uint32_t pk_array[m];
		io->recv_data(pk_array, sizeof(uint32_t) * m);

		// Convert the public key to an NTL vector
    OTPublicKey pk;
		pk.SetLength(m);
		for (size_t i = 0; i < m; ++i) {
			pk[i] = NTL::conv<NTL::ZZ_p>(pk_array[i]);
		}

    std::cout << "(Sender) Encrypting..." << std::endl;

    // Encrypt the two inputs
    OTCiphertext ct[2];
    ct[0] = OTEnc(pk, 0, secret0);
    ct[1] = OTEnc(pk, 1, secret1);

    std::cout << "(Sender) Encrypted. Serializing ciphertexts..." << std::endl;

    // Send to the receiver
    uint64_t serialized_cts[2][n+1] = {0};
    for (size_t cti = 0; cti <= 1; ++cti) {
      for (size_t ui = 0; ui < n; ++ui) {
        NTL::conv(serialized_cts[cti][ui], ct[cti].u[ui]);
      }
      NTL::conv(serialized_cts[cti][n], ct[cti].c);
    }

    std::cout << "(Sender) Serialized ciphertexts. Sending..." << std::endl;
		io->send_data(serialized_cts, sizeof(uint64_t) * (2*(n+1)));
	}

  // pre : `out_data` indicates the location where the received value
  //         will be stored;
  //       `b` indicates the location of the choice of which secret to receive;
  //       `length` would normally indicate the length, in blocks, of a data
  //         element, but, since we're initially doing bit OT, this input is ignored
	void recv_impl(block* out_data, const bool* b, int length) {
		// Generate the public key from the choice bit b
		OTKeypair keypair = OTKeyGen(*b);

		// Convert the pkey to an int array so it can be sent
		uint32_t pk_array[m];
		for (size_t i = 0; i < m; i++) {
			pk_array[i] = NTL::conv<uint32_t>(keypair.pk[i]);
		}

		// Send the public key
		io->send_data(pk_array, sizeof(uint32_t) * m);

		std::cout << "(Receiver) Sent public key; waiting for ctexts" << std::endl;

    uint64_t serialized_cts[2][n+1] = {0};
		io->recv_data(serialized_cts, sizeof(uint64_t) * (2*(n+1)));

    std::cout << "(Receiver) Received serialized ciphertexts." << std::endl;

    // Parse serialized inputs into NTL objects
    OTCiphertext ct[2];

    for (size_t cti = 0; cti <= 1; ++cti) {
      ct[cti].u.SetLength(n);
      for (size_t ui = 0; ui < n; ++ui) {
        NTL::conv(ct[cti].u[ui], serialized_cts[cti][ui]);
      }
      NTL::conv(ct[cti].c, serialized_cts[cti][n]);
    }

    std::cout << "Parsed serialized ciphertexts, receiving: " << std::endl
      << "Ciphertext 0: (" << ct[0].u << ", " << ct[0].c << ")\n"
      << "Ciphertext 1: (" << ct[1].u << ", " << ct[1].c << ")\n";

    // Decrypt and output
    // Plaintext OTDec(OTKey sk, OTCiphertext ct) {
    Plaintext p = OTDec(keypair.sk, ct[*b]);  // choose ciphertext according to selection bit
    *out_data = _mm_set_epi32(0, 0, 0, p);
	}
};
/**@}*/  // doxygen end of group
}  // namespace emp
#endif// OT_LATTICE_H__
