#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <Eigen/Dense>

#include <string> // std::string, for timer formatting

#include <algorithm>  // std::min
#include <cmath>  // std::log2, std::floor, std::fmod

#include <iostream>  // debug printlns

#include "emp-ot/ot.h"

#include <boost/function.hpp>
#include <boost/bind.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/random/normal_distribution.hpp>
#include <boost/random/random_device.hpp>

constexpr int DEBUG = 0;  // 2: print ciphertexsts, 1: minimal debug info

/** @addtogroup OT
    @{
*/

// Parameters
constexpr long PARAM_Q = 140737488355000; ///< Modulus: 2 ** 47
constexpr int PARAM_N = 1600; ///< Number of rows of `A`
constexpr int PARAM_M = 150494; ///< Number of columns of `A`
constexpr double PARAM_ALPHA = 2.59894264322e-13;
constexpr double PARAM_R = 125878741.823;
// For the Discretized Gaussian
constexpr double LWE_ERROR_STDEV = PARAM_Q * PARAM_ALPHA / boost::math::constants::root_two_pi<double>();
constexpr double R_STDEV = PARAM_R / boost::math::constants::root_two_pi<double>(); ///< Standard deviation of the discretized Gaussian

using int_mod_q = uint64_t;

using MatrixModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, Eigen::Dynamic>;
using VectorModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, 1>;

using LWEPublicKey = MatrixModQ;
using LWESecretKey = MatrixModQ;
struct LWEKeypair { LWEPublicKey pk; LWESecretKey sk; };

using Branch = int;
using Plaintext = VectorModQ;
struct LWECiphertext { VectorModQ u; VectorModQ c; };

/// Wraps EMP to sample an integer type 
/// (works for sure with short, int, long) 
/// providing an interface acceptable to
/// std::normal_distribution
class LongAESWrapper {
public:
	typedef unsigned long result_type;
	emp::PRG prg;
	result_type min() {
		return std::numeric_limits<result_type>::min();
	}
	result_type max() {
		return std::numeric_limits<result_type>::max();
	}
	result_type operator()() {
		result_type outp = 0;
		prg.random_data(&outp, sizeof(result_type));
		return outp;
	}
};

namespace emp {

/// @param dst The int_mod_q to write the sample to
/// @param bound One more than the largest integer sampleable
/// @param sample_prg The PRG to sample from
/// \pre \p dst is zeroed, bound is of the form `2**k` where 8 divides `k`
///      \p bound *must* be a power of 2.
/// \post Sets \p dst to a random integer between
///       0 and `bound - 1` (inclusive) through
///       rejection sampling, using the given EMP PRG.
void SampleBounded(int_mod_q &dst, int_mod_q bound, PRG& sample_prg) {
	int_mod_q bound_mask = bound - 1;
	int nbytes_bound = 1 + std::floor((std::log2(bound)-1)/8);
	sample_prg.random_data(&dst, nbytes_bound);
	dst &= bound_mask;
}

/// @param result The matrix that is written to
/// @param sample_prg The PRG to sample from
/// \post Populates the matrix mod Q \p result with uniform values
///	     from the given PRG generated using rejection sampling.
void UniformMatrixModQ(MatrixModQ &result, PRG &sample_prg) {
	int n = result.rows();
	int m = result.cols();
	for (int j = 0; j < m; ++j) {
		for (int i = 0; i < n; ++i) {
			SampleBounded(result(i, j), PARAM_Q, sample_prg);
		}
	}
}

LongAESWrapper law;
boost::function<double()> SampleStandardGaussian = boost::bind(
							       boost::random::normal_distribution<>(0, 1),
							       boost::ref(law));

/// @param stdev The standard deviation of the discretized gaussian
/// \post Returns a sample from the discretized gaussian of standard
/// distribution \p stdev centered around zero.
long SampleDiscretizedGaussian(double stdev) {
	double e = SampleStandardGaussian() * stdev;
	return boost::math::lround(e) % PARAM_Q;
}

/// @param result The matrix that is written to
/// @param stdev The standard deviation of the discretized gaussian
/// \post Populates the matrix mod Q \p result with values from
///	the discretized gaussian of standard distribution \p stdev
void DiscretizedGaussianMatrixModQ(MatrixModQ &result, double stdev) {
	int n = result.rows();
	int m = result.cols();
	for (int j = 0; j < m; ++j) {  // j, i loop order because column-major
		for (int i = 0; i < n; ++i) {
			result(i, j) = SampleDiscretizedGaussian(stdev);
		}
	}
}

template<typename IO, int PARAM_L>
class OTLattice: public OT<OTLattice<IO, PARAM_L>> {
public:
	IO* io = nullptr; ///< The `emp::IOChannel<T>` used for communication.
	PRG prg; ///< `emp::PRG` with a random seed.
	PRG crs_prg; ///< `emp::PRG` with a seed shared between the sender and receiver for CRS generation.
	MatrixModQ A; ///< The `PARAM_N` by `PARAM_M` matrix that represents the lattice.
	MatrixModQ v[2]; ///< The two vectors that correspond to the two encryption branches.
	bool initialized;  ///< Whether or not coinflip has been run, `crs_prg` has been seeded, and `A` has been generated.

	/// @param raw_plaintext A block of plaintext to encode
	/// \post Returns an appropriate (for passing to LWEEnc) object
	///       representing the given plaintext \p raw_plaintext.
	///       In particular, this implementation interprets the given plaintext `p`
	///       as an array of four length-32 bitstrings, takes the `PARAM_L`
	///       many least-significant bits, and places them (in increasing significance
	///       order) in the resulting vector.
	Plaintext EncodePlaintext(block raw_plaintext) {
		VectorModQ to_return(PARAM_L);
		int a[4];
		// indices given to _mm_extract_epi32 start from the *right*
		a[0] = _mm_extract_epi32(raw_plaintext, 3);
		a[1] = _mm_extract_epi32(raw_plaintext, 2);
		a[2] = _mm_extract_epi32(raw_plaintext, 1);
		a[3] = _mm_extract_epi32(raw_plaintext, 0);

		// iterate over ints right to left;
		// within each int, iterate over bits right to left
		for (int i = 0; i <= PARAM_L / 32; ++i) {
			for (int j = 0; j < std::min(32, PARAM_L - (32*i)); ++j) {
				to_return((32*i) + j) = (a[3-i] & (1 << j)) >> j;
			}
		}
		return to_return;
	}
	/// @param encoded_plaintext The plaintext to be decoded
	/// \post Returns the raw plaintext corresponding to \p encoded_plaintext.
	block DecodePlaintext(const Plaintext& encoded_plaintext) {
		int a[4] {0};
		for (int i = 0; i <= PARAM_L / 32; ++i) {
			for (int j = 0; j < std::min(32, PARAM_L - (32*i)); ++j) {
				a[3-i] |= encoded_plaintext((32*i) + j) << j;
			}
		}
		return _mm_set_epi32(a[0], a[1], a[2], a[3]);
	}

	/// @param sigma The request bit.
	/// \pre \p sigma is 0 or 1.
	/// \post Generates a key pair messy under branch `(1 - sigma)`
	///       and decryptable under branch \p sigma.
	LWEKeypair OTKeyGen(Branch sigma) {
		LWESecretKey S = MatrixModQ();
		S.resize(PARAM_N, PARAM_L);
		UniformMatrixModQ(S, prg);


		MatrixModQ pk(PARAM_M, PARAM_L);
		DiscretizedGaussianMatrixModQ(pk, LWE_ERROR_STDEV);

		pk.noalias() -= v[sigma];
		pk.noalias() += (S.transpose()*A).transpose();

		if (DEBUG >= 2)
			std::cout << "(Receiver) Debug: A = " << A << ", pk = " << pk << ", sk = " << S << endl;
		return {pk, S};
	}



	/// @param pk The public key used for encryption
	/// @param sigma The branch to encrypt on
	/// @param mu The plaintext to encrypt
	/// \pre Sigma is 0 or 1.
	/// \post Returns the ciphertext corresponding to encrypting \p mu with \p pk
	///       on branch \p sigma.
	LWECiphertext OTEnc(const LWEPublicKey &pk, Branch sigma, const Plaintext &mu) {
		LWEPublicKey branch_pk {pk + v[sigma]};
		VectorModQ x(PARAM_M);
		for (int i = 0; i < PARAM_M; ++i) {
			x(i) = SampleDiscretizedGaussian(R_STDEV);
		}
		//DiscretizedGaussianMatrixModQ(x, R_STDEV);

		VectorModQ u = A*x;
		VectorModQ c = (branch_pk.transpose() * x) + ((PARAM_Q / 2)*mu);
		return {u, c};
	}

	/// @param sk The secret key
	/// @param ct The ciphertext
	/// \pre \p sk is of length `n`, \p ct is of the form `(u, c)` of length `(n, 1)`
	/// \post Decrypts the ciphertext \p ct using the secret key \p sk
	///       by computing \f$ b' := c - \langle sk, u \rangle \f$ and returning
	///       - 0 if b' is closer to `0 (mod Q)` than to `Q/2`
	///       - 1 otherwise
	Plaintext OTDec(LWESecretKey &sk, LWECiphertext &ct) {
		Plaintext muprime = ct.c - (sk.transpose() * ct.u);
		for (int i = 0; i < PARAM_L; ++i) {
			muprime(i) %= PARAM_Q;
			muprime(i) = muprime(i) > PARAM_Q/4 && muprime(i) <= 3*PARAM_Q/4;
		}
		return muprime;
	}

	/// \pre `crs_prg` has been initialized with a shared seed from coinflip.
	/// \post Populates `A` uniformly using rejection sampling with PRG `crs_prg`.
	void InitializeCrs() {
		UniformMatrixModQ(A, crs_prg);
	}

	/// \pre `crs_prg` has been initialized with a shared seed from coinflip
	/// \post Populates `v0`, `v1` uniformly using rejection sampling with PRG `crs_prg`.
	void GenerateCrsVectors() {
		UniformMatrixModQ(v[0], crs_prg);
		UniformMatrixModQ(v[1], crs_prg);
	}

	/// @param io The instance of the IO used for communication.
	/// \post Initializes the view of one participant of the lattice-based
	///       OT protocol.
	explicit OTLattice(IO * io) {
		this->io = io;
		initialized = false;
		A.resize(PARAM_N, PARAM_M);
		v[0].resize(PARAM_M, PARAM_L);
		v[1].resize(PARAM_M, PARAM_L);
	}

	/// \post Initializes `crs_prg` with a random seed shared with the other party.
	void sender_coinflip() {
		// Generate a random block
		block rand_sender;
		prg.random_block(&rand_sender);

		// Send the hash of the block to the receiver
		char sender_dgst[Hash::DIGEST_SIZE];
		Hash::hash_once(sender_dgst, &rand_sender, sizeof(block));
		io->send_data(sender_dgst, Hash::DIGEST_SIZE);

		// Receive the receiver's random block
		block rand_receiver;
		io->recv_block(&rand_receiver, 1);

		// Send the sender's block
		io->send_block(&rand_sender, 1);

		// Get whether the receiver accepts the sender's block
		bool success;
		io->recv_data(&success, sizeof(bool));
		if (success) {
			// Initialize the prg with the seed (rand_sender (xor) rand_receiver)
			block seed = xorBlocks(rand_sender, rand_receiver);
			crs_prg.reseed(&seed);
		} else {
			error("Coinflip Failed\n");
		}
	}

	/// \post Initializes `crs_prg` with a random seed shared with the other party.
	void receiver_coinflip() {
		// Generate a random block
		block rand_receiver;
		prg.random_block(&rand_receiver);

		// Receive the hash of the sender's random block
		char received_sender_dgst[Hash::DIGEST_SIZE];
		io->recv_data(received_sender_dgst, Hash::DIGEST_SIZE);

		// Send the receiver's random block
		io->send_block(&rand_receiver, 1);

		// Receive the sender's random block
		block rand_sender;
		io->recv_block(&rand_sender, 1);

		// Check that the hash of the sender's block equals
		// the earlier received hash.
		char computed_sender_dgst[Hash::DIGEST_SIZE];
		Hash::hash_once(computed_sender_dgst, &rand_sender, sizeof(block));
		if (std::strncmp(received_sender_dgst, computed_sender_dgst, Hash::DIGEST_SIZE) != 0) {
			// Then the strings are not equal and the sender is not following the protocol.
			bool success = false;
			io->send_data(&success, sizeof(bool));
			error("Coinflip Failed\n");
		}
		else {
			bool success = true;
			io->send_data(&success, sizeof(bool));
			// Initialize the prg with the seed (rand_sender (xor) rand_receiver)
			block seed = xorBlocks(rand_sender, rand_receiver);
			crs_prg.reseed(&seed);
		}
		// Since this function ends with an io->send,
		// Make sure all messages are actually sent by flushing the IO.
		io->flush(); 
	}

	// (Note: When initializing an OT object, the EMP API doesn't explicitly
	// specify whether it's in the role of sender or receiver; rather,
	// it will call either `send_impl` or `recv_impl`, according to the
	// protocol participant)

	/// @param data0 The first secret
	/// @param data1 The second secret
	/// @param length The number of OTs to perform
	/// \pre `data0[i]` and `data1[i]` are the sender's two inputs
	///       for the `i`th OT transmission.
	/// \post Waits for a public key `pk` from the receiver;
	///       encrypts each input under the received key and the corresponding branch
	///       and sends the ciphertexts to the receiver.
	void send_impl(const block* data0, const block* data1, int length) {
		if (!initialized) {
			sender_coinflip(); // should only happen once
			InitializeCrs();
			initialized = true;
		}



		for (int ot_iter = 0; ot_iter < length; ++ot_iter) {

			// Generate new v1, v2 every time
			GenerateCrsVectors();

			Plaintext secret0 = EncodePlaintext(data0[ot_iter]);
			Plaintext secret1 = EncodePlaintext(data1[ot_iter]);

			if (DEBUG > 1)
				std::cerr << "(Sender, iteration " << ot_iter << ") Encoded values x0=" << secret0 << ", x1=" << secret1 << std::endl;

			int_mod_q pk_array[PARAM_M * PARAM_L];
			io->recv_data(pk_array, sizeof(pk_array[0]) * PARAM_M * PARAM_L);

			Eigen::Map<MatrixModQ> pk {pk_array, PARAM_M, PARAM_L};  // interpret memory as matrix

			if (DEBUG)
				std::cerr << "(Sender) Encrypting..." << std::endl;

			// Encrypt the two inputs
			LWECiphertext ct[2];
			ct[0] = OTEnc(pk, 0, secret0);
			ct[1] = OTEnc(pk, 1, secret1);



			if (DEBUG == 1)
				std::cerr << "(Sender) Encrypted. Sending ciphertexts..." << std::endl;
			if (DEBUG >= 2) {
				std::cerr << "Sending Ciphertext 0: (" << ct[0].u << ", " << ct[0].c << ")\n"
					  << "Sending Ciphertext 1: (" << ct[1].u << ", " << ct[1].c << ")\n";
			}

			for (int i = 0; i <= 1; ++i) {
				io->send_data(ct[i].u.data(), sizeof(int_mod_q) * ct[i].u.size());
				io->send_data(ct[i].c.data(), sizeof(int_mod_q) * ct[i].c.size());
			}
		}
	}

	/// @param out_data Where the results of the OTs are stored
	/// @param b b The location of the choice of which secret to receive
	/// @param length The number of OT executions to be performed.
	void recv_impl(block* out_data, const bool* b, int length) {
		if (! initialized) {
			receiver_coinflip(); // should only happen once
			InitializeCrs();
			initialized = true;
		}

		// std::cout << "(Lattice OT 1, sender: performing " << length << " OTs): ";
		for (int ot_iter = 0; ot_iter < length; ++ot_iter) {
			// std::cout << ot_iter + 1 << "... " << std::flush;
			// if (ot_iter == length - 1)
			// 	std::cout << std::endl;

			// Generate new v1, v2 every time
			GenerateCrsVectors();
			// Generate the public key from the choice bit b
			LWEKeypair keypair = OTKeyGen(b[ot_iter]);


			// Send the public key
			io->send_data(keypair.pk.data(), sizeof(int_mod_q) * keypair.pk.size());

			if (DEBUG)
				std::cerr << "(Receiver) Sent public key; waiting for ctexts" << std::endl;

			int_mod_q ct_array[2*(PARAM_N+PARAM_L)];
			io->recv_data(ct_array, sizeof(int_mod_q) * (2*(PARAM_N+PARAM_L)));
			LWECiphertext ct[2];

			ct[0] = LWECiphertext {
					       Eigen::Map<VectorModQ> {ct_array, PARAM_N, 1},
					       Eigen::Map<VectorModQ> {ct_array + PARAM_N, PARAM_L, 1}
			};

			ct[1] = LWECiphertext {
					       Eigen::Map<VectorModQ> {ct_array + PARAM_N + PARAM_L, PARAM_N, 1},
					       Eigen::Map<VectorModQ> {ct_array + PARAM_N + (PARAM_N + PARAM_L), PARAM_L, 1}
			};

			if (DEBUG >= 2) {
				std::cerr << "Received ciphertext " << b[ot_iter] << ": (u=" << ct[b[ot_iter]].u << ",\nc=" << ct[b[ot_iter]].c << ")\n";
			}

			Plaintext p = OTDec(keypair.sk, ct[b[ot_iter]]);  // choose ciphertext according to selection bit

			if (DEBUG > 1)
				std::cerr << "(Receiver, iteration " << ot_iter << ") Decrypted branch " << b[ot_iter] << " to get plaintext " << p << std::endl;

			out_data[ot_iter] = DecodePlaintext(p);

		}
	}
};
	/**@}*/  // doxygen end of group
}  // namespace emp
#endif  // OT_LATTICE_H__
