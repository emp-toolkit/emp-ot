#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <Eigen/Dense>

#include <boost/timer/timer.hpp>
#include <string> // std::string, for timer formatting

#include <algorithm>  // std::min
#include <cmath>  // std::log2, std::floor, std::fmod

#include <iostream>  // debug printlns
#include <limits>   // std::numeric_limits

#include "emp-ot/ot.h"

#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/random/normal_distribution.hpp>
#include <boost/random/random_device.hpp>

constexpr int DEBUG = 0; // 2: print ciphertexts, 1: minimal debug info

/** @addtogroup OT
    @{
*/

constexpr int BATCH_SIZE = 4; ///< The number of OTs to perform at a time. Change this to 128 or something for speedup
// Using Enumeration Parameters
using int_mod_q = uint64_t;
constexpr uint64_t PARAM_LOGQ = 64; ///< Modulus
constexpr int PARAM_N = 1300;       ///< Number of rows of `A`
constexpr int PARAM_M = 166528;     ///< Number of columns of `A`
constexpr double PARAM_ALPHA = 4.332e-16;
constexpr double PARAM_R = 1.136e8;
constexpr int PARAM_ALPHABET_SIZE =
    8192; ///< Should work even if not a power of 2
// constexpr uint64_t PARAM_LOGQ = 64; ///< Modulus
// constexpr int PARAM_N = 670;        ///< Number of rows of `A`
// constexpr int PARAM_M = 85888;      ///< Number of columns of `A`
// constexpr double PARAM_ALPHA = 5.626e-12;
// constexpr double PARAM_R = 7.876e7;
// constexpr int PARAM_ALPHABET_SIZE = 2; ///< Should work even if not a power
// of 2
//// For the Discretized Gaussian
constexpr double LWE_ERROR_STDEV =
    2.0 * ((int_mod_q)1 << (PARAM_LOGQ - 1)) * PARAM_ALPHA /
    boost::math::constants::root_two_pi<double>();
constexpr double R_STDEV =
    PARAM_R / boost::math::constants::root_two_pi<
                  double>(); ///< Standard deviation of the discretized Gaussian
constexpr int_mod_q MOD_Q_MASK = PARAM_LOGQ == 8 * sizeof(int_mod_q)
                                     ? std::numeric_limits<int_mod_q>::max()
                                     : ((int_mod_q)1 << PARAM_LOGQ) - 1;

using MatrixModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, Eigen::Dynamic>;
using VectorModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, 1>;


using LWEPublicKey = MatrixModQ;
using LWESecretKey = MatrixModQ;
//typedef MatrixModQ* LWEPublicKey;
//typedef MatrixModQ* LWESecretKey;

struct LWEKeypair {
  LWEPublicKey pk;
  LWESecretKey sk;
};

using Branch = int;
using Plaintext = MatrixModQ;

struct LWECiphertext {
	// batch_size many PARAM_N by PARAM_L matrices concatenated together: N x (batch_size * L)
	MatrixModQ U;
	MatrixModQ C;
};


/// Wraps EMP to sample an integer type 
/// (works for sure with short, int, long) 
/// providing an interface acceptable to
/// std::normal_distribution
class LongAESWrapper {
public:
	typedef int_mod_q result_type;
	emp::PRG prg;
	result_type min() { return std::numeric_limits<result_type>::min(); }
	result_type max() { return std::numeric_limits<result_type>::max(); }
	result_type operator()() {
		result_type outp = 0;
		prg.random_data(&outp, sizeof(result_type));
		return outp;
	}
};

namespace emp {

/// @param result The matrix that is written to
/// @param sample_prg The PRG to sample from
/// \post Populates the matrix mod Q \p result with uniform values
///	     from the given PRG.
void UniformMatrixModQ(MatrixModQ &result, PRG &sample_prg) {
	int n = result.rows();
	int m = result.cols();
	sample_prg.random_data(result.data(), m * n * sizeof(result(0, 0)));
	for (int j = 0; j < m; ++j) {
		for (int i = 0; i < n; ++i) {
			result(i, j) &= MOD_Q_MASK;
		}
	}
}

LongAESWrapper law;
boost::function<double()> SampleStandardGaussian =
    boost::bind(boost::random::normal_distribution<>(0, 1), boost::ref(law));

/// @param stdev The standard deviation of the discretized gaussian
/// \post Returns a sample from the discretized gaussian of standard
/// distribution \p stdev centered around zero.
long SampleDiscretizedGaussian(double stdev) {
	double e = SampleStandardGaussian() * stdev;
  return boost::math::lround(e) & MOD_Q_MASK; // = mod q
}

/// @param result The matrix that is written to
/// @param stdev The standard deviation of the discretized gaussian
/// \post Populates the matrix mod Q \p result with values from
///	the discretized gaussian of standard distribution \p stdev
void DiscretizedGaussianMatrixModQ(MatrixModQ &result, double stdev) {
	int n = result.rows();
	int m = result.cols();
	for (int j = 0; j < m; ++j) {
		for (int i = 0; i < n; ++i) {
			result(i, j) = SampleDiscretizedGaussian(stdev);
		}
	}
}

template <typename IO, int NUM_BITS_PER_SENDER_INPUT>
class OTLattice : public OT<OTLattice<IO, NUM_BITS_PER_SENDER_INPUT>> {
public:
	IO *io = nullptr; ///< The `emp::IOChannel<T>` used for communication.
	PRG prg; ///< `emp::PRG` with a random seed.
	PRG crs_prg;      ///< `emp::PRG` with a seed shared between the sender and
	/// receiver for CRS generation.
	MatrixModQ
	A; ///< The `PARAM_N` by `PARAM_M` matrix that represents the lattice.
	MatrixModQ
	v[2]; ///< The two vectors that correspond to the two encryption branches.
	boost::timer::cpu_timer cpu_timer;

	int PARAM_L =
		lround(ceil(NUM_BITS_PER_SENDER_INPUT / log2(PARAM_ALPHABET_SIZE)));

	/// @param raw_plaintext A block of plaintext to encode
	/// \post Returns an appropriate (for passing to LWEEnc) object
	///       representing the given plaintext \p raw_plaintext.
	///       In particular, this implementation interprets the given plaintext
	///       `p`
	///       as an array of four length-32 bitstrings, takes the `PARAM_L`
	///       many least-significant bits, and places them (in increasing
	///       significance
	///       order) in the resulting vector.
	Plaintext EncodePlaintext(const block* raw_plaintext, int batch_size) {
		Plaintext res(PARAM_L, batch_size);
		for (int batch = 0; batch < batch_size; batch++) {
			int res_idx = 0;
			uint64_t plaintext[2];
			plaintext[0] = raw_plaintext[batch][0];
			plaintext[1] = raw_plaintext[batch][1];

			// # of encoded-message slots required to hold *half*
			// of a 128-bit message
			int lhalf = (int)(1 + (64 / log2(PARAM_ALPHABET_SIZE)));

			int n_encoded = 0;
			for (int half = 0; half <= 1; ++half) {
				vector<int_mod_q> reversed_values;
				int j = n_encoded;
				for (; j < min(PARAM_L, n_encoded + lhalf); ++j) {
					reversed_values.push_back(plaintext[half] % PARAM_ALPHABET_SIZE);
					plaintext[half] /= PARAM_ALPHABET_SIZE;
				}
				for (int k = reversed_values.size() - 1; k >= 0; --k) {
					res(res_idx, batch) = reversed_values[k];
					++res_idx;
				}
				n_encoded = j;
			}
		}

		return res;
	}

	/// @param encoded_plaintext The plaintext to be decoded
	/// \post Returns the raw plaintext corresponding to \p encoded_plaintext.
	void DecodePlaintext(block* to_return, const Plaintext& encoded_plaintext, int batch_size) {
		for (int batch = 0; batch < batch_size; batch++) {
			to_return[batch] = _mm_set_epi32(0, 0, 0, 0);

			int i = 0;
			int lhalf = (int)ceil(64 / log2(PARAM_ALPHABET_SIZE));

			for (int half = 0; half <= 1; ++half) {
				for (int j = i; j < min(PARAM_L, i + lhalf); ++j) {
					to_return[batch][half] =
						(to_return[batch][half] * PARAM_ALPHABET_SIZE) + encoded_plaintext(j, batch);
				}
				i = min(PARAM_L, i + lhalf);
			}
		}
	}

	/// @param sigma The request bit.
	/// \pre \p sigma is 0 or 1.
	/// \post Generates a key pair messy under branch `(1 - sigma)`
	///       and decryptable under branch \p sigma.
	LWEKeypair OTKeyGen(const bool *sigma, int batch_size) {
		LWESecretKey S(PARAM_N, batch_size);
		UniformMatrixModQ(S, prg);

		std::cerr << "Keygen after S:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));

		LWEPublicKey pk(PARAM_M, batch_size);
		DiscretizedGaussianMatrixModQ(pk, LWE_ERROR_STDEV);
		std::cerr << "Keygen after E:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));
		
		for (int col = 0; col < batch_size; col++) {
			// std::cout << "PK Col size: " << pk.rows() << std::endl;
			// std::cout << "V Col size: " << v[sigma[col]].rows() << std::endl;
			// std::cout << "Which v: " << sigma[col] << std::endl;			
			// std::cout << "Which col: " << col << std::endl;
			pk.col(col).noalias() -= v[sigma[col]].col(col);
		}
		pk.noalias() += (S.transpose()*A).transpose();

		std::cerr << "Keygen after arithmetic:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));

		if (DEBUG >= 2)
			std::cout << "(Receiver) Debug: A = " << A << ", pk = " << pk
			          << ", sk = " << S << endl;
		return {pk, S};
	}

	/// @param pk The public key used for encryption
	/// @param sigma The branch to encrypt on
	/// @param mu The plaintext to encrypt
	/// \pre Sigma is 0 or 1.
	/// \post Returns the ciphertext corresponding to encrypting \p mu with \p pk
	///       on branch \p sigma.
	LWECiphertext OTEnc(const LWEPublicKey &pk, Branch sigma,
	                    const Plaintext &mu, int batch_size) {
		
		LWEPublicKey branch_pk{pk + v[sigma]};

		MatrixModQ X(PARAM_M, PARAM_L * batch_size);
		DiscretizedGaussianMatrixModQ(X, R_STDEV);
		//MatrixModQ XTest = X.block(0, 0, PARAM_M, PARAM_L);
		std::cerr << "Enc after sample:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));

		MatrixModQ U = A * X; // Should be N x (L * batch_size)
		//MatrixModQ UTest = A * XTest;
		std::cerr << "Enc after U = A*X:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));


		// if (U.block(0,0,PARAM_N,PARAM_L) != UTest) {
		// 	std::cout << "U doesn't match" << std::endl;
		// }
		
		MatrixModQ C(PARAM_L, batch_size);
		//MatrixModQ CTest;
		for (int batch = 0; batch < batch_size; batch++) {
			
			// c = ((pk+vsigma).T)*x  + floor(mu*q/|Alphabet|)
			// factor of 2 corrects by the fact that we're only multiplying by
			// q/2, not by q, before dividing by the alphabet size
			MatrixModQ SubX = X.block(0, PARAM_L * batch, PARAM_M, PARAM_L);
			C.col(batch) = SubX.transpose() * branch_pk.col(batch);

			// if (batch == 0) {
			// 	CTest = XTest.transpose() * branch_pk.col(0);
			// 	std::cout << "Checking if CTest == C.col(0) before shifting"<< std::endl;
			// 	if (CTest != C.col(0)) {
			// 		std::cout << "They don't match" << std::endl;
			// 		std::cout << "C.col(0): " << C.col(0) << std::endl;
			// 		std::cout << "CTest: " << CTest << std::endl;
			// 	}
			// }
			
			for (int i = 0; i < PARAM_L; ++i) {
				C(i, batch) = C(i, batch) +
					(mu(i, batch) << (PARAM_LOGQ - (uint64_t)ceil(log2(PARAM_ALPHABET_SIZE))));
			}
			std::cerr << "Enc after arithmetic:\t"
			          << boost::timer::format(cpu_timer.elapsed(), 3,
			                                  std::string("%w\tseconds\n"));
		}
		
		// for (int i = 0; i < PARAM_L; ++i) {
		// 	CTest(i) = CTest(i) +
		// 		(mu(i, 0) << (PARAM_LOGQ - (uint64_t)ceil(log2(PARAM_ALPHABET_SIZE))));
		// }

		
		std::cerr << "Enc after c = (pk+vsig).T * X:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));

		// std::cout << "CTest col size: " << CTest.rows() << std::endl;
		// std::cout << "C col size: " << C.rows() << std::endl;
		// std::cout << "Checking if CTest == C.col(0) after shifting"<< std::endl;
		// if (C.col(0) == CTest) {
		// 	std::cout << "They match" << std::endl;
		// }
		// else {
		// 	std::cout << "They don't match" << std::endl;
		// 	std::cout << "C.col(0): " << C.col(0) << std::endl;
		// 	std::cout << "CTest: " << CTest << std::endl;
		// }

		return {U, C};
	}

	/// @param sk The secret key
	/// @param ct The ciphertext
	/// \pre \p sk is of length `n`, \p ct is of the form `(u, c)` of length `(n,
	/// 1)`
	/// \post Decrypts the ciphertext \p ct using the secret key \p sk
	///       by computing \f$ b' := c - \langle sk, u \rangle \f$ and returning
	///       - 0 if b' is closer to `0 (mod Q)` than to `Q/2`
	///       - 1 otherwise
	Plaintext OTDec(LWESecretKey &sk, LWECiphertext *ct, const bool *b, int batch_size) {
		Plaintext muprime(PARAM_L, batch_size); // Each column is the result of an OT
		for (int batch = 0; batch < batch_size; batch++) {
			MatrixModQ SubU = ct[b[batch]].U.block(0, batch * PARAM_L, PARAM_N, PARAM_L);
			//std::cout << "Ut dims: " << SubU.cols() << " x " << SubU.rows() << std::endl;
			//std::cout << "U: " << SubU << std::endl;
			muprime.col(batch) = ct[b[batch]].C.col(batch) - (SubU.transpose() * sk.col(batch));

			for (int i = 0; i < PARAM_L; ++i) {
				int_mod_q value = muprime(i, batch);
				value += ((int_mod_q)1 << (PARAM_LOGQ - 1ul -
				                           (unsigned long)ceil(log2(PARAM_ALPHABET_SIZE))));
				muprime(i, batch) = value >> (PARAM_LOGQ -
				                       (unsigned long)ceil(log2(PARAM_ALPHABET_SIZE)));
			}
		}
		return muprime;
	}

	/// \pre `crs_prg` has been initialized with a shared seed from coinflip.
	/// \post Populates `A` uniformly using rejection sampling with PRG `crs_prg`.
	void InitializeCrs() { UniformMatrixModQ(A, crs_prg); }

	/// \pre `crs_prg` has been initialized with a shared seed from coinflip
	/// \post Populates `v0`, `v1` uniformly using rejection sampling with PRG
	/// `crs_prg`.
	void GenerateCrsVectors() {
		UniformMatrixModQ(v[0], crs_prg);
		UniformMatrixModQ(v[1], crs_prg);
	}

	/// @param io The instance of the IO used for communication.
	/// \post Initializes the view of one participant of the lattice-based
	///       OT protocol.
	explicit OTLattice(IO *io) {
		this->io = io;
		A.resize(PARAM_N, PARAM_M);

	}

	/// \post Initializes `crs_prg` with a random seed shared with the other
	/// party.
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

	/// \post Initializes `crs_prg` with a random seed shared with the other
	/// party.
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
		if (std::strncmp(received_sender_dgst, computed_sender_dgst,
		                 Hash::DIGEST_SIZE) != 0) {
			// Then the strings are not equal and the sender is not following the
			// protocol.
			bool success = false;
			io->send_data(&success, sizeof(bool));
			error("Coinflip Failed\n");
		} else {
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

	int make_batch_count(int length) {
		int batch_count = length / BATCH_SIZE;
		if (length % BATCH_SIZE  > 0) {
			batch_count ++;
		}
		return batch_count;
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
  ///       encrypts each input under the received key and the corresponding
  ///       branch
	///       and sends the ciphertexts to the receiver.
	void send_impl(const block *data0, const block *data1, int length) {
		sender_coinflip(); // should only happen once
		InitializeCrs();
		
		std::cerr << "Sender CRS:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));

		int batch_count = make_batch_count(length);
		for (int ot_iter = 0; ot_iter < batch_count; ++ot_iter) {
			int batch_size = std::min(BATCH_SIZE, length - BATCH_SIZE * ot_iter);

			//std::cout << "Batch: " << ot_iter << std::endl;
			v[0].resize(PARAM_M, batch_size);
			v[1].resize(PARAM_M, batch_size);
			
			cpu_timer.start();
			// Generate new v1, v2 every time
			GenerateCrsVectors();

			// Fix me:
			// std::cout << "Sender values before encoding " << std::hex
			//           << data0[ot_iter][0] << data0[ot_iter][1] << ", "
			//           << data1[ot_iter][0] << data1[ot_iter][1] << std::dec
			//           << std::endl;

			Plaintext secret0 = EncodePlaintext(&data0[ot_iter * BATCH_SIZE], batch_size);
			Plaintext secret1 = EncodePlaintext(&data1[ot_iter * BATCH_SIZE], batch_size);

			if (DEBUG > 0)
				std::cout << "(Sender, iteration " << ot_iter
				          << ") Encoded values x0=\n"
				          << secret0 << ", x1=\n"
				          << secret1 << std::endl;

			// This might cause problems for large BATCH_SIZE
			// Too big for the stack I think. FIX ME. ALSO OPTIMIZE
			int_mod_q *pk_array = new int_mod_q[PARAM_M * batch_size];

			//std::cout << "Expected pk size: " << PARAM_M * batch_size << std::endl;
			io->recv_data(pk_array, sizeof(int_mod_q) * PARAM_M * batch_size);
			
			Eigen::Map<MatrixModQ> pk{pk_array,
			                          PARAM_M,
			                          batch_size}; // interpret memory as matrix

			if (DEBUG)
				std::cerr << "(Sender) Encrypting..." << std::endl;

			// Encrypt the two inputs
			LWECiphertext ct[2];
			ct[0] = OTEnc(pk, 0, secret0, batch_size);
			ct[1] = OTEnc(pk, 1, secret1, batch_size);

			std::cerr << "Sender after enc 0:\t"
			          << boost::timer::format(cpu_timer.elapsed(), 3,
			                                  std::string("%w\tseconds\n"));
			if (DEBUG == 1)
				std::cerr << "(Sender) Encrypted ciphertexts. Sending..." << std::endl;

			//std::cout << "Expect to send: " << batch_size * PARAM_N * PARAM_L + batch_size * PARAM_L << std::endl;
			
			// std::cout << "U0 send[0,0]: " << ct[0].U(0,0) << std::endl;
			// std::cout << "C0 recv[0,0]: " << ct[0].C(0,0) << std::endl;
			// std::cout << "U1 send[0,0]: " << ct[1].U(0,0) << std::endl;
			// std::cout << "C1 recv[0,0]: " << ct[1].C(0,0) << std::endl;
			for (int i = 0; i <= 1; ++i) {
				io->send_data(ct[i].U.data(), sizeof(int_mod_q) * PARAM_N * PARAM_L * batch_size);
				io->send_data(ct[i].C.data(), sizeof(int_mod_q) * PARAM_L * batch_size);
				//std::cout << "Sent all data" << std::endl;

			}
			

			if (DEBUG > 1) {
				std::cout << "Sender: sent ciphertext 0:\n" << ct[0].C << std::endl;
				std::cout << "Sender: sent ciphertext 1:\n" << ct[1].C << std::endl;
			}
			std::cerr << "Sender, iteration " << ot_iter << ": \t"
			          << boost::timer::format(cpu_timer.elapsed(), 3,
			                                  std::string("%w\tseconds\n"));

			delete [] pk_array;
		}
	}

	/// @param out_data Where the results of the OTs are stored
	/// @param b b The location of the choice of which secret to receive
	/// @param length The number of OT executions to be performed.
	void recv_impl(block *out_data, const bool *b, int length) {
		receiver_coinflip(); // should only happen once
		InitializeCrs();

		std::cerr << "Receiver CRS:\t"
		          << boost::timer::format(cpu_timer.elapsed(), 3,
		                                  std::string("%w\tseconds\n"));

		int batch_count = make_batch_count(length);		

		std::cout << "(Lattice OT 1, sender: performing " << length << " OTs): ";
		for (int ot_iter = 0; ot_iter < batch_count; ++ot_iter) {
			int batch_size = std::min(BATCH_SIZE, length - BATCH_SIZE * ot_iter);
			std::cout << ot_iter + 1 << "... " << std::flush;
			if (ot_iter == length - 1)
				std::cout << std::endl;


			cpu_timer.start();

			v[0].resize(PARAM_M, batch_size);
			v[1].resize(PARAM_M, batch_size);
			// Generate new v1, v2 every time
			GenerateCrsVectors();
			// std::cout << "Batch size: " << batch_size << std::endl;
			// std::cout << "V0 Col size: " << v[0].rows() << std::endl;


			// std::cout << "Branch pointer offset: " << ot_iter * BATCH_SIZE << std::endl;
			// std::cout << "Branch value: " << (Branch) b[ot_iter * BATCH_SIZE] << std::endl;
			// Generate the public key from the choice bit b
			LWEKeypair keypair = OTKeyGen(&b[ot_iter * BATCH_SIZE], batch_size);

			std::cerr << "Receiver after keygen:\t"
			          << boost::timer::format(cpu_timer.elapsed(), 3,
			                                  std::string("%w\tseconds\n"));

			// Send the public key
			// FIX ME: Not sure if this is correct
			//std::cout << "pk size: " << keypair.pk.size() << std::endl;
			io->send_data(keypair.pk.data(), sizeof(int_mod_q) * PARAM_M * batch_size);

			if (DEBUG > 0)
				std::cerr << "(Receiver) Sent public key; waiting for ctexts"
				          << std::endl;

			// Receive the ciphertexts
			int Udim = PARAM_N * PARAM_L * batch_size;
			int ct_array_len = Udim + PARAM_L * batch_size;

			int_mod_q *ct_array0 = new int_mod_q[ct_array_len];
			int_mod_q *ct_array1 = new int_mod_q[ct_array_len];
			int_mod_q *ct_array[2] = {ct_array0, ct_array1};
			LWECiphertext ct[2];
			//std::cout << "Expect to receive " << ct_array_len << std::endl;
			for (int i = 0; i <= 1; ++i) {
				//ct[i].U = new MatrixModQ[batch_size];

				io->recv_data(ct_array[i], sizeof(int_mod_q) * ct_array_len);
				ct[i].U = Eigen::Map<MatrixModQ> {ct_array[i], PARAM_N, PARAM_L * batch_size};
				ct[i].C = Eigen::Map<MatrixModQ> {ct_array[i] + Udim, PARAM_L, batch_size};
			
				if (DEBUG > 1) {
				                std::cout << "Receiver: Got ciphertext:\n"
				                << ct[b[ot_iter]].C << std::endl;
				}

				if (DEBUG >= 2) {
				                 std::cerr << "Ciphertext " << b[ot_iter] << ": (u=" << ct[b[ot_iter]].U
				                 << ",\nc=" << ct[b[ot_iter]].C << ")\n";
				}
			}

			// std::cout << "U0 recv[0,0]: " << ct[0].U(0,0) << std::endl;
			// std::cout << "C0 recv[0,0]: " << ct[0].C(0,0) << std::endl;
			// std::cout << "U1 recv[0,0]: " << ct[1].U(0,0) << std::endl;
			// std::cout << "C1 recv[0,0]: " << ct[1].C(0,0) << std::endl;
			Plaintext p = OTDec(keypair.sk, ct, &b[ot_iter * BATCH_SIZE], batch_size);
			if (DEBUG >= 1) 
				std::cout << "(Receiver, iteration " << ot_iter << ") Decrypted branch "
				          << b[ot_iter] << " to get plaintext: " << std::endl
				          << p << std::endl;

			DecodePlaintext(&out_data[ot_iter * BATCH_SIZE], p, batch_size);
			// std::cout << "Receiver value after decoding " << std::hex
			//           << out_data[ot_iter][0] << out_data[ot_iter][1] << std::dec
			//           << std::endl;

			std::cerr << "Receiver, iteration " << ot_iter << ": \t"
			          << boost::timer::format(cpu_timer.elapsed(), 3,
			                                  std::string("%w\tseconds\n"));

		}
	}
};
	/**@}*/  // doxygen end of group
}  // namespace emp
#endif  // OT_LATTICE_H__
