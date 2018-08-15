// Peikert, Vaikuntanathan, Waters (STOC 2008) 
// Learning With Errors-based OT protocol

#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <Eigen/Dense>  // for linear algebra routines

#include <algorithm>  // std::min
#include <cmath>  // std::log2, std::floor, std::fmod

#include <limits>   // std::numeric_limits

#include "emp-ot/ot.h"

#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/random/normal_distribution.hpp>
#include <boost/random/random_device.hpp>

/** @addtogroup OT
    @{
*/

constexpr int BATCH_SIZE = 32; ///< The number of OTs to perform at a time (performance optimization).
using int_mod_q = uint64_t;

// Parameters for 128-bit OT
constexpr uint64_t PARAM_LOGQ = 64; ///< $\log_2(Modulus)$
constexpr int PARAM_N = 1000;       ///< Number of rows of `A`
constexpr int PARAM_M = 128128;     ///< Number of columns of `A`
constexpr double PARAM_ALPHA = 2.133e-14;
constexpr double PARAM_R = 8.363e7;
constexpr int PARAM_ALPHABET_SIZE = 256;

// Parameters for single-bit OT
// constexpr uint64_t PARAM_LOGQ = 64; ///< Modulus
// constexpr int PARAM_N = 670;        ///< Number of rows of `A`
// constexpr int PARAM_M = 85888;      ///< Number of columns of `A`
// constexpr double PARAM_ALPHA = 5.626e-12;
// constexpr double PARAM_R = 7.876e7;
// constexpr int PARAM_ALPHABET_SIZE = 2; 


constexpr double LWE_ERROR_STDEV = 
    2.0 * ((int_mod_q)1 << (PARAM_LOGQ - 1)) * PARAM_ALPHA /
    boost::math::constants::root_two_pi<double>();  ///< Standard deviation of the key-generation rounded Gaussian
constexpr double R_STDEV =
    PARAM_R / boost::math::constants::root_two_pi<
                  double>(); ///< Standard deviation of the encryption-time rounded Gaussian
constexpr int_mod_q MOD_Q_MASK = (PARAM_LOGQ == 8 * sizeof(int_mod_q))
                                     ? std::numeric_limits<int_mod_q>::max()
                                     : ((int_mod_q)2 << (PARAM_LOGQ-1)) - 1;

using MatrixModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, Eigen::Dynamic>;

using LWEPublicKey = MatrixModQ;
using LWESecretKey = MatrixModQ;

struct LWEKeypair {
  LWEPublicKey pk;
  LWESecretKey sk;
};

using Branch = int;
using Plaintext = MatrixModQ;

struct LWECiphertext {

	// curr_batch_size many PARAM_N by PARAM_L matrices concatenated together: N x (curr_batch_size * L)
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
	uint64_t n = result.rows();
	uint64_t m = result.cols();
	for (uint64_t j = 0; j < m; ++j) {
		sample_prg.random_data(&result(0, j), n*sizeof(int_mod_q));
		for (uint64_t i = 0; i < n; ++i) {
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
	for (int j = 0; j < m; ++j) {  // j, i loop order because column-major
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
	PRG crs_prg;  ///< `emp::PRG` with a seed shared between the sender and
	/// receiver for CRS generation.
	MatrixModQ
	A; ///< The `PARAM_N` by `PARAM_M` matrix that represents the lattice.
	MatrixModQ
	v[2]; ///< The two vectors that correspond to the two encryption branches.

	int PARAM_L =
		lround(ceil(NUM_BITS_PER_SENDER_INPUT / log2(PARAM_ALPHABET_SIZE)));

	/// @param raw_plaintext A pointer to `curr_batch_size` many blocks
	///        of plaintext to encode
	/// @param curr_batch_size The number of plaintexts in this batch
	/// \post Returns an appropriate (for passing to LWEEnc) object
	///       representing the given plaintexts \p raw_plaintext.
	///       In particular, this implementation interprets each given plaintext
	///       `p`
	///       as an array of four length-32 bitstrings, takes the `PARAM_L`
	///       many least-significant bits, and places them (in increasing
	///       significance
	///       order) in the corresponding column of the resulting matrix.
	Plaintext EncodePlaintext(const block* raw_plaintext, int curr_batch_size) {
		Plaintext res(PARAM_L, curr_batch_size);
		for (int batch = 0; batch < curr_batch_size; batch++) {
			int res_idx = 0;
			uint64_t plaintext[2];
			plaintext[0] = raw_plaintext[batch][0];
			plaintext[1] = raw_plaintext[batch][1];

			int bits_encoded = 0;
			int bits_per_entry = log2(PARAM_ALPHABET_SIZE);
			uint64_t value_mask = (1ul << (unsigned)bits_per_entry) - 1ul;
			int_mod_q tmp = 0;  // used for temporarily storing partial value overlapping the halves

			// encode bits from the first half -- raw_plaintext[0] gives the *lower-order* 64 bits
			while (bits_encoded < 64 and (bits_encoded / bits_per_entry) < PARAM_L) {
				if (bits_encoded + bits_per_entry <= 64) {  // case 1: can encode full value
					res(res_idx++, batch) = (plaintext[0] >> bits_encoded) & value_mask;
					bits_encoded += bits_per_entry;
				} else {  // case 2: must encode partial value, getting rest from second plaintext
					tmp = plaintext[0] >> (bits_encoded);
					break;
				}
			}

			// if necessary, and if we haven't encoded enough bits already, handle partial number
			int bits_encoded_second_half = 0;
			if (64 % bits_per_entry != 0 and (bits_encoded / bits_per_entry) < PARAM_L) {
				bits_encoded_second_half = bits_per_entry - (64 % bits_per_entry);
				auto beginning_of_second_half = plaintext[1] & ((1ul << (unsigned)bits_encoded_second_half) - 1ul);
				tmp |= beginning_of_second_half << (unsigned)(64 % bits_per_entry);
				res(res_idx++, batch) = tmp;
				bits_encoded = 64;
			}

			// encode as many bits of the second half as necessary (if any)
			// raw_plaintext[1] gives the *higher-order* 64 bits
			while ((bits_encoded + bits_encoded_second_half) / bits_per_entry < PARAM_L) {
				res(res_idx++, batch) = (plaintext[1] >> bits_encoded_second_half) & value_mask;
				bits_encoded_second_half += bits_per_entry;
			}
		}

		return res;
	}

	/// @param to_return A pointer to the blocks that the plaintext will be written to
	/// @param encoded_plaintext The plaintexts to be decoded
	/// \pre  The number of columns in \p encoded_plaintext equals the number of
	///       blocks pointed to by \p to_return.
	/// \post For each encoded plaintext, writes the raw plaintext corresponding to it
	///       in the corresponding block in \p to_return
	void DecodePlaintext(block* to_return, const Plaintext& encoded_plaintext, int curr_batch_size) {
		for (int batch = 0; batch < curr_batch_size; batch++) {
			//ptext0 will be the lower-order 64 bits, ptext1 the higher-order 64
			uint64_t ptext0{0}, ptext1{0};
			auto bits_per_entry = static_cast<unsigned>(log2(PARAM_ALPHABET_SIZE));
			
			unsigned bits_decoded = 0;
			for (int i = 0; i < PARAM_L; ++i) {
				if (bits_decoded < 64 and bits_decoded + bits_per_entry <= 64) {
					// case 1: handle value solely in lower-order 64 bits 
					ptext0 |= encoded_plaintext(i, batch) << bits_decoded;
				} else if (bits_decoded < 64 and bits_decoded + bits_per_entry > 64) {
					// case 2: handle value straddling the two halves
					auto current = encoded_plaintext(i, batch);
					ptext0 |= (current & ((1ul << unsigned(64 - bits_decoded)) - 1ul)) << bits_decoded;
					current >>= unsigned(64 - bits_decoded);
					ptext1 = current;
				} else if (bits_decoded < 128 and bits_decoded + bits_per_entry <= 128) {
					// case 3: handle usual case, with value solely in higher-order 64 bits
					ptext1 |= encoded_plaintext(i, batch) << (bits_decoded - 64);
				} else {
					// case 4: value solely in higher-order bits, but not enough space
					auto current = encoded_plaintext(i, batch);
					ptext1 |= (current & ((1ul << unsigned(128 - bits_decoded)) - 1ul)) << (bits_decoded - 64);	
				}
				bits_decoded += bits_per_entry;
			}
			to_return[batch][0] = ptext0;
			to_return[batch][1] = ptext1;
		}
	}

	/// @param sigma points to an array of \p curr_batch_size many request bits,
	///        one for each OT in the batch.
	/// \pre The length of \p sigma is \p curr_batch_size.
	/// \post For each bit `b` in \p sigma, generates a key pair messy
	///       under branch `(1 - b)` and decryptable under branch `b`.
	LWEKeypair OTKeyGen(const bool *sigma, int curr_batch_size) {
		LWESecretKey S(PARAM_N, curr_batch_size);
		UniformMatrixModQ(S, prg);

		LWEPublicKey pk(PARAM_M, curr_batch_size);
		DiscretizedGaussianMatrixModQ(pk, LWE_ERROR_STDEV);
		
		for (int batch = 0; batch < curr_batch_size; batch++) {

			pk.col(batch).noalias() -= v[sigma[batch]].col(batch);
		}
		pk.noalias() += (S.transpose()*A).transpose();

		return {pk, S};
	}

	/// @param pk The matrix of public keys used for encryption
	/// @param sigma The branch to encrypt on
	/// @param mu The matrix of plaintexts to encrypt
	/// @param curr_batch_size The number of OTs that are in the batch.
	/// \pre Sigma is 0 or 1.
	/// \post Returns the ciphertexts corresponding to encrypting each \p mu with
	///       corresponding \p pk on branch \p sigma.
	LWECiphertext OTEnc(const LWEPublicKey &pk, Branch sigma,
	                    const Plaintext &mu, int curr_batch_size) {
		
		LWEPublicKey branch_pk{pk + v[sigma]};

		MatrixModQ E(PARAM_M, PARAM_L * curr_batch_size);
		DiscretizedGaussianMatrixModQ(E, R_STDEV);

		MatrixModQ U = A * E; // Should be N x (L * curr_batch_size)
		
		MatrixModQ C(PARAM_L, curr_batch_size);
		for (int batch = 0; batch < curr_batch_size; batch++) {
			// Compute C = ((pk+vsigma).T)*E  + floor(mu*q/|Alphabet|)
			MatrixModQ SubE = E.block(0, PARAM_L * batch, PARAM_M, PARAM_L);
			C.col(batch) = SubE.transpose() * branch_pk.col(batch);
			
			for (int i = 0; i < PARAM_L; ++i) {
				C(i, batch) = C(i, batch) +
					(mu(i, batch) << (PARAM_LOGQ - (uint64_t)log2(PARAM_ALPHABET_SIZE)));
			}
		}
		
		return {U, C};
	}

	/// @param sk The matrix of secret keys
	/// @param ct A pointer to ciphertexts
	/// \pre \p sk has `curr_batch_size` many columns, \p ct has curr_batch_size many ciphertexts
	///      \p b is of length curr_batch_size
	/// \post Decrypts each ciphertext in \p ct  using the corresponding secret key SK in \p sk
	///       by computing \f$ b' := c - \langle SK, u \rangle \f$ and
	///       determining which partition of the modspace the result falls into.
	///       see the implementation document for more details.
	Plaintext OTDec(LWESecretKey &sk, LWECiphertext *ct, const bool *b, int curr_batch_size) {
		Plaintext muprime(PARAM_L, curr_batch_size); // Each column is the result of an OT

		for (int batch = 0; batch < curr_batch_size; batch++) {
			MatrixModQ SubU = ct[b[batch]].U.block(0, batch * PARAM_L, PARAM_N, PARAM_L);
			muprime.col(batch) = ct[b[batch]].C.col(batch) - (SubU.transpose() * sk.col(batch));

			for (int i = 0; i < PARAM_L; ++i) {
				int_mod_q value = muprime(i, batch);
				value += ((int_mod_q)1 << (PARAM_LOGQ - 1ul -
				                           (unsigned long)log2(PARAM_ALPHABET_SIZE)));
				muprime(i, batch) = value >> (PARAM_LOGQ -
				                       (unsigned long)log2(PARAM_ALPHABET_SIZE));
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
			error("Coinflip Failed");
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
			// Then the strings are not equal
			// and the sender is not following the protocol.
			bool success = false;
			io->send_data(&success, sizeof(bool));
			error("Coinflip Failed");
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

	// make_batch_count takes in a number of OT executions to perform
	// and returns the number of batches it will take to perform the executions.
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
		sender_coinflip();
		InitializeCrs();

		int batch_count = make_batch_count(length);
		for (int batch_num = 0; batch_num < batch_count; ++batch_num) {
			int curr_batch_size = std::min(BATCH_SIZE, length - (BATCH_SIZE * batch_num));

			v[0].resize(PARAM_M, curr_batch_size);
			v[1].resize(PARAM_M, curr_batch_size);
			GenerateCrsVectors();  // populate v0 and v1

			Plaintext secret0 = EncodePlaintext(&data0[batch_num * BATCH_SIZE], curr_batch_size);
			Plaintext secret1 = EncodePlaintext(&data1[batch_num * BATCH_SIZE], curr_batch_size);

			int_mod_q *pk_array = new int_mod_q[PARAM_M * curr_batch_size];
			io->recv_data(pk_array, sizeof(int_mod_q) * PARAM_M * curr_batch_size);
			Eigen::Map<MatrixModQ> pk{pk_array,
			                          PARAM_M,
			                          curr_batch_size}; // interpret memory as matrix

			// Encrypt the two inputs, then send the ciphertexts
			LWECiphertext ct[2];
			ct[0] = OTEnc(pk, 0, secret0, curr_batch_size);
			ct[1] = OTEnc(pk, 1, secret1, curr_batch_size);
			for (int i = 0; i <= 1; ++i) {
				io->send_data(ct[i].U.data(), sizeof(int_mod_q) * PARAM_N * PARAM_L * curr_batch_size);
				io->send_data(ct[i].C.data(), sizeof(int_mod_q) * PARAM_L * curr_batch_size);
			}

			delete[] pk_array;
		}
	}

	/// @param out_data Where the results of the OTs are stored
	/// @param b b The location of the choice of which secret to receive
	/// @param length The number of OT executions to be performed.
	void recv_impl(block *out_data, const bool *b, int length) {
		receiver_coinflip();
		InitializeCrs();

		int batch_count = make_batch_count(length);
		for (int batch_num = 0; batch_num < batch_count; ++batch_num) {
			// curr_batch_size is the number of executions in the current batch
			int curr_batch_size = std::min(BATCH_SIZE, length - (BATCH_SIZE * batch_num));

			v[0].resize(PARAM_M, curr_batch_size);
			v[1].resize(PARAM_M, curr_batch_size);

			GenerateCrsVectors();

			// Generate the public key from the choice bit b
			LWEKeypair keypair = OTKeyGen(&b[batch_num * BATCH_SIZE], curr_batch_size);

			// Send the public key
			io->send_data(keypair.pk.data(), sizeof(int_mod_q) * PARAM_M * curr_batch_size);

			// Receive the ciphertexts
			int Udim = PARAM_N * PARAM_L * curr_batch_size;  // horizontal dimension of the matrix U
			int ct_array_len = Udim + PARAM_L * curr_batch_size;
			int_mod_q *ct_array = new int_mod_q[ct_array_len];
			LWECiphertext ct[2];
			for (int i = 0; i <= 1; ++i) {
				io->recv_data(ct_array, sizeof(int_mod_q) * ct_array_len);
				ct[i].U = Eigen::Map<MatrixModQ> {ct_array, PARAM_N, PARAM_L * curr_batch_size};
				ct[i].C = Eigen::Map<MatrixModQ> {ct_array + Udim, PARAM_L, curr_batch_size};
			}

			Plaintext p = OTDec(keypair.sk, ct, &b[batch_num * BATCH_SIZE], curr_batch_size);
			DecodePlaintext(&out_data[batch_num * BATCH_SIZE], p, curr_batch_size);

			delete []ct_array;
		}
	}
};
	/**@}*/  // doxygen end of group
}  // namespace emp
#endif  // OT_LATTICE_H__
