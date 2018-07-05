#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
#include <Eigen/Dense>

#include <algorithm>  // std::min
#include <cmath>  // std::log2, std::floor
#include <iostream>  // debug printlns
#include <random> // random_device (for reseeding)
#include <vector>

#include "emp-ot/ot.h"

constexpr int DEBUG = 0;  // 2: print ctexts, 1: minimal debug info

/** @addtogroup OT
  @{
  */

constexpr int PARAM_Q = 1024;
constexpr int PARAM_N = 300;
//constexpr int PARAM_M = PARAM_N * std::log2(PARAM_Q); // Clang doesn't like std::log2
constexpr int PARAM_M = PARAM_N * 10; // 10 = log2(1024)
// PARAM_L is a template parameter

constexpr double ALPHA = 0.1;
constexpr double PARAM_R = 0.1;
constexpr double STD_KEYGEN = ALPHA * PARAM_Q;
constexpr double STD_ENC = ALPHA * PARAM_R;

using int_mod_q = uint16_t;

using MatrixModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, Eigen::Dynamic>;
using VectorModQ = Eigen::Matrix<int_mod_q, Eigen::Dynamic, 1>;

using LWEPublicKey = MatrixModQ;
using LWESecretKey = MatrixModQ;
struct LWEKeypair { LWEPublicKey pk; LWESecretKey sk; };

using Branch     = int;
using Plaintext  = VectorModQ;
struct LWECiphertext { VectorModQ u; VectorModQ c; };

namespace emp {

// post: sets `dst` to a random integer between
//       0 and `bound` - 1 (inclusive) through
//       rejection sampling, using the given EMP PRG
void SampleBounded(int_mod_q &dst, int_mod_q bound, PRG& sample_prg) {
  int nbits_q, nbytes_q;
  if (!bound) {
    nbytes_q = sizeof(dst);
    nbits_q = 8*nbytes_q;
  } else {
    nbits_q = 1 + std::floor(std::log2(bound));
    nbytes_q = 1 + std::floor(std::log2(bound)/8);
  }
  int_mod_q rnd;
  do {
    rnd = 0;
    sample_prg.random_data(&rnd, nbytes_q);
    rnd &= ((1 << nbits_q) - 1);  // to minimize waste,
    // only sample less than
    // the next-greater power of 2
  } while (bound != 0 and rnd >= bound);
  dst = rnd;
}



// post: returns a uniform matrix mod Q generated using rejection sampling
//       with values drawn from the given PRG
MatrixModQ UniformMatrixModQ(int n, int m, PRG &sample_prg) {
  MatrixModQ to_return(n, m);
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < m; ++j) {
      SampleBounded(to_return(i, j), PARAM_Q, sample_prg);
    }
  }
  return to_return;
}

MatrixModQ DGSMatrixModQ(int n, int m, PRG &sample_prg, double sigma, double c, size_t tau) {
	MatrixModQ to_return(n, m);
	for (int i = 0; i < n; ++i) {
		for (int j = 0; j < m; ++j) {
			to_return(i, j) = sample_prg.dgs_sample(sigma, c, tau) % PARAM_Q;
		}
	}
	return to_return;
}
	
template<typename IO, int PARAM_L>
class OTLattice: public OT<OTLattice<IO, PARAM_L>> {
 public:
  IO* io = nullptr;
  PRG prg;  // FIXME for testing

  MatrixModQ A;
  MatrixModQ v[2];

  // post: returns an appropriate (for passing to LWEEnc) object
  //       representing the given plaintext
  //       In particular, this implementation interprets the given plaintext `p`
  //       as an array of four length-32 bitstrings, takes the `PARAM_L`
  //       many least-significant bits, and places them (in increasing significance
  //       order) in the resulting vector.
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

  // post: returns the raw plaintext corresponding to the given
  //       encoded plaintext
  block DecodePlaintext(const Plaintext& encoded_plaintext) {
    int a[4] {0};
    for (int i = 0; i <= PARAM_L / 32; ++i) {
      for (int j = 0; j < std::min(32, PARAM_L - (32*i)); ++j) {
        a[3-i] |= encoded_plaintext((32*i) + j) << j;
      }
    }
    return _mm_set_epi32(a[0], a[1], a[2], a[3]);
  }

  // pre : sigma (currently 0 or 1) is the request bit
  // post: generates a key pair messy under branch (1 - sigma)
  //       and decryptable under branch sigma
  // TODO: change to sample from LWE noise distribution
  //       (discretized Gaussian \bar{\Psi}_\alpha)
  LWEKeypair OTKeyGen(Branch sigma) {
    LWESecretKey S = UniformMatrixModQ(PARAM_N, PARAM_L, prg);
    //MatrixModQ E = MatrixModQ::Zero(PARAM_M, PARAM_L); // FIXME - use Gaussian instead of zeroes
    MatrixModQ E = DGSMatrixModQ(PARAM_M, PARAM_L, prg, STD_KEYGEN, 0, 12);
    LWEPublicKey pk = A.transpose()*S + E - v[sigma];
    
    if (DEBUG >= 2)
     	std::cout << "(Receiver) Debug: A = " << A << ", pk = " << pk << ", sk = " << S << endl;
    return {pk, S};
  }

  // TODO: change to sample error from discrete Gaussian, rather than Unif(0,1)
  LWECiphertext OTEnc(const LWEPublicKey &pk, Branch sigma, const Plaintext &mu) {
    LWEPublicKey branch_pk {pk + v[sigma]};
    VectorModQ x(PARAM_M);
    for (int i = 0; i < PARAM_M; ++i) {
	    //SampleBounded(x(i), 2, prg);  // Unif({0,1}^m)
	    // standard deviation, center, tau
	    x(i) = prg.dgs_sample(STD_ENC, 0, 12); // works as expected with uint16_t
    }
    VectorModQ u = A*x;
    VectorModQ c = (branch_pk.transpose() * x) + ((PARAM_Q / 2)*mu);
    return {u, c};
  }

  // pre : sk is of length n, ct is of the form (u, c) of length (n, 1)
  // post: decrypts the ciphertext `ct` using the secret key `sk`
  //       by computing b' := c - <sk, u> and returning
  //       - 0 if b' is closer to 0 (mod Q) than to Q/2
  //       - 1 otherwise
  Plaintext OTDec(LWESecretKey &sk, LWECiphertext &ct) {
    Plaintext muprime = ct.c - (sk.transpose() * ct.u);
    for (int i = 0; i < PARAM_L; ++i) {
      muprime(i) %= PARAM_Q;
      muprime(i) = muprime(i) > PARAM_Q/4 && muprime(i) <= 3*PARAM_Q/4;
    }
    return muprime;
  }

  // post: populates A, v0, v1 using a fixed-key EMP-library PRG
  //       and rejection sampling
  void InitializeCrs() {
    PRG crs_prg(fix_key);  // emp::fix_key is a library-specified constant

    A = UniformMatrixModQ(PARAM_N, PARAM_M, crs_prg);
    v[0] = UniformMatrixModQ(PARAM_M, PARAM_L, crs_prg);
    v[1] = UniformMatrixModQ(PARAM_M, PARAM_L, crs_prg);
  }

  // post: initializes the view of one participant of the lattice-based
  //       OT protocol by drawing a CRS using a fixed PRG seed
  //       and preparing a PRG to draw (nondeterministically) random bits
  //       for the LWE noise and secret
  explicit OTLattice(IO * io) {
    this->io = io;
    InitializeCrs();
  }

  // (Note: When initializing an OT object, the EMP API doesn't explicitly
  // specify whether it's in the role of sender or receiver; rather,
  // it will call either `send_impl` or `recv_impl`, according to the
  // protocol participant)

  // pre : `data0`[i] and `data1`[i] are the sender's two inputs
  //       for the `i`th OT transmission
  // post: waits for a public key `pk` from the receiver;
  //       encrypts each input under the received key and the corresponding branch;
  //       and sends the ciphertexts to the receiver
  void send_impl(const block* data0, const block* data1, int length) {
    std::cout << "OTs complete (" << PARAM_L << " bits each): ";
    int tenths_complete = 0;
    for (int ot_iter = 0; ot_iter < length; ++ot_iter) {
      if (length > 10 and ot_iter > tenths_complete * length/10) {
        ++tenths_complete;
        std::cout << ot_iter << " (" << 10*(tenths_complete -1)<< "%)... " << std::flush;
      }
      if (ot_iter == length - 1)
        std::cout << std::endl << std::flush;

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

  // pre : `out_data` indicates the location where the received values
  //         will be stored;
  //       `b` indicates the location of the choice of which secret to receive;
  //       `length` indicates the number of OT executions to be performed
  void recv_impl(block* out_data, const bool* b, int length) {
    for (int ot_iter = 0; ot_iter < length; ++ot_iter) {
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
