#ifndef OT_LATTICE_H__
#define OT_LATTICE_H__
extern "C" {
#include <dgs/dgs_gauss.h>
}
#include <Eigen/Dense>

#include <cmath>  // std::log2, std::floor
#include <iostream>  // debug printlns
#include <memory> // unique_ptr
#include <random> // random_device (for reseeding)
#include <vector>

#include "emp-ot/ot.h"

constexpr bool DEBUG = 0;

/** @addtogroup OT
  @{
  */

constexpr int PARAM_Q = 100;
constexpr int PARAM_N = 500;
constexpr int PARAM_M = 700;
constexpr int PARAM_L = 128;  // Message length
constexpr double PARAM_R = 7.0;
constexpr double PARAM_ALPHA = 1.0 / (PARAM_M * PARAM_M * PARAM_M);

using MatrixModQ = Eigen::Matrix<uint16_t, Eigen::Dynamic, Eigen::Dynamic>;
using VectorModQ = Eigen::Matrix<uint16_t, Eigen::Dynamic, 1>;

using LWEPublicKey = MatrixModQ;
using LWESecretKey = MatrixModQ;
struct LWEKeypair { LWEPublicKey pk; LWESecretKey sk; };

using Branch     = int;
using Plaintext  = VectorModQ;
struct LWECiphertext { VectorModQ u; VectorModQ c; };

namespace emp {

// post: uses SystemRandom to reseed the given PRG
void ReseedPrg(PRG& prg_to_reseed, std::random_device &rd) {
  auto seed = std::unique_ptr<__m128i>(new __m128i);
  *seed = _mm_set_epi32(rd(), rd(), rd(), rd());
  prg_to_reseed.reseed(reinterpret_cast<void*>(seed.get()), 0);
}

// post: sets `dst` to a random integer between
//       0 and `bound` - 1 (inclusive) through
//       rejection sampling, using the given EMP PRG
void SampleBounded(uint16_t &dst, uint16_t bound, PRG& sample_prg) {
  int nbits_q, nbytes_q;
  if (!bound) {
    nbytes_q = sizeof(dst);
    nbits_q = 8*nbytes_q;
  } else {
    nbits_q = 1 + std::floor(std::log2(bound));
    nbytes_q = 1 + std::floor(std::log2(bound)/8);
  }
  uint16_t rnd;
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

template<typename IO>
class OTLattice: public OT<OTLattice<IO>> {
 public:
  IO* io = nullptr;
  PRG prg;  // hack; can't initialize without fix_key without _rdrand
  // must re-seed in order to get dynamic-seeded PRG
  std::random_device rd;

  MatrixModQ A;
  MatrixModQ v[2];

  // post: returns an appropriate (for passing to LWEEnc) object
  //       representing the given plaintext
  //       In particular, this implementation interprets the given plaintext `p`
  //       as an array of four 32-bit integers and encodes the number as a
  //       byte array which preserves the numbers' order and encodes them in a
  //       big-endian manner
  Plaintext EncodePlaintext(block raw_plaintext) {
    VectorModQ to_return(PARAM_L);
    int a[4];
    // indices given to _mm_extract_epi32 start from the *right*
    a[0] = _mm_extract_epi32(raw_plaintext, 3);
    a[1] = _mm_extract_epi32(raw_plaintext, 2);
    a[2] = _mm_extract_epi32(raw_plaintext, 1);
    a[3] = _mm_extract_epi32(raw_plaintext, 0);


    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 32; ++j) {  // within each int, go right to left
        to_return((32*i) + (31-j)) = (a[i] & (1 << j)) >> j;
      }
    }
    return to_return;
  }

  // post: returns the raw plaintext corresponding to the given
  //       encoded plaintext
  block DecodePlaintext(const Plaintext& encoded_plaintext) {
    int a[4] {0};
    for (int i = 0; i < 4; ++i) {  // iterate over ints LTR
      for (int j = 0; j < 32; ++j) {
        a[i] |= encoded_plaintext((32*i) + (31-j)) << j;
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
    LWESecretKey S = UniformMatrixModQ(PARAM_M, PARAM_L, prg);
    MatrixModQ E = MatrixModQ::Zero(PARAM_M, PARAM_L); // FIXME - use Gaussian instead of zeroes
    LWEPublicKey pk = A.transpose()*S + E - v[sigma];

    // if (DEBUG)
    // 	std::cout << "(Receiver) Debug: pk = " << pk << ", sk = " << s << endl;
    return {pk, S};
  }

  // TODO: change to sample error from discrete Gaussian, rather than Unif(0,1)
  LWECiphertext OTEnc(const LWEPublicKey &pk, Branch sigma, const Plaintext &mu) {
    LWEPublicKey BranchPk {pk + v[sigma]};
    VectorModQ x(PARAM_M);
    for (int i = 0; i < PARAM_M; ++i) {
      SampleBounded(x(i), 2, prg);  // Unif({0,1}^m)
    }
    VectorModQ u = A*x;
    VectorModQ c = (pk.transpose() * x) + (PARAM_Q / 2)*mu;
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
    prg = PRG {fix_key};

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
    ReseedPrg(prg, rd);

    // dgs_disc_gauss_dp_init(stdev, center, cutoff # of stdevs, algorithm)
    // lwe_error_dist = dgs_disc_gauss_dp_init(PARAM_ALPHA * PARAM_N, 0, 12, DGS_DISC_GAUSS_UNIFORM_TABLE);

    if (DEBUG)
      std::cout << "Initialized!" << std::endl;  // DEBUG
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
    for (int ot_iter = 0; ot_iter < length; ++ot_iter) {
      if (!(ot_iter % (length / 10)))
        std::cout << ot_iter << " (" << (ot_iter / (length/10))*10 << "%)... " << std::flush;
      if (ot_iter == length - 1)
        std::cout << std::endl << std::flush;

      Plaintext secret0 = EncodePlaintext(data0[ot_iter]);
      Plaintext secret1 = EncodePlaintext(data1[ot_iter]);

      if (DEBUG)
        std::cerr << "(Sender, iteration " << ot_iter << ") Initialized with values x0=" << secret0 << ", x1=" << secret1 << std::endl;

      uint16_t pk_array[PARAM_M * PARAM_L];
      io->recv_data(pk_array, sizeof(pk_array[0]) * PARAM_M * PARAM_L);
      Eigen::Map<MatrixModQ> pk {pk_array, PARAM_M, PARAM_L};  // interpret memory as matrix

      if (DEBUG)
        std::cerr << "(Sender) Encrypting..." << std::endl;

      // Encrypt the two inputs
      LWECiphertext ct[2];
      ct[0] = OTEnc(pk, 0, secret0);
      ct[1] = OTEnc(pk, 1, secret1);

      if (DEBUG)
        std::cerr << "(Sender) Encrypted. Sending ciphertexts..." << std::endl;
      if (DEBUG) {
        std::cerr << "Sending Ciphertext 0: (" << ct[0].u << ", " << ct[0].c << ")\n"
          << "Sending Ciphertext 1: (" << ct[1].u << ", " << ct[1].c << ")\n";
      }

      for (int i = 0; i <= 1; ++i) {
        io->send_data(ct[i].u.data(), sizeof(uint16_t) * ct[i].u.size());
        io->send_data(ct[i].c.data(), sizeof(uint16_t) * ct[i].c.size());
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
      io->send_data(keypair.pk.data(), sizeof(uint16_t) * keypair.pk.size());

      if (DEBUG)
        std::cerr << "(Receiver) Sent public key; waiting for ctexts" << std::endl;

      uint16_t ct_array[2*(PARAM_N+PARAM_L)];
      io->recv_data(ct_array, sizeof(uint16_t) * (2*(PARAM_N+PARAM_L)));

      LWECiphertext ct[2];

      ct[0] = LWECiphertext {
        Eigen::Map<VectorModQ> {ct_array, PARAM_N, 1},
          Eigen::Map<VectorModQ> {ct_array + PARAM_N, PARAM_L, 1}
      };

      ct[1] = LWECiphertext {
        Eigen::Map<VectorModQ> {ct_array + PARAM_N + PARAM_L, PARAM_N, 1},
          Eigen::Map<VectorModQ> {ct_array + PARAM_N + (PARAM_N + PARAM_L), PARAM_L, 1}
      };

      if (DEBUG)
        std::cerr << "(Receiver) Received serialized ciphertexts." << std::endl;

      Plaintext p = OTDec(keypair.sk, ct[b[ot_iter]]);  // choose ciphertext according to selection bit

      if (DEBUG)
        std::cerr << "(Receiver, iteration " << ot_iter << ") Decrypted branch " << b[ot_iter] << " to get plaintext " << p << std::endl;

      out_data[ot_iter] = DecodePlaintext(p);
    }
  }
};
/**@}*/  // doxygen end of group
}  // namespace emp
#endif  // OT_LATTICE_H__
