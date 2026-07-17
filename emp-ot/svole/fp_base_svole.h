#ifndef EMP_OT_SVOLE_FP_BASE_SVOLE_H__
#define EMP_OT_SVOLE_FP_BASE_SVOLE_H__

#include "emp-ot/base_ot/co.h"
#include "emp-ot/svole/fp_utility.h"
#include "emp-tool/emp-tool.h"
#include <memory>
#include <vector>

// Bootstrap layer for FpVOLE: COPE-based seed sVOLE plus its chi-fold
// consistency check. Combines what used to be two separate files in
// emp-zk (fp_cope.h + fp_base_svole.h) into one. FpVOLE only includes
// this header to get both Cope and Base_svole.
//
// Why not Ferret for Cope's base OTs: Cope is a chosen-bit OT
// construction — the OT-receiver picks delta_bool, the OT-sender
// supplies both K0,K1. Mapping that onto raw Ferret COT requires the
// chooser to be the COT-*receiver*, but the F_p sVOLE Δ-holder
// (ALICE) must be the inner-Ferret COT-*sender* to drive the main
// MPFSS sibling-OT layer (c[j]=base[j]^K0[j], identical to the F_2k
// case). The two roles conflict; using CO directly for Cope's 61
// base OTs avoids running a second Ferret with swapped roles.

namespace emp {

// =================================================================
// Cope — COPE folding chosen-input OT into F_p sVOLE pairs.
// =================================================================

class Cope {
public:
  int party;
  int64_t m;
  IOChannel *io;
  block sid;                 // session id forwarded to the base CO
  __uint128_t delta;
  std::vector<PRG> G0, G1;
  std::unique_ptr<bool[]> delta_bool;
  __uint128_t mask;

  Cope(int party, IOChannel *io, int64_t m, block sid)
      : party(party), m(m), io(io), sid(sid) {
    mask = (__uint128_t)0xFFFFFFFFFFFFFFFFLL;
  }

  // sender
  void initialize(__uint128_t delta_in) {
    this->delta = delta_in;
    delta_bool.reset(new bool[m]);
    delta64_to_bool(delta_bool.get(), delta_in);

    std::vector<block> K(m);
    CO otco(io);
    otco.set_sid(sid);
    otco.recv(K.data(), delta_bool.get(), m);

    G0.resize(m);
    for (int64_t i = 0; i < m; ++i)
      G0[i].reseed(K.data() + i);
  }

  // recver
  void initialize() {
    std::vector<block> K(2 * m);
    PRG prg;
    prg.random_block(K.data(), 2 * m);
    CO otco(io);
    otco.set_sid(sid);
    otco.send(K.data(), K.data() + m, m);

    G0.resize(m);
    G1.resize(m);
    for (int64_t i = 0; i < m; ++i) {
      G0[i].reseed(K.data() + i);
      G1[i].reseed(K.data() + m + i);
    }
  }

  // sender: single
  __uint128_t extend() {
    std::vector<__uint128_t> w(m), v(m);
    for (int64_t i = 0; i < m; ++i) {
      G0[i].random_block((block *)(&w[i]), 1);
      extract_fp(w[i]);
    }

    io->recv_data(v.data(), m * sizeof(__uint128_t));
    __uint128_t ch[2];
    ch[0] = (__uint128_t)0;
    for (int64_t i = 0; i < m; ++i) {
      ch[1] = v[i];
      v[i] = mod(w[i] + ch[delta_bool[i]], pr);
    }

    return prm2pr(v.data());
  }

  // sender: batch
  void extend(__uint128_t *ret, int64_t size) {
    std::vector<uint64_t> w(m * size), v(m * size);
    for (int64_t i = 0; i < m; ++i) {
      G0[i].random_data_unaligned(&w[i * size], size * sizeof(uint64_t));
      for (int64_t j = 0; j < size; ++j) {
        w[i * size + j] = mod(w[i * size + j]);
      }
    }

    uint64_t ch[2];
    ch[0] = (uint64_t)0;
    for (int64_t i = 0; i < m; ++i) {
      for (int64_t j = 0; j < size; ++j) {
        io->recv_data(&v[i * size + j], sizeof(uint64_t));
        ch[1] = v[i * size + j];
        v[i * size + j] = add_mod(w[i * size + j], ch[delta_bool[i]]);
      }
    }

    prm2pr(ret, v.data(), size);
  }

  // recver: single
  __uint128_t extend(__uint128_t u) {
    std::vector<__uint128_t> w0(m), w1(m), tau(m);
    for (int64_t i = 0; i < m; ++i) {
      G0[i].random_block((block *)(&w0[i]), 1);
      G1[i].random_block((block *)(&w1[i]), 1);
      extract_fp(w0[i]);
      extract_fp(w1[i]);
      w1[i] = mod(w1[i] + u, pr);
      w1[i] = pr - w1[i];
      tau[i] = mod(w0[i] + w1[i], pr);
    }

    io->send_data(tau.data(), m * sizeof(__uint128_t));
    io->flush();

    return prm2pr(w0.data());
  }

  // recver: batch
  void extend(__uint128_t *ret, uint64_t *u, int64_t size) {
    std::vector<uint64_t> w0(m * size), w1(m * size);
    for (int64_t i = 0; i < m; ++i) {
      G0[i].random_data_unaligned(&w0[i * size], size * sizeof(uint64_t));
      G1[i].random_data_unaligned(&w1[i * size], size * sizeof(uint64_t));
      for (int64_t j = 0; j < size; ++j) {
        w0[i * size + j] = mod(w0[i * size + j]);
        w1[i * size + j] = mod(w1[i * size + j]);

        w1[i * size + j] = add_mod(w1[i * size + j], u[j]);
        w1[i * size + j] = PR - w1[i * size + j];
        uint64_t tau = add_mod(w0[i * size + j], w1[i * size + j]);
        io->send_data(&tau, sizeof(uint64_t));
      }
    }

    prm2pr(ret, w0.data(), size);
  }

  void delta64_to_bool(bool *bdata, __uint128_t u128) {
    uint64_t *ptr = (uint64_t *)(&u128);
    uint64_t in = ptr[0];
    for (int64_t i = 0; i < m; ++i) {
      bdata[i] = ((in & 0x1LL) == 1);
      in >>= 1;
    }
  }

  __uint128_t prm2pr(__uint128_t *a) {
    __uint128_t ret = (__uint128_t)0;
    __uint128_t tmp;
    for (int64_t i = 0; i < m; ++i) {
      tmp = mod(a[i] << i, pr);
      ret = mod(ret + tmp, pr);
    }
    return ret;
  }

  void prm2pr(__uint128_t *ret, __uint128_t *a, int64_t size) {
    memset(ret, 0, size * sizeof(__uint128_t));
    __uint128_t tmp;
    for (int64_t i = 0; i < m; ++i) {
      for (int64_t j = 0; j < size; ++j) {
        tmp = mod(a[i * size + j] << i, pr);
        ret[j] = mod(ret[j] + tmp, pr);
      }
    }
  }

  void prm2pr(__uint128_t *ret, uint64_t *a, int64_t size) {
    memset(ret, 0, size * sizeof(__uint128_t));
    __uint128_t tmp;
    for (int64_t i = 0; i < m; ++i) {
      for (int64_t j = 0; j < size; ++j) {
        tmp = (__uint128_t)a[i * size + j];
        tmp = mod(tmp << i, pr);
        ret[j] = (__uint128_t)add_mod(ret[j], tmp);
      }
    }
  }
};

// =================================================================
// Base_svole — seed sVOLE via Cope, with chi-fold consistency
// check (one round per triple_gen_send/recv call).
// =================================================================

// Templated on the AuthValue carrier (AuthValueFp; defined in
// fp_vole.h). Passing it as a template parameter makes the name
// lookup of AV-typed expressions dependent, so this header can
// forward-use the carrier without a complete definition here.
template <typename AuthValue> class Base_svole {
public:
  using AV = AuthValue;  // val-first carrier

  int party;
  IOChannel *io;
  std::unique_ptr<Cope> cope;
  __uint128_t Delta;

  // SENDER (ALICE = Δ-holder)
  Base_svole(int party, IOChannel *io, block sid, __uint128_t Delta)
      : party(party), io(io), Delta(Delta) {
    cope = std::make_unique<Cope>(party, io, MERSENNE_PRIME_EXP, sid);
    cope->initialize(Delta);
  }

  // RECEIVER (BOB)
  Base_svole(int party, IOChannel *io, block sid) : party(party), io(io) {
    cope = std::make_unique<Cope>(party, io, MERSENNE_PRIME_EXP, sid);
    cope->initialize();
  }

  // Sender produces (val=0, mac=cope_mac) pairs.
  void triple_gen_send(AV *share, int64_t size) {
    std::vector<__uint128_t> macs(size);
    cope->extend(macs.data(), size);
    __uint128_t b;
    cope->extend(&b, 1);
    sender_check(macs.data(), (uint64_t)b, size);
    for (int64_t i = 0; i < size; ++i)
      share[i] = AV{0, (uint64_t)macs[i]};
  }

  // Receiver produces (val=x, mac=cope_mac) pairs.
  void triple_gen_recv(AV *share, int64_t size) {
    PRG prg;
    std::vector<uint64_t> x(size + 1);
    prg.random_data_unaligned(x.data(), (size + 1) * sizeof(uint64_t));
    for (int64_t i = 0; i < size + 1; ++i) x[i] = mod(x[i]);
    std::vector<__uint128_t> macs(size);
    cope->extend(macs.data(), x.data(), size);
    __uint128_t c;
    cope->extend(&c, &x[size], 1);
    recver_check(macs.data(), x.data(), (uint64_t)c, x[size], size);
    for (int64_t i = 0; i < size; ++i)
      share[i] = AV{x[i], (uint64_t)macs[i]};
  }

  // Internal: chi-fold over raw mod-p macs (low 64 of __uint128_t).
  void sender_check(__uint128_t *macs, uint64_t b, int64_t size) {
    PRG prg;
    uint64_t seed;
    prg.random_data_unaligned(&seed, sizeof(uint64_t));
    seed = mod(seed);
    io->send_data(&seed, sizeof(uint64_t));
    std::vector<uint64_t> chi(size);
    uni_hash_coeff_gen(chi.data(), seed, size);
    uint64_t y = vector_inn_prdt_sum_red(macs, chi.data(), size);
    y = add_mod(y, b);
    uint64_t xz[2];
    io->recv_data(xz, 2 * sizeof(uint64_t));
    xz[1] = mult_mod(xz[1], (uint64_t)Delta);
    y = add_mod(y, xz[1]);
    expecting(y == xz[0], "base sVOLE check fails");
  }

  void recver_check(__uint128_t *macs, uint64_t *x, uint64_t c, uint64_t a,
                    int64_t size) {
    uint64_t seed;
    io->recv_data(&seed, sizeof(uint64_t));
    std::vector<uint64_t> chi(size);
    uni_hash_coeff_gen(chi.data(), seed, size);
    uint64_t xz[2];
    xz[0] = vector_inn_prdt_sum_red(macs, chi.data(), size);
    xz[1] = vector_inn_prdt_sum_red(x, chi.data(), size);
    xz[0] = add_mod(xz[0], c);
    xz[1] = add_mod(xz[1], a);
    io->send_data(xz, 2 * sizeof(uint64_t));
  }
};

} // namespace emp

#endif
