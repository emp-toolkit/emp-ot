#ifndef EMP_OT_SVOLE_FP_VOLE_H__
#define EMP_OT_SVOLE_FP_VOLE_H__

#include "emp-ot/svole/fp_base_svole.h"
#include "emp-ot/svole/fp_utility.h"
#include "emp-ot/svole/svole.h"
#include <vector>

// F_p sVOLE: MersennePolicy61 + FpVOLE alias over the generic
// Svole<Policy, IO>. The bootstrap runs Base_svole (COPE + chi-fold)
// for seed sVOLE pairs, then a pre-stage MPFSS+LPN to amplify into
// n_pre carry-over pairs.

namespace emp {

// Forward declaration so the Policy's Bootstrap can reference Svole<>
// before it's fully visible (svole.h is already included above).
template <typename Policy, typename IO> class Svole;

// =================================================================
// MersennePolicy61 — F_p = GF(2^61 - 1).
// =================================================================

struct MersennePolicy61 {
  using F = uint64_t;
  using K = uint64_t;
  // Val-first via the unified emp::AuthValue<F, K> template:
  // low 64 = val, high 64 = mac. Downstream emp-zk consumers
  // (ostriple.h, edabits.h) match this layout via VAL/MAC accessors.
  using AuthValue = emp::AuthValue<F, K>;

  static constexpr uint64_t PR_VAL = (1ULL << 61) - 1;
  static constexpr int M_BASIS = MERSENNE_PRIME_EXP;  // = 61, basis for COPE

  static inline F    f_zero()              { return 0; }
  static inline F    f_add (F a, F b)      { return add_mod(a, b); }
  static inline F    f_sub (F a, F b)      { return a >= b ? a - b : a + PR_VAL - b; }
  static inline F    f_mul (F a, F b)      { return mult_mod(a, b); }
  static inline bool f_eq  (F a, F b)      { return a == b; }

  static inline F    embed     (K x)       { return x; }
  static inline F    scalar_mul(K x, F y)  { return mult_mod(x, y); }

  static inline K    k_zero()              { return 0; }
  static inline K    k_add (K a, K b)      { return add_mod(a, b); }

  // AuthValue ops for the unified Lpn / Mpsvole machinery. mod-p adds
  // overflow uint64_t after ~8 unreduced accumulations, so partial
  // reduction is needed every 5 adds (matches the legacy LpnFp 5+5
  // split).
  static constexpr int kLpnSafeAddsPerReduce = 5;

  // SIMD: AuthValue is a packed 128-bit (val_low, mac_high);
  // `_mm_add_epi64` adds both lanes in one op. vec_mod brings both
  // back into [0, p).
  static inline void auth_add_into(AuthValue &acc, const AuthValue &x) {
    block *a = reinterpret_cast<block *>(&acc);
    const block *b = reinterpret_cast<const block *>(&x);
    *a = _mm_add_epi64(*a, *b);
  }
  static inline void auth_partial_reduce(AuthValue &acc) {
    block *a = reinterpret_cast<block *>(&acc);
    *a = vec_mod(*a);
  }
  static inline void auth_final_reduce(AuthValue &acc) {
    block *a = reinterpret_cast<block *>(&acc);
    *a = vec_mod(*a);
  }
  // cGGM block leaf → AuthValue: mod-p extract the low 64 as mac;
  // val starts at zero (sender side; receiver inserts val at α later).
  static inline AuthValue auth_from_block(block leaf) {
    AuthValue av{};
    av.mac = mod((uint64_t)_mm_extract_epi64(leaf, 0));
    return av;
  }
  // FS-derived chi seed: mod-p reduce the digest's low 64 to F.
  static inline F hash_to_f(block digest_b) {
    return mod((uint64_t)_mm_extract_epi64(digest_b, 0));
  }

  // -------- Svole Policy hooks --------

  // F_p convention: ALICE is the Δ-holder externally.
  static constexpr int delta_holder_party() { return ALICE; }

  // Ferret's block Δ is independent of the F_p sVOLE Δ on this side;
  // the latter must come from the user via set_delta.
  static inline F resolve_delta(Ferret * /*unused*/) { return 0; }

  // F_p Δ doesn't need to be propagated into Ferret — cGGM keeps using
  // Ferret's own block Δ for the F_2 sibling correlation; only the
  // chi-fold algebra (in Mpsvole) consumes the F_p Δ.
  static inline void on_set_delta(F /*delta*/, Ferret * /*ferret*/) {}

  // Bootstrap: COPE seed sVOLE → pre-stage MPFSS+LPN → pre_next_.
  // Fixed inner PrimalLPNParameter (ferret_b10) for the pre stage,
  // mirroring F2k's bootstrap structure. No tiered recursion —
  // ferret_b10's n is comfortably > the main param's M for all
  // b10..b13 main configurations.
  template <typename IO> struct Bootstrap {
    static void run(Svole<MersennePolicy61, IO> &svole) {
      constexpr PrimalLPNParameter pre_param = tuning::ferret_b10;
      const int64_t M     = svole_M(svole.param);
      const int64_t n_pre = svole_n(pre_param);

      // ---- Stage 1: seed sVOLE via Cope + chi-fold check ----
      //   Base_svole produces (1 + t_pre + k_pre) seed pairs.
      const int64_t triple_n = 1 + pre_param.t + pre_param.k;
      std::vector<AuthValue> seed_pairs(triple_n);
      if (svole.is_delta_holder()) {
        Base_svole<IO> bv(ALICE, svole.io_,
                          (__uint128_t)svole.delta_value_);
        bv.triple_gen_send(seed_pairs.data(), triple_n);
      } else {
        Base_svole<IO> bv(BOB, svole.io_);
        bv.triple_gen_recv(seed_pairs.data(), triple_n);
      }

      // ---- Stage 2: pre-MPFSS sibling-OT base COTs from Ferret ----
      std::vector<block> pre_base_cots(pre_param.t * pre_param.tree_depth);
      svole.pull_cots_(pre_base_cots.data(),
                       (int64_t)pre_base_cots.size());

      // ---- Stage 3: pre-MPFSS + pre-LPN → last M into pre_next_ ----
      std::vector<AuthValue> pre_vole(
          n_pre, AuthValue{k_zero(), f_zero()});
      MpsvoleSender<MersennePolicy61, IO>   pre_send(
          pre_param.t, pre_param.tree_depth, svole.io_);
      MpsvoleReceiver<MersennePolicy61, IO> pre_recv(
          pre_param.t, pre_param.tree_depth, svole.io_);
      Lpn<MersennePolicy61, 10> pre_lpn(pre_param.k);
      pre_lpn.reseed(zero_block);
      if (svole.malicious) {
        pre_send.set_malicious();
        pre_recv.set_malicious();
      }

      const int64_t pre_leaves = int64_t{1} << pre_param.tree_depth;

      if (svole.is_delta_holder()) {
        pre_send.set_cggm_delta(svole.base_ferret_->Delta);
        pre_send.set_delta(svole.delta_value_);
        pre_send.run_begin();
        for (int64_t i = 0; i < pre_param.t; ++i) {
          AuthValue *leaves_i = pre_vole.data() + i * pre_leaves;
          const block *base_i =
              pre_base_cots.data() + i * pre_param.tree_depth;
          pre_send.run_next_tree(leaves_i, base_i, (int)i,
                                 seed_pairs[i].mac);
        }
        pre_send.run_end(seed_pairs[pre_param.t]);
      } else {
        pre_recv.run_begin();
        for (int64_t i = 0; i < pre_param.t; ++i) {
          AuthValue *leaves_i = pre_vole.data() + i * pre_leaves;
          const block *base_i =
              pre_base_cots.data() + i * pre_param.tree_depth;
          uint32_t alpha = pre_recv.run_next_tree(
              leaves_i, base_i, (int)i, seed_pairs[i].mac);
          leaves_i[alpha].val = seed_pairs[i].val;
        }
        pre_recv.run_end(seed_pairs.data(), seed_pairs[pre_param.t]);
      }

      // Pre-LPN over the full n_pre, folding the k_pre carry slots
      // (seed_pairs[t_pre+1 ..]) into the t_pre-sparse vector.
      pre_lpn.compute_slice(pre_vole.data(),
                            seed_pairs.data() + pre_param.t + 1, n_pre);

      std::memcpy(svole.pre_next_.data(),
                  pre_vole.data() + (n_pre - M),
                  M * sizeof(AuthValue));
    }
  };
};

// Back-compat alias. Old call sites that used `FpVOLE<Policy, IO>`
// (or just `FpVOLE<>`) continue to work.
template <typename Policy = MersennePolicy61, typename IO = NetIO>
using FpVOLE = Svole<Policy, IO>;

} // namespace emp
#endif
