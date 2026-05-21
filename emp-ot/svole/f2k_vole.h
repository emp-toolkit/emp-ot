#ifndef EMP_OT_SVOLE_F2K_VOLE_H__
#define EMP_OT_SVOLE_F2K_VOLE_H__

#include "emp-ot/common/mp_gadget.h"   // ChiFoldFlavor + MultiPointGadget AuthValue contract
#include "emp-ot/svole/svole.h"
#include <limits>

// F_2 ⊂ F_{2^128} sVOLE: AuthValueF2k carrier + F2kVOLE alias over
// the generic Svole<AuthValue>. Bootstrap is Galois packing of
// M*128 raw Ferret COTs into M seed sVOLE pairs, with optional
// tiered recursion via a smaller inner Svole when M exceeds the
// threshold.

namespace emp {

// Forward declaration so the carrier's Bootstrap can reference Svole<>
// before it's fully visible (Svole.h is already included above).
template <typename AuthValue> class Svole;

// Concrete carrier + ops for F_2k sVOLE. Storage is val/mac pair
// (val-first, 32 bytes total). Static methods provide field
// arithmetic, chi-fold derivation, LPN-side ops, and the protocol
// hooks (delta-holder convention, Bootstrap, on_set_delta).
struct AuthValueF2k {
  using F = block;

  // Storage (val-first by convention; downstream emp-zk depends on
  // val in the low 64 bits of an AuthValue-shaped __uint128_t).
  F val;
  F mac;

  // -------- Field arithmetic --------
  static inline F    f_zero()              { return zero_block; }
  static inline F    f_add (F a, F b)      { return a ^ b; }
  static inline F    f_sub (F a, F b)      { return a ^ b; }
  static inline F    f_mul (F a, F b)      { block r; gfmul(a, b, &r); return r; }

  // -------- Wire-format traits --------
  // Per-tree wire ships secret_sum:F; cGGM doesn't pre-mask the per-
  // leaf LSB (α-fill is via secret_sum subtraction in MPFSS).
  static constexpr bool kHasSecretSum = true;
  static constexpr bool kClearLeafLSB = false;
  static constexpr ChiFoldFlavor kChiFoldFlavor = ChiFoldFlavor::FTyped;

  // -------- Element conversion --------
  // cGGM block leaf → AuthValueF2k (mac copied verbatim, val = 0).
  static inline AuthValueF2k auth_from_block(block leaf) {
    return AuthValueF2k{ zero_block, leaf };
  }

  // -------- Chi-fold helpers --------
  // Per-tree chi vector: hash the FS-bound chi seed, expand via
  // uni_hash_coeff_gen. Under F_2^128 the digest IS an F element,
  // so the hash output is used directly as the uni_hash seed.
  static inline void expand_chi(block chi_seed, F* chi, int64_t sz) {
    Hash hash;
    block digest = hash.hash_for_block(&chi_seed, sizeof(block));
    uni_hash_coeff_gen(chi, digest, sz);
  }

  // VW[idx] = Σ chi[i] · leaves[i].mac.
  static inline void accumulate_VW(F& VW_slot, const F* chi,
                                   const AuthValueF2k* leaves, int64_t sz) {
    F v = f_zero();
    for (int64_t i = 0; i < sz; ++i)
      v = f_add(v, f_mul(chi[i], leaves[i].mac));
    VW_slot = v;
  }

  // -------- LPN ops (Lpn<AuthValueF2k, 10>) --------
  // F_2 is XOR-only — no carry concern, so partial/final reduce are
  // no-ops and the LPN can fold all d adds in one batch.
  static constexpr int kLpnSafeAddsPerReduce =
      std::numeric_limits<int>::max();
  static inline void auth_add_into(AuthValueF2k& acc,
                                   const AuthValueF2k& x) {
    acc.val = acc.val ^ x.val;
    acc.mac = acc.mac ^ x.mac;
  }
  static inline void auth_partial_reduce(AuthValueF2k&) {}
  static inline void auth_final_reduce  (AuthValueF2k&) {}

  // -------- Svole protocol hooks --------

  // F_2k convention: BOB is the Δ-holder externally.
  static constexpr int delta_holder_party() { return BOB; }

  // Ferret samples its own Δ in its ctor. For F_2^k that block IS the
  // sVOLE Δ — read it back at Svole-ctor time.
  static inline F resolve_delta(Ferret *f) { return f->Delta; }

  // User-supplied Δ is propagated into the inner Ferret so that the
  // Galois-packed seed pairs (and downstream cGGM leaves) correlate
  // under the requested Δ.
  static inline void on_set_delta(F delta, Ferret *f) {
    bool bits[128];
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&delta);
    for (int i = 0; i < 128; ++i)
      bits[i] = (bytes[i / 8] >> (i % 8)) & 1;
    assert(bits[0] && "F2k set_delta: Δ.LSB must be 1");
    f->set_delta(bits);
  }

  // Bootstrap: Galois packing, with optional tiered nesting if the
  // main param's M would exhaust ferret_b10's amplification budget.
  struct Bootstrap {
    static void run(Svole<AuthValueF2k> &svole) {
      const int64_t M = svole_M(svole.param);
      constexpr PrimalLPNParameter base_param = tuning::ferret_b10;
      const int64_t base_M = svole_M(base_param);

      if (M > tuning::ferret_bootstrap_nest_factor * base_M) {
        // Nested: a smaller Svole (default ferret_b10) provides M seed
        // pairs. Inner's own bootstrap hits the base case (direct
        // Galois packing) since its M is below the nest threshold.
        Svole<AuthValueF2k> inner(svole.party, svole.io_,
                                  svole.malicious, base_param);
        if (svole.is_delta_holder()) inner.set_delta(svole.delta());
        inner.run(svole.carry_next_.data(), M);
      } else {
        // Base case: direct Galois packing of M * 128 raw Ferret COTs.
        std::vector<block> ferret_buf((size_t)M * 128);
        svole.pull_cots_(ferret_buf.data(), M * 128);
        GaloisFieldPacking pack;
        for (int64_t i = 0; i < M; ++i) {
          svole.carry_next_[i].val = zero_block;
          // Non-Δ-holder packs the val side from RCOT LSBs; the
          // Δ-holder keeps val = 0 (no val on the sender side).
          if (!svole.is_delta_holder()) {
            bool val_b[128];
            for (int kk = 0; kk < 128; ++kk)
              val_b[kk] = getLSB(ferret_buf[i * 128 + kk]);
            svole.carry_next_[i].val = bool_to_block(val_b);
          }
          pack.packing(&svole.carry_next_[i].mac,
                       ferret_buf.data() + i * 128);
        }
      }
    }
  };
};

// Convenience alias naming the F_2^k carrier.
template <typename AuthValue = AuthValueF2k>
using F2kVOLE = Svole<AuthValue>;

} // namespace emp
#endif
