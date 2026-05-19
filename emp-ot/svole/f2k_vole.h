#ifndef EMP_OT_SVOLE_F2K_VOLE_H__
#define EMP_OT_SVOLE_F2K_VOLE_H__

#include "emp-ot/svole/svole.h"
#include <limits>

// F_2 ⊂ F_{2^128} sVOLE: F2kDefaultPolicy + F2kVOLE alias over the
// generic Svole<Policy, IO>. The bootstrap is Galois packing of M*128
// raw Ferret COTs into M seed sVOLE pairs, with optional tiered
// recursion via a smaller inner Svole when M exceeds the threshold.

namespace emp {

// Forward declaration so the Policy's Bootstrap can reference Svole<>
// before it's fully visible (Svole.h is already included above).
template <typename Policy, typename IO> class Svole;

// F_2 ⊂ F_{2^128}: default policy.
//
// K = F = block. The OT-to-sVOLE bootstrap (Galois packing) is in
// F2kDefaultPolicy::Bootstrap<IO>::run.
struct F2kDefaultPolicy {
  using F = block;
  using K = block;
  using AuthValue = emp::AuthValue<F, K>;  // {val, mac} = 32 bytes

  static inline F    f_zero()              { return zero_block; }
  static inline F    f_add (F a, F b)      { return a ^ b; }
  static inline F    f_sub (F a, F b)      { return a ^ b; }
  static inline F    f_mul (F a, F b)      { block r; gfmul(a, b, &r); return r; }
  static inline bool f_eq  (F a, F b)      { return cmpBlock(&a, &b, 1); }

  static inline F    embed     (K x)       { return x; }
  static inline F    scalar_mul(K x, F y)  { return f_mul(x, y); }

  static inline K    k_zero()              { return zero_block; }
  static inline K    k_add (K a, K b)      { return a ^ b; }

  // AuthValue ops for the unified Lpn / Mpsvole machinery.
  // F_2 is XOR-only — no carry concern, so partial/final reduce are
  // no-ops and the LPN can fold all d adds in one batch.
  static constexpr int kLpnSafeAddsPerReduce =
      std::numeric_limits<int>::max();
  static inline void auth_add_into(AuthValue &acc, const AuthValue &x) {
    acc.val = acc.val ^ x.val;
    acc.mac = acc.mac ^ x.mac;
  }
  static inline void auth_partial_reduce(AuthValue &) {}
  static inline void auth_final_reduce  (AuthValue &) {}
  // cGGM block leaf → AuthValue (mac copied verbatim, val implicit 0).
  static inline AuthValue auth_from_block(block leaf) {
    return AuthValue{ zero_block, leaf };
  }
  // FS-derived chi seed: under F_2^128 the hash digest IS an F element.
  static inline F hash_to_f(block digest_b) { return digest_b; }

  // -------- Svole Policy hooks --------

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
  template <typename IO> struct Bootstrap {
    static void run(Svole<F2kDefaultPolicy, IO> &svole) {
      const int64_t M = svole_M(svole.param);
      constexpr PrimalLPNParameter base_param = tuning::ferret_b10;
      const int64_t base_M = svole_M(base_param);

      if (M > tuning::ferret_bootstrap_nest_factor * base_M) {
        // Nested: a smaller Svole (default ferret_b10) provides M seed
        // pairs. Inner's own bootstrap hits the base case (direct
        // Galois packing) since its M is below the nest threshold.
        Svole<F2kDefaultPolicy, IO> inner(svole.party, svole.io_,
                                          svole.malicious, base_param);
        if (svole.is_delta_holder()) inner.set_delta(svole.delta());
        inner.extend(svole.pre_next_.data(), M);
      } else {
        // Base case: direct Galois packing of M * 128 raw Ferret COTs.
        std::vector<block> ferret_buf((size_t)M * 128);
        svole.pull_cots_(ferret_buf.data(), M * 128);
        GaloisFieldPacking pack;
        for (int64_t i = 0; i < M; ++i) {
          svole.pre_next_[i].val = F2kDefaultPolicy::k_zero();
          // Non-Δ-holder packs the val side from RCOT LSBs; the
          // Δ-holder keeps val = 0 (no val on the sender side).
          if (!svole.is_delta_holder()) {
            bool val_b[128];
            for (int kk = 0; kk < 128; ++kk)
              val_b[kk] = getLSB(ferret_buf[i * 128 + kk]);
            svole.pre_next_[i].val = bool_to_block(val_b);
          }
          pack.packing(&svole.pre_next_[i].mac,
                       ferret_buf.data() + i * 128);
        }
      }
    }
  };
};

// Back-compat alias. Old call sites that used `F2kVOLE<Policy, IO>`
// (or just `F2kVOLE<>`) continue to work.
template <typename Policy = F2kDefaultPolicy, typename IO = NetIO>
using F2kVOLE = Svole<Policy, IO>;

} // namespace emp
#endif
