#ifndef EMP_OT_MP_GADGET_H__
#define EMP_OT_MP_GADGET_H__

#include "emp-ot/common/cggm.h"
#include "emp-ot/tuning.h"   // kConsistCheckCotNum
#include <emp-tool/emp-tool.h>
#include <type_traits>
#include <vector>

// Unified multi-point sibling-OT gadget. Driven `tree_n` times by an
// outer streaming extension (Ferret RCOT or sVOLE). One template
// class subsumes all three current shapes:
//
//   Ferret MPCOT (F_2 RCOT)    : AuthValue=AuthValueFerret (single
//                                 `block mac` field), no per-tree
//                                 `secret_sum` on wire, cGGM with
//                                 kClearLeafLSB=true (α-fill via
//                                 the leveled-Δ XOR closure),
//                                 F_2k-packed chi-fold.
//   Mpsvole (F_2k / F_p sVOLE) : AuthValue=AuthValueF2k/AuthValueFp
//                                 (val+mac pair), per-tree
//                                 `secret_sum:F` on wire,
//                                 kClearLeafLSB=false (α-fill via
//                                 secret_sum subtraction), F-typed
//                                 chi-fold.
//
// AuthValue contract (the carrier type itself provides everything):
//   using F                                       — the field type
//   F mac;                                        — mac storage
//   [F val;]                                      — sVOLE only
//   static F   f_zero()/f_add/f_sub/f_mul         — field arithmetic
//   static AuthValue auth_from_block(block leaf)  — cGGM leaf wrap
//   static void expand_chi(block, F*, int64_t)    — FS chi
//   static void accumulate_VW(F&, const F*, const AuthValue*, int64_t)
//                                                 — VW[i] = Σ chi·mac
//   static constexpr bool          kHasSecretSum  — wire flag
//   static constexpr bool          kClearLeafLSB  — cGGM flag
//   static constexpr ChiFoldFlavor kChiFoldFlavor — F2kPacked|FTyped
//
// Two run_end variants are provided; the caller picks the one
// matching their kChiFoldFlavor. Calling the wrong one trips a
// static_assert at compile time.

namespace emp {

// The F2kPacked consistency check packs the chi-fold transcript hash
// into a 2-block buffer. Catch a future digest-size change instead of
// silently writing past the end of `block dig[2]`.
static_assert(Hash::DIGEST_SIZE == 2 * (int)sizeof(block),
              "MultiPointGadget assumes a 2-block (32-byte) digest");

enum class ChiFoldFlavor {
  F2kPacked,   // sender ships bool[128] x_prime + 2-block digest;
               // receiver derives x_prime from XOR(chi_alpha) and the
               // chi-check region LSBs. Used by Ferret MPCOT.
  FTyped,      // sender ships F x_star + 1-block digest; receiver
               // computes x_star = Σ chi_α·val + triple.val. Used by
               // Mpsvole (F_2k + F_p).
};

// Bit-0-set mask. Used in the F2kPacked α-fill path: reconstructed
// leaf carries the choice bit at bit 0. Mirror of the value baked
// into cggm::detail::kCggmLsbClearMask. Lives at file scope so both
// sides of the gadget agree.
inline constexpr block lsb_only_mask = makeBlock(0LL, 1LL);

// =================================================================
// MultiPointGadgetSender — Δ-holder side.
// =================================================================

template <typename AuthValue>
class MultiPointGadgetSender {
public:
  using F = typename AuthValue::F;

  IOChannel *io;
  bool      is_malicious = false;
  int64_t   tree_n;
  int64_t   tree_depth;
  int64_t   leave_n;

  // cGGM uses cggm_delta (block); chi-fold under FTyped uses delta (F).
  // For F_2k Ferret/Svole the two values coincide; for F_p Svole they
  // are independent. F2kPacked chi-fold reads cggm_delta directly.
  block cggm_delta = zero_block;
  F     delta      = AuthValue::f_zero();

  PRG prg;
  std::vector<F>      consist_check_VW;
  GaloisFieldPacking  pack;   // F2kPacked only.

  // Per-tree scratch — sized once at construction (or on set_malicious
  // for chi) instead of std::vector ctor per run_next_tree call.
  std::vector<block> K0;
  std::vector<block> c;
  std::vector<block> leaves_block;  // sized only when kHasSecretSum
  std::vector<F>     chi;           // sized only when is_malicious

  MultiPointGadgetSender(int64_t t, int64_t td, IOChannel *io_in)
      : io(io_in), tree_n(t), tree_depth(td),
        leave_n(int64_t{1} << td) {
    K0.resize(tree_depth);
    c.resize(tree_depth);
    if constexpr (AuthValue::kHasSecretSum)
      leaves_block.resize(leave_n);
  }

  void set_malicious()         { is_malicious = true; chi.resize(leave_n); }
  void set_cggm_delta(block d) { cggm_delta = d; }
  void set_delta(F d)          { delta = d; }

  void run_begin() {
    if (is_malicious) consist_check_VW.assign(tree_n, AuthValue::f_zero());
  }

  // Per-tree work:
  //   1. cGGM build into leaves_i + K0[tree_depth]. For Ferret-style
  //      (kHasSecretSum=false), AuthValue is layout-compat with block
  //      and cGGM writes directly via reinterpret_cast. For sVOLE
  //      (kHasSecretSum=true), cGGM writes a temp block buffer and
  //      auth_from_block converts.
  //   2. c[j] = base_i[j] XOR K0[j] (correction shipped to receiver).
  //   3. If kHasSecretSum: secret_sum = gamma_i − Σ mac (shipped).
  //   4. Malicious: chi seed from FS transcript; expand_chi; VW
  //      accumulation.
  //
  // gamma_i is the per-tree carrier (sVOLE carry_curr_[tree_idx].mac).
  // For Ferret-style policies (kHasSecretSum=false) it is unused;
  // callers may omit it.
  void run_next_tree(AuthValue *leaves_i, const block *base_i, int tree_idx,
                     [[maybe_unused]] F gamma_i = AuthValue::f_zero()) {
    block seed;
    prg.random_block(&seed, 1);

    if constexpr (!AuthValue::kHasSecretSum) {
      // AuthValueFerret has single `block mac` field → layout = block.
      cggm::build_sender<cggm::kTile, AuthValue::kClearLeafLSB>(
          tree_depth, cggm_delta, seed,
          reinterpret_cast<block*>(leaves_i), K0.data());
    } else {
      cggm::build_sender<cggm::kTile, AuthValue::kClearLeafLSB>(
          tree_depth, cggm_delta, seed, leaves_block.data(), K0.data());
      for (int64_t i = 0; i < leave_n; ++i)
        leaves_i[i] = AuthValue::auth_from_block(leaves_block[i]);
    }

    for (int64_t j = 0; j < tree_depth; ++j) c[j] = base_i[j] ^ K0[j];
    io->send_block(c.data(), tree_depth);

    if constexpr (AuthValue::kHasSecretSum) {
      F leaves_sum = AuthValue::f_zero();
      for (int64_t i = 0; i < leave_n; ++i)
        leaves_sum = AuthValue::f_add(leaves_sum, leaves_i[i].mac);
      F secret_sum = AuthValue::f_sub(gamma_i, leaves_sum);
      io->send_data(&secret_sum, sizeof(F));
    }
    io->flush();

    if (is_malicious) {
      block chi_seed = io->get_digest();
      AuthValue::expand_chi(chi_seed, chi.data(), leave_n);
      AuthValue::accumulate_VW(consist_check_VW[tree_idx], chi.data(),
                               leaves_i, leave_n);
    }
  }

  // F2kPacked round-final check. Mutates `pre_cot_data[i]` for i in
  // x_prime (in-place Δ-XOR on the chi-check region). Caller's
  // buffer; the mutation is intentional and mirrored in the receiver.
  void run_end_packed(block *pre_cot_data) {
    static_assert(AuthValue::kChiFoldFlavor == ChiFoldFlavor::F2kPacked,
                  "run_end_packed: AuthValue is not F2kPacked");
    if (!is_malicious) return;
    block r1, r2;
    vector_self_xor(&r1, consist_check_VW.data(), tree_n);
    bool x_prime[kConsistCheckCotNum];
    io->recv_bool(x_prime, kConsistCheckCotNum);
    for (int i = 0; i < kConsistCheckCotNum; ++i)
      if (x_prime[i])
        pre_cot_data[i] = pre_cot_data[i] ^ cggm_delta;
    pack.packing(&r2, pre_cot_data);
    r1 = r1 ^ r2;
    block dig[2];
    Hash hash;
    hash.hash_once(dig, &r1, sizeof(block));
    io->send_data(dig, 2 * sizeof(block));
    io->flush();
  }

  // FTyped round-final check (sender). `triple_t` is the carry-over
  // chi-fold triple (carry_curr_[t] on the outer-Svole side). For
  // Ferret-style policies this method is never instantiated (gated
  // by static_assert + the outer's chi-fold-flavor-aware caller),
  // so the .mac access in the body is fine.
  void run_end_typed(AuthValue triple_t) {
    static_assert(AuthValue::kChiFoldFlavor == ChiFoldFlavor::FTyped,
                  "run_end_typed: AuthValue is not FTyped");
    if (!is_malicious) return;
    F x_star;
    io->recv_data(&x_star, sizeof(F));
    F vb = AuthValue::f_add(AuthValue::f_mul(delta, x_star), triple_t.mac);
    for (int64_t i = 0; i < tree_n; ++i)
      vb = AuthValue::f_add(vb, consist_check_VW[i]);
    Hash hash;
    block h = hash.hash_for_block(&vb, sizeof(F));
    io->send_data(&h, sizeof(block));
    io->flush();
  }
};

// =================================================================
// MultiPointGadgetReceiver — no-Δ side.
// =================================================================

template <typename AuthValue>
class MultiPointGadgetReceiver {
public:
  using F = typename AuthValue::F;

  IOChannel *io;
  bool      is_malicious = false;
  int64_t   tree_n;
  int64_t   tree_depth;
  int64_t   leave_n;

  std::vector<F> consist_check_chi_alpha;
  std::vector<F> consist_check_VW;
  GaloisFieldPacking pack;   // F2kPacked only.

  // Per-tree scratch — sized once at construction (or on set_malicious
  // for chi) instead of std::vector ctor per run_next_tree call.
  std::vector<block> c;
  std::vector<block> K_recv;
  std::vector<block> leaves_block;  // sized only when kHasSecretSum
  std::vector<F>     chi;           // sized only when is_malicious

  MultiPointGadgetReceiver(int64_t t, int64_t td, IOChannel *io_in)
      : io(io_in), tree_n(t), tree_depth(td),
        leave_n(int64_t{1} << td) {
    c.resize(tree_depth);
    K_recv.resize(tree_depth);
    if constexpr (AuthValue::kHasSecretSum)
      leaves_block.resize(leave_n);
  }

  void set_malicious() { is_malicious = true; chi.resize(leave_n); }

  void run_begin() {
    if (is_malicious) {
      consist_check_chi_alpha.assign(tree_n, AuthValue::f_zero());
      consist_check_VW.assign(tree_n, AuthValue::f_zero());
    }
  }

  // Per-tree work (mirror of sender; see MultiPointGadgetSender for
  // the wire-format summary):
  //   1. α = MSB-first NOT(LSB) of base_i.
  //   2. Recv c[] (and, when kHasSecretSum, secret_sum:F).
  //   3. K_recv[j] = base_i[j] XOR c[j].
  //   4. cGGM eval.
  //   5. α-fill (F2kPacked: XOR closure + lsb_only_mask;
  //              FTyped: triple_yz − secret_sum − Σ_{j≠α} mac).
  //   6. Malicious: chi seed, expand_chi, chi_alpha + VW.
  // Returns α.
  uint32_t run_next_tree(AuthValue *leaves_i, const block *base_i, int tree_idx,
                         F triple_yz_i = AuthValue::f_zero()) {
    uint32_t alpha = 0;
    for (int64_t j = 0; j < tree_depth; ++j) {
      alpha <<= 1;
      if (!getLSB(base_i[j])) alpha += 1;
    }

    io->recv_block(c.data(), tree_depth);
    F secret_sum = AuthValue::f_zero();
    if constexpr (AuthValue::kHasSecretSum) {
      io->recv_data(&secret_sum, sizeof(F));
    }

    for (int64_t j = 0; j < tree_depth; ++j) K_recv[j] = base_i[j] ^ c[j];

    if constexpr (!AuthValue::kHasSecretSum) {
      // Ferret-style: AuthValue layout = block; cGGM writes directly.
      block* leaves_block_view = reinterpret_cast<block*>(leaves_i);
      cggm::eval_receiver<cggm::kTile, AuthValue::kClearLeafLSB>(
          tree_depth, alpha, K_recv.data(), leaves_block_view);
      // F2kPacked α-fill: eval_receiver leaves leaves[α] = zero_block;
      // XOR-sum of all LSB-cleared leaves equals the sender's LSB-
      // cleared α-leaf; OR in lsb_only_mask to recover the carrier bit.
      block nodes_sum = zero_block;
      for (int64_t k = 0; k < leave_n; ++k)
        nodes_sum = nodes_sum ^ leaves_block_view[k];
      leaves_block_view[alpha] = nodes_sum ^ lsb_only_mask;
      (void)secret_sum;
      (void)triple_yz_i;
    } else {
      cggm::eval_receiver<cggm::kTile, AuthValue::kClearLeafLSB>(
          tree_depth, alpha, K_recv.data(), leaves_block.data());
      F nodes_sum = AuthValue::f_zero();
      for (int64_t i = 0; i < leave_n; ++i) {
        if ((uint32_t)i == alpha) {
          leaves_i[i] = AuthValue{};   // .mac filled below; .val by caller
          continue;
        }
        leaves_i[i] = AuthValue::auth_from_block(leaves_block[i]);
        nodes_sum = AuthValue::f_add(nodes_sum, leaves_i[i].mac);
      }
      leaves_i[alpha].mac =
          AuthValue::f_sub(triple_yz_i,
                           AuthValue::f_add(secret_sum, nodes_sum));
    }

    if (is_malicious) {
      block chi_seed = io->get_digest();
      AuthValue::expand_chi(chi_seed, chi.data(), leave_n);
      consist_check_chi_alpha[tree_idx] = chi[alpha];
      AuthValue::accumulate_VW(consist_check_VW[tree_idx], chi.data(),
                               leaves_i, leave_n);
    }

    return alpha;
  }

  // F2kPacked round-final check (receiver).
  void run_end_packed(block *pre_cot_data) {
    static_assert(AuthValue::kChiFoldFlavor == ChiFoldFlavor::F2kPacked,
                  "run_end_packed: AuthValue is not F2kPacked");
    if (!is_malicious) return;
    block r1, r2;
    vector_self_xor(&r1, consist_check_VW.data(), tree_n);
    vector_self_xor(&r2, consist_check_chi_alpha.data(), tree_n);

    uint64_t pos[2];
    static_assert(sizeof(pos) == sizeof(block), "pos must alias a block exactly");
    std::memcpy(pos, &r2, sizeof(block));
    bool pre_cot_bool[kConsistCheckCotNum];
    for (int i = 0; i < 2; ++i) {
      for (int j = 0; j < 64; ++j) {
        pre_cot_bool[i * 64 + j] =
            ((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i * 64 + j]);
        pos[i] >>= 1;
      }
    }
    io->send_bool(pre_cot_bool, kConsistCheckCotNum);
    io->flush();

    block r3;
    pack.packing(&r3, pre_cot_data);
    r1 = r1 ^ r3;
    block dig[2];
    Hash hash;
    hash.hash_once(dig, &r1, sizeof(block));
    block recv[2];
    io->recv_data(recv, 2 * sizeof(block));
    if (!cmpBlock(dig, recv, 2))
      error("MultiPointGadget consistency check fails");
  }

  // FTyped round-final check (receiver). Both val- and mac-side
  // arithmetic goes through f_mul/f_add: AuthValue<F> has val and
  // mac both F-typed, so scalar_mul/embed degenerate to f_mul and
  // identity.
  void run_end_typed(const AuthValue *triples, AuthValue triple_t) {
    static_assert(AuthValue::kChiFoldFlavor == ChiFoldFlavor::FTyped,
                  "run_end_typed: AuthValue is not FTyped");
    if (!is_malicious) return;
    F beta_mul_chialpha = AuthValue::f_zero();
    for (int64_t i = 0; i < tree_n; ++i) {
      F tmp = AuthValue::f_mul(triples[i].val,
                               consist_check_chi_alpha[i]);
      beta_mul_chialpha = AuthValue::f_add(beta_mul_chialpha, tmp);
    }
    F x_star =
        AuthValue::f_add(beta_mul_chialpha, triple_t.val);
    io->send_data(&x_star, sizeof(F));
    io->flush();

    F va = triple_t.mac;
    for (int64_t i = 0; i < tree_n; ++i)
      va = AuthValue::f_add(va, consist_check_VW[i]);
    Hash hash;
    block h = hash.hash_for_block(&va, sizeof(F));
    block r;
    io->recv_data(&r, sizeof(block));
    if (!cmpBlock(&r, &h, 1))
      error("MultiPointGadget chi-fold check failed");
  }
};

} // namespace emp
#endif // EMP_OT_MP_GADGET_H__
