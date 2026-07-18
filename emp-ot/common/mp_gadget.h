#ifndef EMP_OT_MP_GADGET_H__
#define EMP_OT_MP_GADGET_H__

#include "emp-ot/common/cggm.h"
#include "emp-ot/tuning.h"   // kConsistCheckCotNum
#include <emp-tool/emp-tool.h>
#include <algorithm>
#include <future>
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

// Domain separators for the round-final consistency-check commitments,
// at file scope so the sender and receiver hash byte-identical inputs.
inline constexpr char kDomCheckPacked[] = "emp-ot:mpcot:check-f2kpacked";
inline constexpr char kDomCheckTyped[]  = "emp-ot:mpcot:check-ftyped";

// Run `fn(s)` for s in [0,B) — on `pool` if given (and worth it), else
// inline. Used by the decoupled prepare path to parallelize the per-tree
// cGGM expand / VW across a batch; the caller keeps all socket + FS calls
// on its own thread, so `fn` must be pure compute on disjoint scratch.
template <class Fn>
inline void mp_parallel_for(ThreadPool *pool, int B, Fn &&fn) {
  if (pool && B > 1) {
    std::vector<std::future<void>> futs;
    futs.reserve(B);
    for (int s = 0; s < B; ++s) futs.emplace_back(pool->enqueue(fn, s));
    for (auto &f : futs) f.get();
  } else {
    for (int s = 0; s < B; ++s) fn(s);
  }
}

// =================================================================
// MultiPointGadgetSender — Δ-holder side.
// =================================================================

template <typename AuthValue>
class MultiPointGadgetSender {
public:
  using F = typename AuthValue::F;

  IOChannel *io;
  block     sid = zero_block;   // set by the owner; bound into the check RO
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

  // ---- Decoupled "silent consume" path (SilentFerret) --------------
  // Splits run_next_tree into a one-shot prepare (all wire traffic, run
  // once at begin) and a wire-free per-tree produce (run at consume).
  // prepare_all() expands every tree, ships corrections in tree order, and
  // remembers the per-tree cGGM root seeds so
  // produce_tree() can re-derive a tree's leaves with no I/O. In
  // malicious mode it also folds each tree's chi contribution into
  // consist_check_VW here, so end()'s run_end_packed check is unchanged.
  //
  // The expensive cGGM expand and VW inner-product run on `pool` a batch
  // at a time; the socket sends and the per-tree get_digest() chi snapshot
  // stay on this thread in tree order, so the resulting chi seeds — and
  // thus the whole malicious transcript — are bit-identical to the
  // interleaved run_next_tree path. Only the *timing* of the traffic moves.
  std::vector<block> c_scratch_;      // tree_n * tree_depth corrections (ship-and-forget)
  std::vector<block> leaves_scratch_; // batch * leave_n  (per-task slots)
  std::vector<block> K0_scratch_;     // batch * tree_depth
  std::vector<F>     chi_scratch_;    // batch * leave_n (malicious only)

  // `base` points at the tree_n*tree_depth cGGM-correction base COTs
  // (contiguous; base + i*tree_depth is tree i's K^{ᾱ} input). `seeds`
  // supplies the tree_n cGGM root seeds — caller-owned and *reproducible*
  // (e.g. a seek'd PRG) so produce_tree can re-derive the same leaves
  // later with no stored per-round state. `pool` may be null (serial);
  // `batch` bounds peak leaf scratch. Corrections are shipped and not
  // retained (the sender never re-reads them).
  void prepare_all(ThreadPool *pool, int batch, const block *base,
                   const block *seeds) {
    static_assert(!AuthValue::kHasSecretSum,
                  "prepare_all: Ferret-style (no secret_sum) path only");
    if (batch < 1) batch = 1;
    c_scratch_.resize(tree_n * tree_depth);
    leaves_scratch_.resize((int64_t)batch * leave_n);
    K0_scratch_.resize((int64_t)batch * tree_depth);
    std::vector<block> chi_seeds(batch);
    if (is_malicious) chi_scratch_.resize((int64_t)batch * leave_n);
    int64_t last_flush = 0;

    for (int64_t b0 = 0; b0 < tree_n; b0 += batch) {
      const int B = (int)std::min<int64_t>(batch, tree_n - b0);
      // (1) expand + correction — parallel, disjoint per-task scratch.
      mp_parallel_for(pool, B, [&](int s) {
        const int64_t i = b0 + s;
        block *lv = leaves_scratch_.data() + (int64_t)s * leave_n;
        block *k0 = K0_scratch_.data() + (int64_t)s * tree_depth;
        cggm::build_sender<cggm::kTile, AuthValue::kClearLeafLSB>(
            tree_depth, cggm_delta, seeds[i], lv, k0);
        const block *base_i = base + i * tree_depth;
        block *c_i = c_scratch_.data() + i * tree_depth;
        for (int64_t j = 0; j < tree_depth; ++j) c_i[j] = base_i[j] ^ k0[j];
      });
      // (2) ship corrections + snapshot chi seed — this thread, tree order.
      for (int s = 0; s < B; ++s) {
        const int64_t i = b0 + s;
        io->send_block(c_scratch_.data() + i * tree_depth, tree_depth);
        if (is_malicious) chi_seeds[s] = io->get_digest();
      }
      // In malicious mode the receiver must evaluate these trees for its chi
      // fold. Flush coarse waves so that work overlaps our VW fold instead of
      // waiting for the full correction stream to fill NetIO's buffer. Keep
      // the threshold independent of the compute batch: batch=1 must not turn
      // every tree into a small socket write.
      const int64_t shipped = b0 + B;
      if (is_malicious &&
          (shipped - last_flush >= tuning::mp_gadget_flush_trees ||
           shipped == tree_n)) {
        io->flush();
        last_flush = shipped;
      }
      // (3) VW fold — parallel; each tree writes its own slot.
      if (is_malicious)
        mp_parallel_for(pool, B, [&](int s) {
          const int64_t i = b0 + s;
          block *lv = leaves_scratch_.data() + (int64_t)s * leave_n;
          F *chi = chi_scratch_.data() + (int64_t)s * leave_n;
          AuthValue::expand_chi(chi_seeds[s], chi, leave_n);
          AuthValue::accumulate_VW(consist_check_VW[i], chi,
                                   reinterpret_cast<AuthValue *>(lv), leave_n);
        });
    }
    // Semi-honest preparation only stores corrections on the receiver, so a
    // single flush avoids turning the stream into many small writes.
    if (!is_malicious) io->flush();
  }

  // Re-derive one tree's leaves into `leaves_i` from its cGGM root `seed`
  // (layout-compat block* since kHasSecretSum=false). No wire I/O, no VW
  // (already folded in prepare_all). Reentrant / const: the caller supplies
  // `k0_scratch` (tree_depth blocks, the throwaway correction sink) so
  // concurrent threads can produce disjoint trees.
  void produce_tree(AuthValue *leaves_i, block seed,
                    block *k0_scratch) const {
    static_assert(!AuthValue::kHasSecretSum,
                  "produce_tree: Ferret-style path only");
    cggm::build_sender<cggm::kTile, AuthValue::kClearLeafLSB>(
        tree_depth, cggm_delta, seed,
        reinterpret_cast<block *>(leaves_i), k0_scratch);
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
    RO(kDomCheckPacked, sid).absorb(r1).squeeze_digest(dig);
    io->send_data(dig, 2 * sizeof(block));
    io->flush();
  }

  // ---- Batched F2kPacked check (SilentFerret multi-round prepay) --------
  // Ferret's per-round run_end_packed IS the paper's Appendix-C batched check
  // over the round's t trees (eprint 2020/924). These two methods extend it to
  // ONE check over a whole K-round prepay (m = K*t executions): fold each round's
  // VW into a running accumulator with NO I/O, then run a single round-trip with
  // ONE mask. The check is a pure XOR-linear combination, so only the running
  // F(2^128) scalar is retained — never the per-tree/per-leaf values.
  //
  // fold_round_check: XOR this round's chi-fold (sum over the round's trees,
  // already in consist_check_VW from prepare_all) into the batch accumulator.
  void fold_round_check(block &acc_vw) {
    if (!is_malicious) return;
    block r;
    vector_self_xor(&r, consist_check_VW.data(), tree_n);
    acc_vw = acc_vw ^ r;
  }

  // Single round-trip over the whole batch. `mask128` = the batch's 128 consist-
  // check COTs (the paper's one-time kappa-COT mask; the sender's keys). `acc_vw`
  // = running XOR of every round's VW. The Δ-XOR is applied to a local copy, so
  // the caller's mask buffer stays pristine. For K=1 this is byte-identical to
  // run_end_packed (one VW, one digest) — the no-arg SilentFerret path is then a
  // wire-equivalent drop-in for Ferret.
  void finalize_batched_packed_sender(block acc_vw, const block *mask128) {
    if (!is_malicious) return;
    bool x_prime[kConsistCheckCotNum];
    io->recv_bool(x_prime, kConsistCheckCotNum);
    block consist[kConsistCheckCotNum];
    for (int i = 0; i < kConsistCheckCotNum; ++i)
      consist[i] = x_prime[i] ? (mask128[i] ^ cggm_delta) : mask128[i];
    block Y;
    pack.packing(&Y, consist);
    block r1 = acc_vw ^ Y;
    block dig[2];
    RO(kDomCheckPacked, sid).absorb(r1).squeeze_digest(dig);
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
    block h = RO(kDomCheckTyped, sid).absorb(&vb, sizeof(F)).squeeze_block();
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
  block     sid = zero_block;   // set by the owner; bound into the check RO
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
  //   5. α-fill (F2kPacked: XOR closure + bit0_mask;
  //              FTyped: triple_yz − secret_sum − Σ_{j≠α} mac).
  //   6. Malicious: chi seed, expand_chi, chi_alpha + VW.
  // Returns the punctured leaf's storage index = bit_reverse(α), which
  // is where the caller writes its val (split-layout leaf order).
  uint32_t run_next_tree(AuthValue *leaves_i, const block *base_i, int tree_idx,
                         F triple_yz_i = AuthValue::f_zero()) {
    uint32_t alpha = 0;
    for (int64_t j = 0; j < tree_depth; ++j) {
      alpha <<= 1;
      if (!getLSB(base_i[j])) alpha += 1;
    }
    // `alpha` is the top-down path; the split-layout cGGM stores its leaf
    // (the punctured slot) at bit_reverse(alpha). eval_receiver takes the
    // path; every leaf-array access below uses the reversed storage index.
    const uint32_t rev = cggm::bit_reverse(alpha, (int)tree_depth);

    io->recv_block(c.data(), tree_depth);
    F secret_sum = AuthValue::f_zero();
    if constexpr (AuthValue::kHasSecretSum) {
      io->recv_data(&secret_sum, sizeof(F));
    }

    for (int64_t j = 0; j < tree_depth; ++j) K_recv[j] = base_i[j] ^ c[j];

    if constexpr (!AuthValue::kHasSecretSum) {
      // Ferret-style: AuthValue layout = block; cGGM writes directly.
      block* leaves_block_view = reinterpret_cast<block*>(leaves_i);
      const block known_xor =
          cggm::eval_receiver<cggm::kTile, AuthValue::kClearLeafLSB>(
              tree_depth, alpha, K_recv.data(), leaves_block_view);
      // F2kPacked α-fill: eval_receiver leaves leaves[α] = zero_block;
      // XOR-sum of all LSB-cleared leaves equals the sender's LSB-
      // cleared α-leaf; OR in bit0_mask to recover the carrier bit.
      leaves_block_view[rev] = known_xor ^ bit0_mask;
      (void)secret_sum;
      (void)triple_yz_i;
    } else {
      cggm::eval_receiver<cggm::kTile, AuthValue::kClearLeafLSB>(
          tree_depth, alpha, K_recv.data(), leaves_block.data());
      F nodes_sum = AuthValue::f_zero();
      for (int64_t i = 0; i < leave_n; ++i) {
        if ((uint32_t)i == rev) {
          leaves_i[i] = AuthValue{};   // .mac filled below; .val by caller
          continue;
        }
        leaves_i[i] = AuthValue::auth_from_block(leaves_block[i]);
        nodes_sum = AuthValue::f_add(nodes_sum, leaves_i[i].mac);
      }
      leaves_i[rev].mac =
          AuthValue::f_sub(triple_yz_i,
                           AuthValue::f_add(secret_sum, nodes_sum));
    }

    if (is_malicious) {
      block chi_seed = io->get_digest();
      AuthValue::expand_chi(chi_seed, chi.data(), leave_n);
      consist_check_chi_alpha[tree_idx] = chi[rev];
      AuthValue::accumulate_VW(consist_check_VW[tree_idx], chi.data(),
                               leaves_i, leave_n);
    }

    return rev;
  }

  // ---- Decoupled "silent consume" path (SilentFerret) --------------
  // Mirror of MultiPointGadgetSender's prepare_all / produce_tree.
  // prepare_all() receives and stores every tree's correction. In malicious
  // mode it also evaluates each tree and folds its chi contribution into
  // consist_check_chi_alpha / consist_check_VW so end()'s run_end_packed
  // check is unchanged. In semi-honest mode that evaluation has no persistent
  // effect, so it is deferred to produce_tree(), which evaluates from the
  // stored correction with no I/O.
  //
  // recv + per-tree get_digest() stay on this thread in tree order (so the
  // chi seeds match the sender's snapshots); the cGGM eval + VW run on
  // `pool` a batch at a time over disjoint per-task scratch.
  std::vector<block> leaves_scratch_; // batch * leave_n  (per-task slots)
  std::vector<block> K_recv_scratch_; // batch * tree_depth
  std::vector<F>     chi_scratch_;    // batch * leave_n (malicious only)

  // `base` points at the tree_n*tree_depth cGGM-correction base COTs
  // (contiguous; base + i*tree_depth is tree i's input). The received
  // corrections are written into `c_out` (tree_n*tree_depth, caller-owned)
  // — the receiver *cannot* re-derive them, so the caller retains them and
  // hands the matching slice back to produce_tree. `pool` may be null
  // (serial); `batch` bounds peak leaf scratch.
  void prepare_all(ThreadPool *pool, int batch, const block *base,
                   block *c_out) {
    static_assert(!AuthValue::kHasSecretSum,
                  "prepare_all: Ferret-style (no secret_sum) path only");
    if (!is_malicious) {
      for (int64_t i = 0; i < tree_n; ++i)
        io->recv_block(c_out + i * tree_depth, tree_depth);
      return;
    }
    if (batch < 1) batch = 1;
    leaves_scratch_.resize((int64_t)batch * leave_n);
    K_recv_scratch_.resize((int64_t)batch * tree_depth);
    std::vector<block> chi_seeds(batch);
    if (is_malicious) chi_scratch_.resize((int64_t)batch * leave_n);

    for (int64_t b0 = 0; b0 < tree_n; b0 += batch) {
      const int B = (int)std::min<int64_t>(batch, tree_n - b0);
      // (1) recv corrections + snapshot chi seed — this thread, tree order.
      for (int s = 0; s < B; ++s) {
        const int64_t i = b0 + s;
        io->recv_block(c_out + i * tree_depth, tree_depth);
        if (is_malicious) chi_seeds[s] = io->get_digest();
      }
      // (2) eval + α-fill (+ malicious chi_alpha / VW) — parallel.
      mp_parallel_for(pool, B, [&](int s) {
        const int64_t i = b0 + s;
        const block *base_i = base + i * tree_depth;
        const block *c_i = c_out + i * tree_depth;
        block *lv = leaves_scratch_.data() + (int64_t)s * leave_n;
        block *kr = K_recv_scratch_.data() + (int64_t)s * tree_depth;
        const uint32_t rev = eval_one_(base_i, c_i, lv, kr);
        if (is_malicious) {
          F *chi = chi_scratch_.data() + (int64_t)s * leave_n;
          AuthValue::expand_chi(chi_seeds[s], chi, leave_n);
          consist_check_chi_alpha[i] = chi[rev];
          AuthValue::accumulate_VW(consist_check_VW[i], chi,
                                   reinterpret_cast<AuthValue *>(lv), leave_n);
        }
      });
    }
  }

  // Re-evaluate one tree's leaves into `leaves_i` from its `base_i` cGGM
  // input and stored correction `c_i` (tree_depth blocks). No wire I/O, no
  // VW (already folded in prepare_all). Reentrant / const: the caller
  // supplies `kr_scratch` (tree_depth blocks) so concurrent threads can
  // produce disjoint trees. Returns bit_reverse(alpha) (the punctured slot).
  uint32_t produce_tree(AuthValue *leaves_i, const block *base_i,
                        const block *c_i, block *kr_scratch) const {
    static_assert(!AuthValue::kHasSecretSum,
                  "produce_tree: Ferret-style path only");
    return eval_one_(base_i, c_i,
                     reinterpret_cast<block *>(leaves_i), kr_scratch);
  }

 private:
  // Shared cGGM-eval + F2kPacked α-fill body for one tree. `kr` is a
  // tree_depth-block scratch (caller-owned, so it is reentrant across pool
  // tasks). const — reads only tree_depth/leave_n. Returns rev = bit_reverse(alpha).
  uint32_t eval_one_(const block *base_i, const block *c_i, block *lv,
                     block *kr) const {
    uint32_t alpha = 0;
    for (int64_t j = 0; j < tree_depth; ++j) {
      alpha <<= 1;
      if (!getLSB(base_i[j])) alpha += 1;
    }
    const uint32_t rev = cggm::bit_reverse(alpha, (int)tree_depth);
    for (int64_t j = 0; j < tree_depth; ++j) kr[j] = base_i[j] ^ c_i[j];
    const block known_xor =
        cggm::eval_receiver<cggm::kTile, AuthValue::kClearLeafLSB>(
            tree_depth, alpha, kr, lv);
    lv[rev] = known_xor ^ bit0_mask;
    return rev;
  }

 public:

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
    RO(kDomCheckPacked, sid).absorb(r1).squeeze_digest(dig);
    block recv[2];
    io->recv_data(recv, 2 * sizeof(block));
    expecting(cmpBlock(dig, recv, 2),
              "MultiPointGadget consistency check fails");
  }

  // ---- Batched F2kPacked check (SilentFerret multi-round prepay) --------
  // Mirror of the sender's batched check (see that comment). The receiver folds
  // both VW and chi_alpha per round; the running chi_alpha sum is the paper's
  // phi = sum_l chi_{alpha_l}. One mask, one round-trip for the whole batch.
  void fold_round_check(block &acc_vw, block &acc_phi) {
    if (!is_malicious) return;
    block rv, rp;
    vector_self_xor(&rv, consist_check_VW.data(), tree_n);
    vector_self_xor(&rp, consist_check_chi_alpha.data(), tree_n);
    acc_vw  = acc_vw  ^ rv;
    acc_phi = acc_phi ^ rp;
  }

  // `mask128` = the batch's 128 consist-check COTs (receiver's MAC side; LSBs are
  // the kappa-COT choice bits x*). `acc_vw` / `acc_phi` are the running batch
  // accumulators. One round-trip; aborts on mismatch. K=1 is byte-identical to
  // run_end_packed.
  void finalize_batched_packed_receiver(block acc_vw, block acc_phi,
                                        const block *mask128) {
    if (!is_malicious) return;
    uint64_t pos[2];
    static_assert(sizeof(pos) == sizeof(block), "pos must alias a block exactly");
    std::memcpy(pos, &acc_phi, sizeof(block));
    bool x_prime[kConsistCheckCotNum];
    for (int i = 0; i < 2; ++i) {
      for (int j = 0; j < 64; ++j) {
        x_prime[i * 64 + j] = ((pos[i] & 1) == 1) ^ getLSB(mask128[i * 64 + j]);
        pos[i] >>= 1;
      }
    }
    io->send_bool(x_prime, kConsistCheckCotNum);
    io->flush();
    block Z;
    pack.packing(&Z, mask128);
    block r1 = acc_vw ^ Z;
    block dig[2];
    RO(kDomCheckPacked, sid).absorb(r1).squeeze_digest(dig);
    block recv[2];
    io->recv_data(recv, 2 * sizeof(block));
    expecting(cmpBlock(dig, recv, 2),
              "MultiPointGadget batched consistency check fails");
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
    block h = RO(kDomCheckTyped, sid).absorb(&va, sizeof(F)).squeeze_block();
    block r;
    io->recv_data(&r, sizeof(block));
    expecting(cmpBlock(&r, &h, 1),
              "MultiPointGadget chi-fold check failed");
  }
};

} // namespace emp
#endif // EMP_OT_MP_GADGET_H__
