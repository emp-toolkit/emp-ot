#ifndef EMP_OT_SVOLE_SVOLE_H__
#define EMP_OT_SVOLE_SVOLE_H__

#include "emp-ot/common/lpn.h"
#include "emp-ot/common/mp_gadget.h"
#include "emp-ot/common/streaming_extension.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include <memory>
#include <vector>

// Svole<AuthValue, IO>: the single sVOLE extension class. Both the
// F_2^k case (AuthValue=AuthValueF2k) and the F_p case
// (AuthValue=AuthValueFp) instantiate this with their respective
// concrete carrier-and-ops type. F2kVOLE / FpVOLE remain as `using`
// aliases over the corresponding carrier.
//
// Structurally parallel to Ferret (emp-ot/ot_extension/ferret/ferret.h):
// both inherit StreamingExtension<Element> (Ferret indirectly via
// OTExtension), implement the same 4-step round loop in begin / next /
// end (bootstrap → swap → reset tree_idx_ → inner_begin; rollover-check
// → process_one_tree; refill → inner_end), and use MultiPointGadget as
// the per-tree inner gadget. Both ping-pong a `carry_curr_/_next_`
// buffer of `refill_trees * 2^tree_depth` elements where refill trees
// write directly into next_.
//
// Party convention is carrier-determined via
// `AuthValue::delta_holder_party()` (returns ALICE or BOB). The
// invariant in both cases is:
//
//   Δ-holder party ↔ inner-Ferret-ALICE ↔ MPFSS sender ↔ rcot caller.
//
// Storage: carry_curr_/_next_ are AuthValue[] (val-first {val, mac}).
// Δ-holder: val = 0 throughout (no val on the sender side).
// Non-Δ-holder: val at sparse positions after MPFSS, dense after LPN.

namespace emp {

// Round geometry, derived from PrimalLPNParameter (shared with Ferret
// and with both F2k / F_p sVOLE).
//   n = t * 2^tree_depth        (trees this round, total LPN-folded outputs)
//   M = t + k + 1               (carry-over to next round: MPFSS reads t,
//                                 LPN reads k, +1 for the malicious
//                                 chi-fold pseudo-triple)
inline constexpr int64_t svole_n(const PrimalLPNParameter &p) {
  return p.t * (int64_t{1} << p.tree_depth);
}
inline constexpr int64_t svole_M(const PrimalLPNParameter &p) {
  return p.t + p.k + 1;
}

// =================================================================
// Svole<AuthValue, IO> — unified sVOLE class for F_2^k and F_p.
// =================================================================

template <typename AuthValue_, typename IO = NetIO>
class Svole : public StreamingExtension<AuthValue_> {
public:
  using AuthValue = AuthValue_;
  using F         = typename AuthValue::F;

  PrimalLPNParameter param;

  // State is intentionally public so AuthValue::Bootstrap<IO>::run
  // can populate carry_next_ + pull from base_ferret_ without `friend`
  // template-template incantations.
  IO *io_;
  F delta_value_;

  // Ping-pong carry-over buffers. Size = `refill_trees * 2^tree_depth`
  // to mirror Ferret's slack-tolerant pattern: refill trees in
  // run_refill_() write directly here, and the first M = svole_M(param)
  // entries become next round's read region.
  std::vector<AuthValue> carry_curr_, carry_next_;
  // Per-round scratch for MPFSS sibling-OT base COTs (t * tree_depth
  // raw blocks from inner Ferret). Refilled in inner_run_begin_().
  std::vector<block>     base_cots_;

  std::unique_ptr<Ferret>                              base_ferret_;
  std::unique_ptr<MultiPointGadgetSender<AuthValue>>   gadget_send_;
  std::unique_ptr<MultiPointGadgetReceiver<AuthValue>> gadget_recv_;
  std::unique_ptr<Lpn<AuthValue, 10>>                  lpn_;

  Svole(int party, IO *io, bool malicious = true,
        PrimalLPNParameter param = tuning::ferret_b13)
      : StreamingExtension<AuthValue>(party, malicious),
        param(param), io_(io) {
    // Δ-holder ↔ inner-Ferret-ALICE (COT-sender) in both carriers.
    const int inner_party =
        (party == AuthValue::delta_holder_party()) ? ALICE : BOB;
    base_ferret_ = std::make_unique<Ferret>(inner_party, io, malicious);

    gadget_send_ = std::make_unique<MultiPointGadgetSender<AuthValue>>(
        param.t, param.tree_depth, io);
    gadget_recv_ = std::make_unique<MultiPointGadgetReceiver<AuthValue>>(
        param.t, param.tree_depth, io);
    if (malicious) {
      gadget_send_->set_malicious();
      gadget_recv_->set_malicious();
    }
    lpn_ = std::make_unique<Lpn<AuthValue, 10>>(param.k);
    lpn_->reseed(zero_block);

    const int64_t carry_blocks =
        param.refill_trees * (int64_t{1} << param.tree_depth);
    carry_curr_.assign(carry_blocks, AuthValue{});
    carry_next_.assign(carry_blocks, AuthValue{});
    base_cots_.assign(param.t * param.tree_depth, zero_block);

    // Pull a default Δ from the freshly-bootstrapped Ferret if the
    // carrier wants it (F2k uses Ferret's auto-sampled block Δ; F_p
    // returns zero, expecting the user to call set_delta).
    delta_value_ = AuthValue::resolve_delta(base_ferret_.get());
  }

  ~Svole() override = default;

  bool is_delta_holder() const {
    return this->party == AuthValue::delta_holder_party();
  }

  // Δ-holder-only, pre-bootstrap. Stored in delta_value_ and
  // additionally propagated into the inner Ferret iff the carrier
  // requires it (F2k case: Ferret Δ === sVOLE Δ; F_p case: no-op).
  void set_delta(F delta) {
    assert(is_delta_holder() && "set_delta: caller is not Δ-holder");
    assert(!this->setup_done && "set_delta: bootstrap already fired");
    delta_value_ = delta;
    AuthValue::on_set_delta(delta, base_ferret_.get());
  }

  F delta() const {
    assert(is_delta_holder() && "delta: caller is not Δ-holder");
    return delta_value_;
  }

  int64_t chunk_size() const override {
    return int64_t{1} << param.tree_depth;
  }

  // Largest chunk-aligned count of user-visible outputs per round.
  // Equal to `(param.t - param.refill_trees) * chunk` by the
  // refill_trees = ceil(M / chunk) identity (param.refill_trees uses
  // Ferret-M; svole_M ≤ Ferret-M, so the identity still satisfies the
  // sVOLE carry-over constraint, with some slack).
  int64_t chunk_aligned_buf_sz() const {
    return (param.t - param.refill_trees) * chunk_size();
  }

  // One-shot rcot pull. The inner Ferret's party (ALICE for Δ-holder,
  // BOB otherwise) determines the role implicitly inside rcot().
  void pull_cots_(block *buf, int64_t num) {
    base_ferret_->rcot(buf, num);
  }

  // -------- Streaming lifecycle --------

  void begin() override {
    this->enter_session_();
    bootstrap_();
    std::swap(carry_curr_, carry_next_);
    tree_idx_ = 0;
    inner_run_begin_();
  }

  void next(AuthValue *out) override {
    this->assert_in_session_();
    // Auto-rollover: if this round's user-visible budget is full,
    // run end+begin transparently before producing the user's tree.
    // Uses public end()/begin() so the session tripwire flips cleanly.
    const int64_t user_budget_trees = param.t - param.refill_trees;
    if (tree_idx_ == user_budget_trees) {
      end();
      begin();
    }
    process_one_tree_(out);
  }

  void end() override {
    run_refill_();
    inner_run_end_();
    this->exit_session_();
  }

private:
  // -------- Per-stage helpers --------

  // Lazy bootstrap, gated by setup_done. Delegates to the carrier's
  // protocol-specific Bootstrap (Galois packing for F2k; COPE +
  // Base_svole + pre-stage MPFSS+LPN for F_p).
  void bootstrap_() {
    if (this->setup_done) return;
    if (!io_->fs_enabled())
      io_->enable_fs(/*send_first=*/is_delta_holder());
    AuthValue::template Bootstrap<IO>::run(*this);
    this->setup_done = true;
  }

  // Pull one round's worth of base COTs from inner Ferret, then run
  // the MPFSS gadget's per-round begin on the active side.
  void inner_run_begin_() {
    pull_cots_(base_cots_.data(), (int64_t)base_cots_.size());
    if (is_delta_holder()) {
      // cGGM Δ = Ferret's block Δ (for F2k this equals delta_value_;
      // for F_p they are independent). Chi-fold Δ = delta_value_.
      gadget_send_->set_cggm_delta(base_ferret_->Delta);
      gadget_send_->set_delta(delta_value_);
      gadget_send_->run_begin();
    } else {
      gadget_recv_->run_begin();
    }
  }

  // Per-tree body. `dst` is either the user's `out` (user-visible
  // tree) or `carry_next_ + (refill_idx) * chunk` (refill tree). The
  // MPFSS gadget writes leaves directly into `dst`; LPN folds
  // in-place over the same `dst` slot.
  void process_one_tree_(AuthValue *dst) {
    const int64_t chunk = chunk_size();
    const int64_t tt = param.t;
    const block *base_i =
        base_cots_.data() + tree_idx_ * param.tree_depth;

    if (is_delta_holder()) {
      gadget_send_->run_next_tree(dst, base_i, tree_idx_,
                                   carry_curr_[tree_idx_].mac);
    } else {
      uint32_t alpha = gadget_recv_->run_next_tree(
          dst, base_i, tree_idx_, carry_curr_[tree_idx_].mac);
      // Insert val at α from the carry-over slot.
      dst[alpha].val = carry_curr_[tree_idx_].val;
    }

    // LPN slice folds the secret (carry_curr_[t..t+k]) into dst's chunk
    // entries. Slot t is dual-use as both the chi-fold triple and the
    // LPN secret's first element — both reads see authenticated
    // triples, which is all the protocol requires.
    lpn_->compute_slice(dst, carry_curr_.data() + tt, chunk);

    tree_idx_++;
  }

  void inner_run_end_() {
    if (is_delta_holder()) {
      gadget_send_->run_end_typed(carry_curr_[param.t]);
    } else {
      gadget_recv_->run_end_typed(carry_curr_.data(), carry_curr_[param.t]);
    }
  }

  // Refill trees write LPN-folded outputs directly into carry_next_
  // (parallel to Ferret's pattern). First M of those become next
  // round's carry_curr_ after the swap in do_begin; the trailing
  // slack is unused on the read side.
  void run_refill_() {
    const int64_t chunk = chunk_size();
    for (int64_t i = 0; i < param.refill_trees; ++i) {
      process_one_tree_(carry_next_.data() + i * chunk);
    }
  }

  int64_t tree_idx_ = 0;
};

} // namespace emp

#endif
