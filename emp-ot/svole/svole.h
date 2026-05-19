#ifndef EMP_OT_SVOLE_SVOLE_H__
#define EMP_OT_SVOLE_SVOLE_H__

#include "emp-ot/lpn.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/svole/mpsvole.h"
#include "emp-ot/svole/svole_extension.h"
#include <memory>
#include <vector>

// Svole<Policy, IO>: the single sVOLE extension class. Both the F_2^k
// case and the F_p case instantiate this with their respective Policy;
// what used to be F2kVOLE and FpVOLE are now `using` aliases over the
// corresponding policy. The class is structurally parallel to Ferret
// (emp-ot/ot_extension/ferret/ferret.h).
//
// - Inherits the streaming contract from SVoleExtension: extend_begin
//   → loop extend_next → extend_end, with chunk_extends() = leave_n,
//   plus the one-shot extend(out, num) wrapper backed by the inherited
//   leftover buffer.
// - Owns a single Ferret instance for the main-stage MPFSS sibling-OT
//   base COTs.
// - Bootstrap (lazy on first extend_begin) is policy-specific and
//   provided as `Policy::template Bootstrap<IO>::run(*this)` — F2k uses
//   Galois packing (+ tiered recursion), F_p uses COPE + Base_svole +
//   a pre-stage MPFSS+LPN amplification.
// - Per-`_next`: one tree's worth of work — pull base for one tree
//   from base_cots_, run Mpsvole{Sender,Receiver}::run_next_tree to
//   produce that tree's sparse F values into vole_buf_; on the
//   non-Δ-holder side insert the per-tree val at α; LPN-slice that
//   tree's leave_n outputs; AuthValue copy out.
// - Auto-rollover: when this tree would cross the user-visible budget
//   (chunk_aligned_buf_sz), call _end + _begin inline (mirrors
//   ferret.cpp:190-192).
// - Per-`_end`: finish the tail trees (refill pre_next_), then run
//   the MPFSS round-final chi-fold consistency check.
//
// Party convention is Policy-determined via
// `Policy::delta_holder_party()` (returns ALICE or BOB). The invariant
// in both cases is:
//
//   Δ-holder party ↔ inner-Ferret-ALICE ↔ MPFSS sender ↔ rcot_send.
//
// Storage: vole_buf_ and pre_curr_/_next_ are AuthValue[] (val-first
// {val, mac}). Δ-holder: val = 0 throughout (no val on the sender
// side). Non-Δ-holder: val at sparse positions after MPFSS, dense
// after LPN.

namespace emp {

// Round geometry, derived from PrimalLPNParameter (shared with Ferret
// and with both F2k / F_p sVOLE).
//   n      = t * 2^tree_depth
//   M      = t + k + 1     (carry-over: MPFSS reads t, LPN reads k,
//                           +1 for the malicious chi-fold pseudo-triple)
//   buf_sz = n - M         (user-visible per round; trailing M outputs
//                           seed the next round)
inline constexpr int64_t svole_n(const PrimalLPNParameter &p) {
  return p.t * (int64_t{1} << p.tree_depth);
}
inline constexpr int64_t svole_M(const PrimalLPNParameter &p) {
  return p.t + p.k + 1;
}
inline constexpr int64_t svole_buf_sz(const PrimalLPNParameter &p) {
  return svole_n(p) - svole_M(p);
}

// =================================================================
// Svole<Policy, IO> — unified sVOLE class for F_2^k and F_p.
// =================================================================

template <typename Policy, typename IO = NetIO>
class Svole : public SVoleExtension<typename Policy::AuthValue> {
public:
  using Base      = SVoleExtension<typename Policy::AuthValue>;
  using AuthValue = typename Policy::AuthValue;
  using F         = typename Policy::F;
  using K         = typename Policy::K;

  PrimalLPNParameter param;

  // State is intentionally public so Policy::Bootstrap<IO>::run can
  // populate pre_next_ + pull from base_ferret_ without `friend`
  // template-template incantations. Mirrors how the old F2kVOLE /
  // FpVOLE classes already exposed most fields.
  IO *io_;
  int64_t tree_idx_ = 0;
  int64_t pos_      = 0;
  F delta_value_;

  std::vector<AuthValue> pre_curr_, pre_next_;
  std::vector<AuthValue> vole_buf_;
  std::vector<block>     base_cots_;

  std::unique_ptr<Ferret>                       base_ferret_;
  std::unique_ptr<MpsvoleSender<Policy, IO>>    mpsvole_send_;
  std::unique_ptr<MpsvoleReceiver<Policy, IO>>  mpsvole_recv_;
  std::unique_ptr<Lpn<Policy, 10>>              lpn_;

  Svole(int party, IO *io, bool malicious = true,
        PrimalLPNParameter param = tuning::ferret_b13)
      : Base(party, malicious), param(param), io_(io) {
    // Δ-holder ↔ inner-Ferret-ALICE (COT-sender) in both Policies.
    const int inner_party =
        (party == Policy::delta_holder_party()) ? ALICE : BOB;
    base_ferret_ = std::make_unique<Ferret>(inner_party, io, malicious);

    mpsvole_send_ = std::make_unique<MpsvoleSender<Policy, IO>>(
        param.t, param.tree_depth, io);
    mpsvole_recv_ = std::make_unique<MpsvoleReceiver<Policy, IO>>(
        param.t, param.tree_depth, io);
    if (malicious) {
      mpsvole_send_->set_malicious();
      mpsvole_recv_->set_malicious();
    }
    lpn_ = std::make_unique<Lpn<Policy, 10>>(param.k);
    lpn_->reseed(zero_block);

    const int64_t n = svole_n(param);
    const int64_t M = svole_M(param);
    const AuthValue zero{Policy::k_zero(), Policy::f_zero()};
    pre_curr_.assign(M, zero);
    pre_next_.assign(M, zero);
    vole_buf_.assign(n, zero);
    base_cots_.assign(param.t * param.tree_depth, zero_block);

    // Pull a default Δ from the freshly-bootstrapped Ferret if the
    // Policy wants it (F2k uses Ferret's auto-sampled block Δ; F_p
    // returns zero, expecting the user to call set_delta).
    delta_value_ = Policy::resolve_delta(base_ferret_.get());
  }

  ~Svole() override = default;

  bool is_delta_holder() const {
    return this->party == Policy::delta_holder_party();
  }

  // Δ-holder-only, pre-bootstrap. Stored in delta_value_ and
  // additionally propagated into the inner Ferret iff the Policy
  // requires it (F2k case: Ferret Δ === sVOLE Δ; F_p case: no-op).
  void set_delta(F delta) {
    assert(is_delta_holder() && "set_delta: caller is not Δ-holder");
    assert(!this->setup_done && "set_delta: bootstrap already fired");
    delta_value_ = delta;
    Policy::on_set_delta(delta, base_ferret_.get());
  }

  F delta() const {
    assert(is_delta_holder() && "delta: caller is not Δ-holder");
    return delta_value_;
  }

  int64_t chunk_extends() const override {
    return int64_t{1} << param.tree_depth;
  }

  // Largest chunk-aligned count of user-visible outputs per round.
  // Callers that one-shot extend() should pass this to avoid the
  // partial-tail leftover dance in the base class wrapper.
  int64_t chunk_aligned_buf_sz() const {
    return (svole_buf_sz(param) / chunk_extends()) * chunk_extends();
  }

  // One-shot rcot pull. Δ-holder = inner-Ferret-ALICE = rcot_send;
  // non-Δ-holder = inner-Ferret-BOB = rcot_recv.
  void pull_cots_(block *buf, int64_t num) {
    if (is_delta_holder()) base_ferret_->rcot_send(buf, num);
    else                   base_ferret_->rcot_recv(buf, num);
  }

protected:
  void do_extend_begin() override {
    bootstrap_pre_();
    std::swap(pre_curr_, pre_next_);
    pos_      = 0;
    tree_idx_ = 0;

    // One-shot pull from Ferret: t * tree_depth raw COTs into base_cots_.
    // OTExtension's leftover buffer handles non-chunk-multiple sizes.
    pull_cots_(base_cots_.data(), (int64_t)base_cots_.size());

    if (is_delta_holder()) {
      // cGGM Δ = Ferret's block Δ (for F2k this equals delta_value_;
      // for F_p they are independent). Chi-fold Δ = delta_value_.
      mpsvole_send_->set_cggm_delta(base_ferret_->Delta);
      mpsvole_send_->set_delta(delta_value_);
      mpsvole_send_->run_begin();
    } else {
      mpsvole_recv_->run_begin();
    }
  }

  void do_extend_next(AuthValue *out) override {
    const int64_t chunk = this->chunk_extends();
    // Auto-rollover: this tree would cross the user-visible budget.
    // Finish the round (tail trees + chi-fold + refill) and start a
    // new one before producing the user's chunk.
    if (pos_ + chunk > chunk_aligned_buf_sz()) {
      do_extend_end();
      do_extend_begin();
    }
    process_one_tree_(out);
  }

  void do_extend_end() override {
    // Finish any remaining trees in this round (the refill_trees that
    // populate next round's carry-over). No AuthValue marshal — those
    // outputs aren't user-visible.
    while (tree_idx_ < param.t) {
      process_one_tree_(/*out=*/nullptr);
    }
    // Round-final chi-fold check.
    if (is_delta_holder()) {
      mpsvole_send_->run_end(pre_curr_[param.t]);
    } else {
      mpsvole_recv_->run_end(pre_curr_.data(), pre_curr_[param.t]);
    }
    // Carry-over: last M = t + k + 1 outputs → pre_next_.
    const int64_t M = svole_M(param);
    const int64_t n = svole_n(param);
    std::memcpy(pre_next_.data(), vole_buf_.data() + (n - M),
                M * sizeof(AuthValue));
  }

private:
  // Process tree at index `tree_idx_`: mpsvole for one tree + LPN slice
  // for that tree's leave_n outputs. If `out != nullptr`, also copy
  // the result block into the user's AuthValue buffer. Advances
  // tree_idx_ and pos_.
  void process_one_tree_(AuthValue *out) {
    const int64_t chunk = chunk_extends();
    const int64_t tt = param.t;
    const block *base_i =
        base_cots_.data() + tree_idx_ * param.tree_depth;
    AuthValue *leaves_i = vole_buf_.data() + tree_idx_ * chunk;

    if (is_delta_holder()) {
      // Sender: cGGM + ship c[] + secret_sum; mac set per position.
      mpsvole_send_->run_next_tree(leaves_i, base_i, tree_idx_,
                                   pre_curr_[tree_idx_].mac);
    } else {
      // Receiver: recv c[] + secret_sum; cGGM eval; fill puncture mac.
      uint32_t alpha = mpsvole_recv_->run_next_tree(
          leaves_i, base_i, tree_idx_, pre_curr_[tree_idx_].mac);
      // Insert val at α from the carry-over slot.
      leaves_i[alpha].val = pre_curr_[tree_idx_].val;
    }

    // One LPN call serves both parties — val side folds (zero on
    // Δ-holder, dense on the receiver) and mac side folds together.
    lpn_->compute_slice(vole_buf_.data() + pos_, pre_curr_.data() + tt,
                        chunk);

    if (out) {
      std::memcpy(out, vole_buf_.data() + pos_,
                  chunk * sizeof(AuthValue));
    }
    pos_      += chunk;
    tree_idx_ += 1;
  }

  // Lazy bootstrap. Sets up the FS transcript on first call and
  // delegates to the Policy-supplied Bootstrap (Galois packing for
  // F2k, COPE + Base_svole + pre-stage MPFSS+LPN for F_p).
  void bootstrap_pre_() {
    if (this->setup_done) return;
    if (!io_->fs_enabled())
      io_->enable_fs(/*send_first=*/is_delta_holder());
    Policy::template Bootstrap<IO>::run(*this);
    this->setup_done = true;
  }
};

} // namespace emp

#endif
