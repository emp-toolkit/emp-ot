// Out-of-line definitions for Ferret. See ferret.h for the API.
//
// Structure parallel to Svole<AuthValue>: a single class
// inheriting StreamingExtension<block> (via OTExtension), implementing
// the same 4-step round loop directly in begin / next / end:
//
//   begin : lazy bootstrap → swap curr/next → tree_idx_ = 0
//           → inner_run_begin_ (gadget round-begin + one-shot LPN
//                               matrix-seed initialization)
//   next  : if this round's user-visible budget is full, end + begin
//           (transparent rollover); then process_one_tree_
//   end   : run_refill_ (refill trees write directly into next_) +
//           inner_run_end_ (chi-fold check)
//
// AuthValueFerret is layout-equivalent to `block`, so the
// StreamingExtension<block> output buffer is reinterpreted to
// AuthValueFerret* at the gadget / Lpn boundary.

#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/common/lpn.h"
#include "emp-ot/ot_extension/softspoken/softspoken.h"

namespace emp {

// Derive the per-Ferret-lifetime LPN seed: RO(domain, sid). Both parties
// compute it locally from the shared session id, so it needs no wire
// exchange. The domain separator and sid make it independent of other
// derivations and of other sessions; the LPN matrix it seeds is public.
static block derive_lpn_seed_(block sid) {
	return RO("emp-ot:ferret:lpn-seed", sid).squeeze_block();
}

// Seeded choices. The matrix seed binds the parameter set, so a nested
// ferret_b9 and the set above it draw different matrices from one root; so does
// the key of the receiver's seeded choice bits.
static block derive_lpn_seed_from_root_(block root,
		const PrimalLPNParameter &param) {
	return RO("emp-ot:ferret:lpn-matrix-seed", root)
		.absorb((uint64_t)param.t)
		.absorb((uint64_t)param.logk)
		.absorb((uint64_t)param.tree_depth)
		.squeeze_block();
}

static block derive_choice_key_(block seed, const PrimalLPNParameter &param) {
	return RO("emp-ot:ferret:choice-seed", seed)
		.absorb((uint64_t)param.t)
		.absorb((uint64_t)param.logk)
		.absorb((uint64_t)param.tree_depth)
		.squeeze_block();
}

// The SoftSpoken that bootstraps a set below the nesting threshold.
// kChunkBlocks is sized so ferret_b9's base COTs fit in a single chunk
// (ferret_b10, the other direct-bootstrap set, takes two): the default chunk
// would overshoot b9.M by most of a chunk and ship unused PPRF planes.
using FerretBootstrapSoftSpoken =
	SoftSpoken<8, tuning::softspoken_ferret_bootstrap_chunk_blocks>;

Ferret::Ferret(int party, IOChannel *io,
		bool malicious, std::unique_ptr<OT> base_ot,
		PrimalLPNParameter param)
	: OTExtension(party, io, malicious,
	              base_ot ? std::move(base_ot)
	                      : std::unique_ptr<OT>(new FerretBaseOT(io))) {
	validate_primal_lpn_parameter(param);
	this->param = param;

	lpn_ = std::make_unique<Lpn<AuthValueFerret, 10>>(param.k);
	if (is_ot_sender()) {
		gadget_send_ = std::make_unique<MPCOT_Sender>(
		    param.t, param.tree_depth, io);
		if (malicious) gadget_send_->set_malicious();
		// Δ was sampled by the base ctor (LSB pinned to 1). Propagate
		// it into mpcot; outer protocols that want a specific Δ call
		// set_delta post-construction (which also re-propagates).
		gadget_send_->set_cggm_delta(this->Delta);
	} else {
		gadget_recv_ = std::make_unique<MPCOT_Receiver>(
		    param.t, param.tree_depth, io);
		if (malicious) gadget_recv_->set_malicious();
	}

	// Ping-pong buffers, each refill_trees * leave_n blocks. Slots
	// [0, M) hold the round's M base COTs; the slack
	// (refill_trees * leave_n - M) blocks are unused by mpcot/LPN
	// reads but addressable.
	const int64_t buf_blocks =
	    param.refill_trees * (int64_t{1} << param.tree_depth);
	carry_curr_.resize(buf_blocks);
	carry_next_.resize(buf_blocks);
}

Ferret::~Ferret() = default;

int64_t Ferret::chunk_size() const {
	return int64_t{1} << param.tree_depth;
}

// Pre-bootstrap only (enforced by OTExtension::set_delta on the
// inherited setup_done). After updating Delta/delta_bool on the
// base, re-propagate into the sender's mpcot gadget.
void Ferret::set_delta(const bool *bits) {
	OTExtension::set_delta(bits);
	gadget_send_->set_cggm_delta(this->Delta);
}

// Pre-bootstrap only. Nothing goes to base_ot here; bootstrap_ hands it to
// the nested source along with a derived child sid (see ferret.h).
void Ferret::set_sid(SessionID s) {
	expecting(!setup_done, "set_sid: bootstrap already fired");
	OT::set_sid(s);
}

void Ferret::set_choice_seed(const block *choice_seed, const block &lpn_seed) {
	expecting(!setup_done, "set_choice_seed: bootstrap already fired");
	if (is_ot_sender()) {
		expecting(choice_seed == nullptr,
		          "set_choice_seed: the sender has no choice bits; pass nullptr");
	} else {
		expecting(choice_seed != nullptr,
		          "set_choice_seed: the receiver needs a choice seed");
		choice_seed_ = *choice_seed;
	}
	lpn_root_ = lpn_seed;
	seeded_ = true;
}

// =====================================================================
// Lifecycle
// =====================================================================

void Ferret::begin() {
	enter_session_();
	bootstrap_();
	std::swap(carry_curr_, carry_next_);
	tree_idx_ = 0;
	inner_run_begin_();
}

void Ferret::next(block *out) {
	expect_in_session_();
	// Auto-rollover: if this round's user-visible budget is full,
	// restart transparently before producing the user's tree. The helper keeps
	// a counted begin() plan alive across this internal session boundary.
	const int64_t user_budget_trees = param.t - param.refill_trees;
	if (tree_idx_ == user_budget_trees) {
		restart_session_preserving_leftover_();
	}
	process_one_tree_(reinterpret_cast<AuthValueFerret*>(out));
	mark_chunk_unchecked_();
}

void Ferret::end() {
	expect_in_session_();
	if (can_close_checked_continuation_()) {
		// check() already finished the preceding round, then begin() swapped
		// its certified next-round base into carry_curr_. With no new tree
		// generated, undo that swap so a later ordinary begin() advances to
		// exactly this base again. inner_run_begin_ only reset check scratch.
		std::swap(carry_curr_, carry_next_);
		mark_checked_continuation_closed_();
		exit_session_();
		return;
	}
	run_refill_();
	if (mask_src_) draw_check_masks_(carry_curr_.data());
	inner_run_end_();
	mark_chunks_checked_();
	exit_session_();
}

// =====================================================================
// Per-stage helpers
// =====================================================================

// Idempotent. Writes the first round's M base COTs into next_ (the
// first begin() then swaps next_ → curr_).
//
// Tiered source: when param.M is large (b11 / b12 / b13), nest a
// ferret_b9 instance under SoftSpoken<8> so the expensive SoftSpoken
// extend only runs against b9's small M (~0.1M base COTs) instead of
// the full param.M, cutting bootstrap bytes severalfold. One round of
// b9 produces (t - refill_trees)·2^9 ≈ 1.1M RCOTs, which exceeds every
// other param's M, so a single b9 invocation suffices. b9's inner
// bootstrap sees its own small M, below the threshold, and drops
// straight to SoftSpoken — at most one level of nesting.
//
// With seeded choices (set_choice_seed) the base [128, M) carries the seeded
// choice bits: a set that bootstraps directly takes it from SoftSpoken's cot,
// with the seeded bits as the receiver's choices (one correction bit per COT,
// on SoftSpoken's own flow from the receiver), and a set that nests from a
// ferret_b9 seeded alike. Slots [0, 128) stay zero: every check draws its own
// masks (draw_check_masks_) from that SoftSpoken, which malicious mode keeps.
//
// FS transcript enabled before either path; in malicious mode it binds the
// per-tree chi seeds pulled by MPCOT. The public LPN matrix seed is derived
// once for this Ferret instance, at the first round's begin.
void Ferret::bootstrap_() {
	if (setup_done) return;
	fix_sid_();
	if (!io->fs_enabled())
		io->enable_fs(/*send_first=*/is_ot_sender());

	// base_ot moves into the nested source below, which runs it (including
	// any deferred base-OT check). Clear csw_base_, this instance's CSW view
	// of it, so no dangling alias remains.
	csw_base_ = nullptr;

	block *dst = carry_next_.data();
	int64_t n = param.M;
	if (seeded_) {
		std::fill(dst, dst + kConsistCheckCotNum, zero_block);
		dst += kConsistCheckCotNum;
		n -= kConsistCheckCotNum;
	}

	// The nested source gets its own derived session id (it re-forwards a
	// further-derived sid to the moved-in base OT). Role-symmetric: both
	// parties tick the counter identically.
	if (param.M > tuning::ferret_bootstrap_nest_factor * tuning::ferret_b9.M) {
		Ferret b9(party, io, /*malicious=*/malicious,
		          std::move(base_ot), tuning::ferret_b9);
		b9.set_sid(sid.derive());
		if (is_ot_sender()) b9.set_delta(delta_bool);
		if (seeded_)
			b9.set_choice_seed(is_ot_sender() ? nullptr : &choice_seed_, lpn_root_);
		b9.rcot(dst, n);
		mask_src_ = std::move(b9.mask_src_);
	} else {
		auto ssp = std::make_unique<FerretBootstrapSoftSpoken>(
		    party, io, /*malicious=*/malicious, std::move(base_ot));
		ssp->set_sid(sid.derive());
		if (is_ot_sender()) ssp->set_delta(delta_bool);
		if (!seeded_) {
			ssp->rcot(dst, n);
		} else if (is_ot_sender()) {
			ssp->send_cot(dst, n);
		} else {
			const block key = derive_choice_key_(choice_seed_, param);
			PRG choices(&key);
			default_init_vector<uint8_t> c(n);
			choices.random_bool(c.data(), n);
			ssp->recv_cot(dst, reinterpret_cast<const bool *>(c.data()), n);
		}
		if (seeded_ && malicious) mask_src_ = std::move(ssp);
	}
	setup_done = true;
}

// 128 fresh COTs for the check about to run, as one counted SoftSpoken
// session: one 128-OT unit, and in malicious mode SoftSpoken's sacrificial
// unit and its own check. All of it flows from the receiver to the sender,
// ahead of the check's reply from the receiver, so it adds no round trip.
void Ferret::draw_check_masks_(block *mask128) {
	mask_src_->begin(kConsistCheckCotNum);
	mask_src_->next_n(mask128, kConsistCheckCotNum);
	mask_src_->end();
}

// One-shot per-Ferret-lifetime LPN seed. Both parties derive it locally
// from the shared session id, or with seeded choices from the shared root (no
// wire exchange). Subsequent rounds let lpn_'s PRG state advance naturally
// through compute_slice.
void Ferret::inner_run_begin_() {
	if (is_ot_sender()) {
		gadget_send_->sid = sid.value();
		gadget_send_->run_begin();
	} else {
		gadget_recv_->sid = sid.value();
		gadget_recv_->run_begin();
	}
	if (!lpn_seed_set_) {
		lpn_->reseed(seeded_ ? derive_lpn_seed_from_root_(lpn_root_, param)
		                     : derive_lpn_seed_(sid.value()));
		lpn_seed_set_ = true;
	}
}

// Per-tree body. cggm-correction COTs live in curr_ starting at
// offset 128+k; LPN secret lives at curr_+128 (k blocks). The out
// pointer is layout-equivalent to a block*; reinterpret at the gadget
// and Lpn boundaries.
void Ferret::process_one_tree_(AuthValueFerret *out) {
	const int64_t cggm_off = kConsistCheckCotNum + param.k;
	const block* base_i =
	    carry_curr_.data() + cggm_off
	    + tree_idx_ * param.tree_depth;
	if (is_ot_sender()) {
		gadget_send_->run_next_tree(out, base_i, tree_idx_);
	} else {
		gadget_recv_->run_next_tree(out, base_i, tree_idx_);
	}
	lpn_->compute_slice(
	    out,
	    reinterpret_cast<AuthValueFerret*>(
	        carry_curr_.data() + kConsistCheckCotNum),
	    chunk_size());
	tree_idx_++;
}

void Ferret::inner_run_end_() {
	if (is_ot_sender()) {
		gadget_send_->run_end_packed(carry_curr_.data());
	} else {
		gadget_recv_->run_end_packed(carry_curr_.data());
	}
}

// Refill trees write directly into next_ (= next round's M base
// COTs). They share consist_check_VW with this session's
// user-visible trees; the round-final chi-fold check covers both.
void Ferret::run_refill_() {
	const int64_t leave_n = chunk_size();
	for (int64_t i = 0; i < param.refill_trees; ++i) {
		process_one_tree_(
		    reinterpret_cast<AuthValueFerret*>(
		        carry_next_.data() + i * leave_n));
	}
}

}  // namespace emp
