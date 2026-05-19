// Out-of-line definitions for Ferret. See ferret.h for the API.
//
// Structure parallel to Svole<AuthValue, IO>: a single class
// inheriting StreamingExtension<block> (via OTExtension), implementing
// the same 4-step round loop directly in do_begin / do_next / do_end:
//
//   do_begin : lazy bootstrap → swap curr/next → tree_idx_ = 0
//              → inner_run_begin_ (gadget round-begin + one-shot LPN
//                                  seed exchange)
//   do_next  : if this round's user-visible budget is full, do_end +
//              do_begin (transparent rollover); then process_one_tree_
//   do_end   : run_refill_ (refill trees write directly into next_) +
//              inner_run_end_ (chi-fold check)
//
// AuthValueFerret is layout-equivalent to `block`, so the
// StreamingExtension<block> output buffer is reinterpreted to
// AuthValueFerret* at the gadget / Lpn boundary.

#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/common/lpn.h"
#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"

namespace emp {

// Derive the per-Ferret-lifetime LPN seed: H("LPN seed" || r). The
// domain separator makes the resulting seed unrelated to other uses
// of choice_prg (alpha derivation, nested sub-seeds); hashing also
// breaks any algebraic relation, since only the receiver knows
// choice_prg's state but the LPN seed is sent in the clear.
static block derive_lpn_seed_(const block& r) {
	Hash h;
	static const char label[] = "LPN seed";
	h.put(label, sizeof(label) - 1);
	h.put(&r, sizeof(r));
	unsigned char digest[Hash::DIGEST_SIZE];
	h.digest(digest);
	block out;
	memcpy(&out, digest, sizeof(block));
	return out;
}

Ferret::Ferret(int party, IOChannel *io,
		bool malicious, PrimalLPNParameter param,
		std::unique_ptr<OT> base_ot)
	: OTExtension(party, io, malicious,
	              base_ot ? std::move(base_ot)
	                      : std::unique_ptr<OT>(new FerretBaseOT(io))) {
	this->param = param;

	lpn_f2_ = std::make_unique<Lpn<AuthValueFerret, 10>>(param.k);
	if (is_ot_sender()) {
		mpcot_sender_ = std::make_unique<MPCOT_Sender>(
		    param.t, param.tree_depth, io);
		if (malicious) mpcot_sender_->set_malicious();
		// Δ was sampled by the base ctor (LSB pinned to 1). Propagate
		// it into mpcot; outer protocols that want a specific Δ call
		// set_delta post-construction (which also re-propagates).
		mpcot_sender_->set_cggm_delta(this->Delta);
	} else {
		mpcot_receiver_ = std::make_unique<MPCOT_Receiver>(
		    param.t, param.tree_depth, io);
		if (malicious) mpcot_receiver_->set_malicious();
	}

	// Ping-pong buffers, each refill_trees * leave_n blocks. Slots
	// [0, M) hold the round's M base COTs; the slack
	// (refill_trees * leave_n - M) blocks are unused by mpcot/LPN
	// reads but addressable.
	const int64_t buf_blocks =
	    param.refill_trees * (int64_t{1} << param.tree_depth);
	ot_pre_data_curr_.resize(buf_blocks);
	ot_pre_data_next_.resize(buf_blocks);
}

Ferret::~Ferret() = default;

int64_t Ferret::chunk_size() const {
	return int64_t{1} << param.tree_depth;
}

// Pre-bootstrap only (asserted by OTExtension::set_delta on the
// inherited setup_done). After updating Delta/delta_bool on the
// base, re-propagate into the sender's mpcot gadget.
void Ferret::set_delta(const bool *bits) {
	OTExtension::set_delta(bits);
	mpcot_sender_->set_cggm_delta(this->Delta);
}

// =====================================================================
// Lifecycle
// =====================================================================

void Ferret::do_begin() {
	bootstrap_();
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	inner_run_begin_();
}

void Ferret::do_next(block *out) {
	// Auto-rollover: if this round's user-visible budget is full,
	// run end+begin transparently before producing the user's tree.
	const int64_t user_budget_trees = param.t - param.refill_trees;
	if (tree_idx_ == user_budget_trees) {
		do_end();
		do_begin();
	}
	process_one_tree_(reinterpret_cast<AuthValueFerret*>(out));
}

void Ferret::do_end() {
	run_refill_();
	inner_run_end_();
}

// =====================================================================
// Per-stage helpers
// =====================================================================

// Idempotent. Writes the first round's M base COTs into next_ (the
// first do_begin then swaps next_ → curr_).
//
// Tiered source: when param.M is large (b11 / b12 / b13), nest a
// ferret_b10 instance under SoftSpoken<8> so the expensive SoftSpoken
// extend only runs against b10's small M (~74k base COTs) instead of
// the full param.M, cutting bootstrap bytes by ~7×. One round of b10
// produces t·2^d = 870k RCOTs which exceeds every other param's M, so
// a single b10 invocation suffices. b10's inner bootstrap sees M=74k,
// below the threshold, and drops straight to SoftSpoken — at most one
// level of nesting.
//
// FS transcript enabled before either path; in malicious mode it
// binds the per-tree chi seeds pulled by MPCOT, and in both modes it
// gives Ferret a fresh per-round LPN seed.
void Ferret::bootstrap_() {
	if (setup_done) return;
	if (!io->fs_enabled())
		io->enable_fs(/*send_first=*/is_ot_sender());

	auto pump = [&](auto* src) {
		if (is_ot_sender()) {
			src->set_delta(delta_bool);
			src->rcot_send(ot_pre_data_next_.data(), param.M);
		} else {
			// Forward a sub-seed pulled from this Ferret's choice_prg
			// to the inner source's receiver: the inner's base-COT
			// LSBs become our MPCOT alpha positions, so its choice
			// randomness fully determines ours. End-to-end choice
			// control from the top API.
			block inner_seed;
			choice_prg.random_block(&inner_seed, 1);
			src->set_choice_seed(inner_seed);
			src->rcot_recv(ot_pre_data_next_.data(), param.M);
		}
	};

	if (param.M > tuning::ferret_bootstrap_nest_factor * tuning::ferret_b10.M) {
		Ferret b10(party, io, /*malicious=*/malicious,
		           tuning::ferret_b10, std::move(base_ot));
		pump(&b10);
	} else {
		// kChunkBlocks sized so b10.M (~74k) fits in a single
		// SoftSpoken chunk — default 1024-block chunk would
		// overproduce ~131k OTs and ship unused overhead on the wire.
		SoftSpokenOT<8, tuning::softspoken_ferret_bootstrap_chunk_blocks>
		    ssp(party, io, /*malicious=*/malicious, std::move(base_ot));
		pump(&ssp);
	}
	setup_done = true;
}

// One-shot per-Ferret-lifetime LPN seed exchange folds into here.
// Receiver derives the seed from its choice_prg (with domain-
// separated hash) and sends; sender receives. Both reseed lpn_f2_.
// Subsequent rounds let lpn_f2_'s PRG state advance naturally
// through compute_slice.
void Ferret::inner_run_begin_() {
	if (is_ot_sender()) {
		mpcot_sender_->run_begin();
		if (!lpn_seed_set_) {
			block lpn_seed;
			io->recv_block(&lpn_seed, 1);
			lpn_f2_->reseed(lpn_seed);
			lpn_seed_set_ = true;
		}
	} else {
		mpcot_receiver_->run_begin();
		if (!lpn_seed_set_) {
			block r;
			choice_prg.random_block(&r, 1);
			block lpn_seed = derive_lpn_seed_(r);
			io->send_block(&lpn_seed, 1);
			io->flush();
			lpn_f2_->reseed(lpn_seed);
			lpn_seed_set_ = true;
		}
	}
}

// Per-tree body. cggm-correction COTs live in curr_ starting at
// offset 128+k; LPN secret lives at curr_+128 (k blocks). The out
// pointer is layout-equivalent to a block*; reinterpret at the gadget
// and Lpn boundaries.
void Ferret::process_one_tree_(AuthValueFerret *out) {
	const int64_t cggm_off = kConsistCheckCotNum + param.k;
	const block* base_i =
	    ot_pre_data_curr_.data() + cggm_off
	    + tree_idx_ * param.tree_depth;
	if (is_ot_sender()) {
		mpcot_sender_->run_next_tree(out, base_i, tree_idx_);
	} else {
		mpcot_receiver_->run_next_tree(out, base_i, tree_idx_);
	}
	lpn_f2_->compute_slice(
	    out,
	    reinterpret_cast<AuthValueFerret*>(
	        ot_pre_data_curr_.data() + kConsistCheckCotNum),
	    chunk_size());
	tree_idx_++;
}

void Ferret::inner_run_end_() {
	if (is_ot_sender()) {
		mpcot_sender_->run_end_packed(ot_pre_data_curr_.data());
	} else {
		mpcot_receiver_->run_end_packed(ot_pre_data_curr_.data());
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
		        ot_pre_data_next_.data() + i * leave_n));
	}
}

}  // namespace emp
