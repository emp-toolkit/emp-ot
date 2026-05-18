// Out-of-line definitions for Ferret. See ferret.h for the API.

#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/ot_extension/ferret/mpcot.h"
#include "emp-ot/ot_extension/ferret/lpn_f2.h"
#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"

namespace emp {

Ferret::Ferret(int party, IOChannel *io,
		bool malicious, PrimalLPNParameter param,
		std::unique_ptr<OT> base_ot)
	: OTExtension(party, io, malicious,
	              base_ot ? std::move(base_ot)
	                      : std::unique_ptr<OT>(new FerretBaseOT(io))) {
	this->param = param;
	this->tree_idx_ = 0;

	// Compute-only allocations and per-party state. Zero network I/O —
	// the SoftSpoken bootstrap that produces the first round's M base
	// COTs runs lazily on the first do_rcot_*_begin call.
	lpn_f2 = std::make_unique<LpnF2<10>>(param.k);
	if (is_ot_sender()) {
		mpcot_sender = std::make_unique<MPCOT_Sender>(param, io);
		if (malicious) mpcot_sender->set_malicious();
		// Δ was sampled by the base ctor (LSB pinned to 1). Propagate
		// it into mpcot; outer protocols that want a specific Δ call
		// set_delta post-construction (which also re-propagates).
		mpcot_sender->set_delta(this->Delta);
	} else {
		mpcot_receiver = std::make_unique<MPCOT_Receiver>(param, io);
		if (malicious) mpcot_receiver->set_malicious();
	}

	// Two ping-pong base buffers, each `param.refill_trees * leave_n` blocks.
	// Slots [0, param.M) hold the round's M base COTs; the slack
	// `(param.refill_trees * leave_n - M)` blocks are unused by mpcot/LPN
	// reads but addressable.
	const int64_t buf_blocks = param.refill_trees * (int64_t{1} << param.tree_depth);
	ot_pre_data_curr_.resize(buf_blocks);
	ot_pre_data_next_.resize(buf_blocks);
}

Ferret::~Ferret() = default;

int64_t Ferret::chunk_ots() const {
	return int64_t{1} << param.tree_depth;  // = leave_n
}

// =====================================================================
// Streaming API (do_rcot_* hooks for OTExtension)
// =====================================================================
//
// Auto-rollover note: when do_rcot_*_next hits the round boundary it
// calls do_rcot_*_end / _begin directly (not the public lifecycle
// wrappers from OTExtension). The session-active flag stays true
// throughout the rollover, which is correct — from the outside it's
// still one _next call.

// Override the base set_delta to propagate Δ into the sender-side
// mpcot state too. Base set_delta updates Delta + delta_bool[] and
// runs the standard preconditions (sender role, !setup_done,
// bits[0]).
void Ferret::set_delta(const bool *bits) {
	OTExtension::set_delta(bits);
	mpcot_sender->set_delta(this->Delta);
}

// Bootstrap: writes the first round's M base COTs into
// ot_pre_data_NEXT_ (not curr_). The first rcot_*_begin swaps next_
// → curr_ before consuming; after that every _end populates next_
// via the refill trees and every _begin swaps — steady state with
// no special-case for "first call".
//
// Tiered source: when param.M is large (b11 / b12 / b13), we nest a
// ferret_b10 instance under SoftSpoken<8> so the expensive SoftSpoken
// extend only runs against b10's small M (~74k base COTs) instead of
// the full param.M, cutting bootstrap bytes by ~7×. One round of b10
// produces t·2^d = 870k RCOTs which exceeds every other param's M
// (b13 at t=1900 needs 549k), so a single b10 invocation suffices.
// The b10 instance itself sees M=74k, below the threshold, so it
// drops straight to SoftSpoken — at most one level of nesting.
//
// IOChannel FS transcript is enabled here before either path. In
// mali mode it binds the per-tree chi seeds pulled by MPCOT via
// io->get_digest(); in both modes it gives Ferret a fresh
// per-round LPN seed (do_rcot_*_begin reseeds lpn_f2 from the
// digest at round entry). The fs_enabled() guard handles multiple
// Ferret setups sharing one io (the ot_extension and ferret
// bench harnesses build semi + mali back-to-back on one NetIO).
//
// Both source backends would auto-sample a fresh Δ on the sender;
// we override it with Ferret's Δ via set_delta so the produced
// base COTs match this Ferret instance's correlation.
void Ferret::bootstrap_base_cots_() {
	if (setup_done) return;
	if (!io->fs_enabled())
		io->enable_fs(/*send_first=*/is_ot_sender());
	auto pump = [&](auto* src) {
		if (is_ot_sender()) {
			// Forward this instance's Δ to the inner source's sender.
			src->set_delta(this->delta_bool);
			src->rcot_send(ot_pre_data_next_.data(), param.M);
		} else {
			// Forward a sub-seed pulled from this instance's choice_prg
			// to the inner source's receiver. The inner's base-COT LSBs
			// become our MPCOT alpha positions, so its choice randomness
			// fully determines ours — threading a seed pulled from our
			// own PRG gives end-to-end choice control from the top API.
			block inner_seed;
			this->choice_prg.random_block(&inner_seed, 1);
			src->set_choice_seed(inner_seed);
			src->rcot_recv(ot_pre_data_next_.data(), param.M);
		}
	};
	if (param.M > tuning::ferret_bootstrap_nest_factor * tuning::ferret_b10.M) {
		Ferret b10(party, io, /*malicious=*/malicious,
		              tuning::ferret_b10, std::move(base_ot));
		pump(&b10);
	} else {
		// kChunkBlocks sized so b10.M (~74k) fits in a single SoftSpoken
		// chunk (default 1024-block chunk would overproduce ~131k OTs
		// and ship the unused ~57k overhead on the wire). Tunable
		// via tuning::softspoken_ferret_bootstrap_chunk_blocks.
		SoftSpokenOT<8, tuning::softspoken_ferret_bootstrap_chunk_blocks>
			ssp(party, io, /*malicious=*/malicious, std::move(base_ot));
		pump(&ssp);
	}
	setup_done = true;
}

// Derive the per-round LPN seed: H("LPN seed" || receiver-supplied
// block from choice_prg). Domain-separated so the resulting seed is
// unrelated to other uses of choice_prg (alpha derivation, nested
// sub-seeds). Hashing also breaks any algebraic relation to
// choice_prg state — only the receiver knows that state, but the
// LPN seed is sent in the clear.
static block derive_lpn_seed(const block& r) {
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

// =====================================================================
// Streaming send-side
// =====================================================================

void Ferret::do_rcot_send_begin() {
	bootstrap_base_cots_();
	// Swap in the fresh M produced by previous end's refill (or by
	// SoftSpoken bootstrap on the first call). After this, curr_
	// holds the round's M, next_ is stale and will be overwritten
	// by THIS round's end.
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	mpcot_sender->run_begin();
	// LPN seed is picked once per Ferret lifetime: receiver derives it
	// from its choice_prg and sends to the sender; both reseed lpn_f2.
	// Subsequent rounds let lpn_f2's PRG state advance naturally
	// through compute_slice — no reseed needed, and the receiver's
	// choice_prg fully determines every choice bit emitted by this
	// instance.
	if (!lpn_seed_set_) {
		block lpn_seed;
		io->recv_block(&lpn_seed, 1);
		lpn_f2->reseed(lpn_seed);
		lpn_seed_set_ = true;
	}
}

void Ferret::do_rcot_send_next(block* out) {
	// Disjoint layout in [0, M):
	//   chi-check : [0, 128)
	//   LPN       : [128, 128 + param.k)
	//   cGGM      : [128 + param.k, M)
	// Each base COT plays exactly one role per round; aliasing roles
	// would leak (cGGM ships c[j] = base[j] ^ K0[j] on the wire, so
	// any base entry consumed there must not also feed LPN or chi).
	const int64_t cggm_off = kConsistCheckCotNum + param.k;

	// Auto rollover: if this call would overrun the round's
	// user-visible budget, finish the round (refill + chi-fold)
	// and start a new one before producing the user's tree.
	if (tree_idx_ == param.t - param.refill_trees) {
		do_rcot_send_end();
		do_rcot_send_begin();
	}

	const block* base_i = ot_pre_data_curr_.data() + cggm_off + tree_idx_ * param.tree_depth;
	mpcot_sender->run_next_tree(out, base_i, tree_idx_);
	lpn_f2->compute_slice(out,
	                      ot_pre_data_curr_.data() + kConsistCheckCotNum,
	                      chunk_ots());
	tree_idx_++;
}

void Ferret::do_rcot_send_end() {
	const int64_t leave_n = chunk_ots();
	const int64_t cggm_off = kConsistCheckCotNum + param.k;
	// Run param.refill_trees trees, output → next_ buffer (= the next
	// round's M base COTs). These trees consume curr_'s remaining
	// cGGM-correction slots and accumulate into consist_check_VW
	// alongside any user-visible trees this session produced.
	for (int64_t i = 0; i < param.refill_trees; ++i) {
		block* refill_slot = ot_pre_data_next_.data() + i * leave_n;
		const block* base_i = ot_pre_data_curr_.data() + cggm_off + tree_idx_ * param.tree_depth;
		mpcot_sender->run_next_tree(refill_slot, base_i, tree_idx_);
		lpn_f2->compute_slice(refill_slot,
		                      ot_pre_data_curr_.data() + kConsistCheckCotNum,
		                      leave_n);
		tree_idx_++;
	}
	// Chi-fold check on this session's accumulated VW (user-visible
	// + refill trees). VW slots not written this session remain zero
	// on both sides, contributing nothing to the XOR-fold.
	mpcot_sender->run_end(ot_pre_data_curr_.data());
}

// =====================================================================
// Streaming recv-side (mirrors send)
// =====================================================================

void Ferret::do_rcot_recv_begin() {
	bootstrap_base_cots_();
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	mpcot_receiver->run_begin();
	// One-shot LPN seed exchange at the first round; see send side
	// for rationale. PRG state of lpn_f2 then evolves continuously
	// across all subsequent rounds for this Ferret instance.
	if (!lpn_seed_set_) {
		block r;
		this->choice_prg.random_block(&r, 1);
		block lpn_seed = derive_lpn_seed(r);
		io->send_block(&lpn_seed, 1);
		io->flush();
		lpn_f2->reseed(lpn_seed);
		lpn_seed_set_ = true;
	}
}

void Ferret::do_rcot_recv_next(block* out) {
	const int64_t cggm_off = kConsistCheckCotNum + param.k;

	if (tree_idx_ == param.t - param.refill_trees) {
		do_rcot_recv_end();
		do_rcot_recv_begin();
	}

	const block* base_i = ot_pre_data_curr_.data() + cggm_off + tree_idx_ * param.tree_depth;
	mpcot_receiver->run_next_tree(out, base_i, tree_idx_);
	lpn_f2->compute_slice(out,
	                      ot_pre_data_curr_.data() + kConsistCheckCotNum,
	                      chunk_ots());
	tree_idx_++;
}

void Ferret::do_rcot_recv_end() {
	const int64_t leave_n = chunk_ots();
	const int64_t cggm_off = kConsistCheckCotNum + param.k;
	for (int64_t i = 0; i < param.refill_trees; ++i) {
		block* refill_slot = ot_pre_data_next_.data() + i * leave_n;
		const block* base_i = ot_pre_data_curr_.data() + cggm_off + tree_idx_ * param.tree_depth;
		mpcot_receiver->run_next_tree(refill_slot, base_i, tree_idx_);
		lpn_f2->compute_slice(refill_slot,
		                      ot_pre_data_curr_.data() + kConsistCheckCotNum,
		                      leave_n);
		tree_idx_++;
	}
	mpcot_receiver->run_end(ot_pre_data_curr_.data());
}

}  // namespace emp
