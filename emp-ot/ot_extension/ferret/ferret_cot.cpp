// Out-of-line definitions for FerretCOT. See ferret_cot.h for the API.

#include "emp-ot/ot_extension/ferret/ferret_cot.h"
#include "emp-ot/ot_extension/ferret/mpcot.h"
#include "emp-ot/ot_extension/ferret/lpn_f2.h"
#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"

namespace emp {

FerretCOT::FerretCOT(int party, IOChannel *io,
		bool malicious, PrimalLPNParameter param,
		std::unique_ptr<OT> base_ot) {
	this->party = party;
	this->io = io;
	this->is_malicious = malicious;
	this->param = param;
	this->base_ot_ = std::move(base_ot);

	this->bootstrap_done_ = false;
	this->tree_idx_ = 0;

	// Compute-only allocations and per-party state. Zero network I/O —
	// the SoftSpoken bootstrap that produces the first round's M base
	// COTs runs lazily on the first do_rcot_*_begin call.
	lpn_f2 = std::make_unique<LpnF2<10>>(param.k);
	if (party == ALICE) {
		mpcot_sender = std::make_unique<MPCOT_Sender>(param, io);
		if (is_malicious) mpcot_sender->set_malicious();
		// Random Δ with LSB pinned to 1 (the LSB-encoded choice
		// convention shared with the other extensions). Outer protocols
		// that want a specific Δ call set_delta after construction and
		// before the first rcot_*.
		PRG prg;
		prg.random_block(&Delta);
		Delta = (Delta & lsb_clear_mask) ^ lsb_only_mask;
		mpcot_sender->set_delta(Delta);
	} else {
		mpcot_receiver = std::make_unique<MPCOT_Receiver>(param, io);
		if (is_malicious) mpcot_receiver->set_malicious();
	}

	// Two ping-pong base buffers, each `param.refill_trees * leave_n` blocks.
	// Slots [0, param.M) hold the round's M base COTs; the slack
	// `(param.refill_trees * leave_n - M)` blocks are unused by mpcot/LPN
	// reads but addressable.
	const int64_t buf_blocks = param.refill_trees * (int64_t{1} << param.tree_depth);
	ot_pre_data_curr_.resize(buf_blocks);
	ot_pre_data_next_.resize(buf_blocks);
}

FerretCOT::~FerretCOT() = default;

int64_t FerretCOT::chunk_ots() const {
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

// Replace the ctor-sampled Δ with one supplied by an outer protocol.
// Must fire before the SoftSpoken bootstrap consumes Δ (i.e. before
// the first rcot_*_begin call).
void FerretCOT::set_delta(const bool *delta_bool) {
	assert(party == ALICE && "FerretCOT::set_delta: receiver has no Δ");
	assert(!bootstrap_done_ && "FerretCOT::set_delta: bootstrap already fired");
	assert(delta_bool[0] && "FerretCOT::set_delta: delta_bool[0] must be true");
	Delta = bool_to_block(delta_bool);
	mpcot_sender->set_delta(Delta);
}

// Bootstrap: writes the first round's M base COTs into
// ot_pre_data_NEXT_ (not curr_). The first rcot_*_begin swaps next_
// → curr_ before consuming; after that every _end populates next_
// via the refill trees and every _begin swaps — steady state with
// no special-case for "first call".
//
// Tiered source: when param.M is large (i.e. b11 / b12 / b13), we
// nest a ferret_b10 instance under SoftSpoken<8> so the expensive
// SoftSpoken extend only runs against b10's small M (~74k base COTs
// instead of b13's 541k), cutting bootstrap bytes roughly 6×. One
// round of b10 produces t·2^d = 870k RCOTs which exceeds every
// other param's M, so a single b10 invocation suffices. The b10
// instance itself sees M=74k, below the threshold, so it drops
// straight to SoftSpoken — at most one level of nesting.
//
// IOChannel FS transcript is enabled here before either path. In
// mali mode it binds the per-tree chi seeds pulled by MPCOT via
// io->get_digest(); in both modes it gives FerretCOT a fresh
// per-round LPN seed (do_rcot_*_begin reseeds lpn_f2 from the
// digest at round entry). The fs_enabled() guard handles multiple
// FerretCOT setups sharing one io (the ot_extension and ferret
// bench harnesses build semi + mali back-to-back on one NetIO).
//
// Both source backends would auto-sample a fresh Δ on the sender;
// we override it with FerretCOT's Δ via set_delta so the produced
// base COTs match this FerretCOT instance's correlation.
void FerretCOT::bootstrap_base_cots_() {
	if (bootstrap_done_) return;
	if (!io->fs_enabled())
		io->enable_fs(/*send_first=*/party == ALICE);
	auto pump = [&](auto* src) {
		if (party == ALICE) {
			bool delta_bool[128];
			bits_to_bools(delta_bool, &Delta, 128);
			delta_bool[0] = true;
			src->set_delta(delta_bool);
			src->rcot_send(ot_pre_data_next_.data(), param.M);
		} else {
			src->rcot_recv(ot_pre_data_next_.data(), param.M);
		}
	};
	if (param.M > 2 * ferret_b10.M) {
		FerretCOT b10(party, io, /*malicious=*/is_malicious,
		              ferret_b10, std::move(base_ot_));
		pump(&b10);
	} else {
		// kChunkBlocks=580 → 74,240 OTs/chunk, sized so the tier's
		// b10.M = 74,164 base-COT request fits in a single SoftSpoken
		// chunk (default 1024-block chunk would overproduce 131k OTs
		// and ship the unused ~57k overhead on the wire).
		SoftSpokenOT<8, 580> ssp(party, io, /*malicious=*/is_malicious,
		                         std::move(base_ot_));
		pump(&ssp);
	}
	bootstrap_done_ = true;
}

// =====================================================================
// Streaming send-side
// =====================================================================

void FerretCOT::do_rcot_send_begin() {
	bootstrap_base_cots_();
	// Swap in the fresh M produced by previous end's refill (or by
	// SoftSpoken bootstrap on the first call). After this, curr_
	// holds the round's M, next_ is stale and will be overwritten
	// by THIS round's end.
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	mpcot_sender->run_begin();
	// Per-round LPN seed snapshotted from the FS transcript: binds
	// every byte exchanged from setup through the previous round's
	// chi-fold check. Both parties absorb the same byte stream so
	// they derive the same seed.
	lpn_f2->reseed(io->get_digest());
}

void FerretCOT::do_rcot_send_next(block* out) {
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

void FerretCOT::do_rcot_send_end() {
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

void FerretCOT::do_rcot_recv_begin() {
	bootstrap_base_cots_();
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	mpcot_receiver->run_begin();
	lpn_f2->reseed(io->get_digest());
}

void FerretCOT::do_rcot_recv_next(block* out) {
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

void FerretCOT::do_rcot_recv_end() {
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
