// Out-of-line definitions for FerretCOT. See ferret_cot.h for the API.

#include "emp-ot/ot_extension/ferret/ferret_cot.h"
#include "emp-ot/ot_extension/ferret/mpcot.h"
#include "emp-ot/ot_extension/ferret/lpn_f2.h"
#include "emp-ot/ot_extension/softspoken/softspoken_ot.h"

namespace emp {

FerretCOT::FerretCOT(int party, IOChannel *io,
		bool malicious, bool run_setup, PrimalLPNParameter param,
		std::unique_ptr<OT> base_ot) {
	this->party = party;
	this->io = io;
	this->is_malicious = malicious;
	this->param = param;
	this->base_ot_ = std::move(base_ot);

	this->extend_initialized = false;
	this->tree_idx_ = 0;

	if(run_setup) {
		if(party == ALICE) {
			PRG prg;
			prg.random_block(&Delta);
			Delta = (Delta & lsb_clear_mask) ^ lsb_only_mask;
			setup(Delta);
		} else setup();
	}
}

FerretCOT::~FerretCOT() = default;

int64_t FerretCOT::chunk_ots() const {
	return int64_t{1} << param.log_bin_sz;  // = leave_n
}

void FerretCOT::setup(block Deltain) {
	this->Delta = Deltain;
	setup();
}

void FerretCOT::setup() {
	lpn_f2 = std::make_unique<LpnF2<10>>(party, param.n, param.k, io);
	if (party == ALICE) {
		mpcot_sender = std::make_unique<MPCOT_Sender>(param.n, param.t, param.log_bin_sz, io);
		if (is_malicious) mpcot_sender->set_malicious();
		mpcot_sender->set_delta(Delta);
	} else {
		mpcot_receiver = std::make_unique<MPCOT_Receiver>(param.n, param.t, param.log_bin_sz, io);
		if (is_malicious) mpcot_receiver->set_malicious();
	}

	const int tree_n  = param.t;
	const int tree_h  = param.log_bin_sz + 1;
	const int leave_n = 1 << param.log_bin_sz;

	// M base COTs per round = LPN k + cGGM level corrections
	// (tree_n × (h-1)) + 128 for the malicious consistency check.
	M           = param.k + tree_n * (tree_h - 1) + MPCOT_Sender::kConsistCheckCotNum;
	refill_trees = (M + leave_n - 1) / leave_n;  // ceil(M / leave_n)
	extend_initialized = true;
	tree_idx_   = 0;

	// Two ping-pong base buffers, each `refill_trees * leave_n` blocks.
	// Slots [0, M) hold the round's M base COTs; the slack
	// `(refill_trees * leave_n - M)` blocks are unused by mpcot/LPN
	// reads but addressable.
	const int64_t buf_blocks = (int64_t)refill_trees * leave_n;
	ot_pre_data_curr_.resize(buf_blocks);
	ot_pre_data_next_.resize(buf_blocks);

	// Bootstrap: SoftSpokenOT<8> writes the first round's M base COTs
	// into ot_pre_data_NEXT_ (not curr_). The first rcot_*_begin
	// swaps next_ → curr_ before consuming. After that, every end
	// populates next_ via the refill trees, every begin swaps —
	// steady state with no special-case for "first call".
	//
	// IOChannel FS transcript is enabled before bootstrap so every
	// byte from setup onward binds the per-tree chi seeds pulled by
	// MPCOT via netio->get_digest() (no-op for semi-honest).
	if (is_malicious) io->enable_fs(/*send_first=*/party == ALICE);

	SoftSpokenOT<8> ssp(io, std::move(base_ot_));
	if (is_malicious) ssp.set_malicious(true);
	if (party == ALICE) { ssp.setup_send(Delta); ssp.rcot_send(ot_pre_data_next_.data(), M); }
	else                { ssp.setup_recv();      ssp.rcot_recv(ot_pre_data_next_.data(), M); }
}

// =====================================================================
// Streaming send-side
// =====================================================================

void FerretCOT::rcot_send_begin() {
	if (!extend_initialized) error("Run setup before extending");
	// Swap in the fresh M produced by previous end's refill (or by
	// SoftSpoken bootstrap on the first call). After this, curr_
	// holds the round's M, next_ is stale and will be overwritten
	// by THIS round's end.
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	mpcot_sender->run_begin();
	lpn_f2->begin_round();   // network seed exchange (one block)
}

void FerretCOT::rcot_send_next(block* out) {
	const int tree_n  = param.t;
	const int n_lvl   = param.log_bin_sz;            // tree_height - 1
	const int64_t leave_n = chunk_ots();

	// Auto rollover: if this call would overrun the round's
	// user-visible budget, finish the round (refill + chi-fold)
	// and start a new one before producing the user's tree.
	if (tree_idx_ == tree_n - refill_trees) {
		rcot_send_end();
		rcot_send_begin();
	}

	const block* base_i = ot_pre_data_curr_.data() + tree_idx_ * n_lvl;
	mpcot_sender->run_next_tree(out, base_i, tree_idx_);
	lpn_f2->compute_slice(out,
	                      ot_pre_data_curr_.data() + MPCOT_Sender::kConsistCheckCotNum,
	                      leave_n);
	tree_idx_++;
}

void FerretCOT::rcot_send_end() {
	const int n_lvl   = param.log_bin_sz;
	const int64_t leave_n = chunk_ots();
	// Run refill_trees trees, output → next_ buffer (= the next
	// round's M base COTs). These trees consume curr_'s remaining
	// cGGM-correction slots and accumulate into consist_check_VW
	// alongside any user-visible trees this session produced.
	for (int64_t i = 0; i < refill_trees; ++i) {
		block* refill_slot = ot_pre_data_next_.data() + i * leave_n;
		const block* base_i = ot_pre_data_curr_.data() + tree_idx_ * n_lvl;
		mpcot_sender->run_next_tree(refill_slot, base_i, tree_idx_);
		lpn_f2->compute_slice(refill_slot,
		                      ot_pre_data_curr_.data() + MPCOT_Sender::kConsistCheckCotNum,
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

void FerretCOT::rcot_recv_begin() {
	if (!extend_initialized) error("Run setup before extending");
	std::swap(ot_pre_data_curr_, ot_pre_data_next_);
	tree_idx_ = 0;
	mpcot_receiver->run_begin();
	lpn_f2->begin_round();
}

void FerretCOT::rcot_recv_next(block* out) {
	const int tree_n  = param.t;
	const int n_lvl   = param.log_bin_sz;
	const int64_t leave_n = chunk_ots();

	if (tree_idx_ == tree_n - refill_trees) {
		rcot_recv_end();
		rcot_recv_begin();
	}

	const block* base_i = ot_pre_data_curr_.data() + tree_idx_ * n_lvl;
	mpcot_receiver->run_next_tree(out, base_i, tree_idx_);
	lpn_f2->compute_slice(out,
	                      ot_pre_data_curr_.data() + MPCOT_Receiver::kConsistCheckCotNum,
	                      leave_n);
	tree_idx_++;
}

void FerretCOT::rcot_recv_end() {
	const int n_lvl   = param.log_bin_sz;
	const int64_t leave_n = chunk_ots();
	for (int64_t i = 0; i < refill_trees; ++i) {
		block* refill_slot = ot_pre_data_next_.data() + i * leave_n;
		const block* base_i = ot_pre_data_curr_.data() + tree_idx_ * n_lvl;
		mpcot_receiver->run_next_tree(refill_slot, base_i, tree_idx_);
		lpn_f2->compute_slice(refill_slot,
		                      ot_pre_data_curr_.data() + MPCOT_Receiver::kConsistCheckCotNum,
		                      leave_n);
		tree_idx_++;
	}
	mpcot_receiver->run_end(ot_pre_data_curr_.data());
}

// =====================================================================
// One-shot wrappers (RandomCOT contract)
// =====================================================================

// Helper: drain up to `take_max` blocks of leftover into `out`.
// Returns the number drained.
static int64_t drain_leftover(block* out, int64_t take_max,
                              BlockVec& leftover, int& pos, int& count) {
	if (count == 0) return 0;
	int64_t take = std::min<int64_t>(take_max, count);
	memcpy(out, leftover.data() + pos, take * sizeof(block));
	pos   += (int)take;
	count -= (int)take;
	return take;
}

void FerretCOT::rcot_send(block* data, int64_t num) {
	const int64_t chunk = chunk_ots();
	int64_t produced = drain_leftover(data, num, leftover_,
	                                  leftover_pos_, leftover_count_);
	if (produced == num) return;

	rcot_send_begin();
	while (produced + chunk <= num) {
		rcot_send_next(data + produced);
		produced += chunk;
	}
	if (produced < num) {
		// Partial tail: produce one more tree into leftover_, copy
		// the user-requested prefix to data, save the suffix for the
		// next rcot_send call.
		if (leftover_.empty()) leftover_.resize(chunk);
		rcot_send_next(leftover_.data());
		int64_t take = num - produced;
		memcpy(data + produced, leftover_.data(), take * sizeof(block));
		leftover_pos_   = (int)take;
		leftover_count_ = (int)(chunk - take);
	}
	rcot_send_end();
}

void FerretCOT::rcot_recv(block* data, int64_t num) {
	const int64_t chunk = chunk_ots();
	int64_t produced = drain_leftover(data, num, leftover_,
	                                  leftover_pos_, leftover_count_);
	if (produced == num) return;

	rcot_recv_begin();
	while (produced + chunk <= num) {
		rcot_recv_next(data + produced);
		produced += chunk;
	}
	if (produced < num) {
		if (leftover_.empty()) leftover_.resize(chunk);
		rcot_recv_next(leftover_.data());
		int64_t take = num - produced;
		memcpy(data + produced, leftover_.data(), take * sizeof(block));
		leftover_pos_   = (int)take;
		leftover_count_ = (int)(chunk - take);
	}
	rcot_recv_end();
}

}  // namespace emp
