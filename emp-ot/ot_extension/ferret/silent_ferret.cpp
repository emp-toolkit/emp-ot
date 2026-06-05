// Out-of-line definitions for SilentFerret. See silent_ferret.h for the
// API and the wire-free / deferred-check / consumer-driven rationale.

#include "emp-ot/ot_extension/ferret/silent_ferret.h"
#include "emp-ot/common/lpn.h"
#include <algorithm>
#include <cassert>

namespace emp {

// cGGM per-tree correction scratch (tree_depth blocks). Stack-allocated
// per produce call so the produce path is reentrant; sized to the largest
// Ferret tree_depth with margin.
static constexpr int kMaxTreeDepth = 32;

SilentFerret::SilentFerret(int party, IOChannel *io, bool malicious,
                           PrimalLPNParameter param,
                           std::unique_ptr<OT> base_ot, int n_threads)
	: Ferret(party, io, malicious, param, std::move(base_ot)),
	  n_threads_(n_threads < 1 ? 1 : n_threads) {
	assert(param.tree_depth <= kMaxTreeDepth && "tree_depth exceeds scratch");
	// One wave holds `batch_` trees' leaf buffers in flight; a small
	// multiple of the worker count keeps every worker busy while bounding
	// peak scratch (batch_ * leave_n blocks). Serial (1) when single-threaded.
	batch_ = (n_threads_ <= 1) ? 1 : n_threads_ * 8;
	// Deterministic LPN PRG blocks consumed per chunk; tree j folds the
	// stream at round_base_ + j*bpc_ (see produce_range).
	bpc_ = lpn_->blocks_per_chunk(chunk_size());
}

SilentFerret::~SilentFerret() = default;

void SilentFerret::begin() {
	// Base does bootstrap (once) + ping-pong swap + tree_idx_=0 +
	// inner_run_begin_ (gadget round-begin sizes consist_check_VW, LPN seed).
	Ferret::begin();
	if (n_threads_ > 1 && !pool_)
		pool_ = std::make_unique<ThreadPool>((size_t)n_threads_);

	// LPN PRG key is fixed for the instance's lifetime (reseed is one-shot
	// inside inner_run_begin_); capture it so produce_range can fork PRGs.
	lpn_key_ = lpn_->prg_key();

	// All MPCOT correction traffic up front: sender ships every tree's
	// correction (one flush) and keeps the root seeds; receiver stores the
	// corrections. In malicious mode both fold each tree's chi contribution
	// into the gadget's VW here, so end()'s run_end_packed check is unchanged.
	const block *base = carry_curr_.data() + (kConsistCheckCotNum + param.k);
	if (is_ot_sender())
		gadget_send_->prepare_all(pool_.get(), batch_, base);
	else
		gadget_recv_->prepare_all(pool_.get(), batch_, base);
}

void SilentFerret::end() {
	// Refill trees are the fixed tail [round_capacity(), t) of the round;
	// produce them by absolute index into next round's base buffer. Done
	// here (not via the inherited run_refill_) because produce_range does
	// not advance tree_idx_, so the cursor can't drive the refill.
	produce_range_(carry_next_.data(), round_capacity(), param.refill_trees);
	// This round consumed LPN counters [round_base_, round_base_ + t*bpc_):
	// user trees [0,user_budget) + refill [user_budget, t). Advance so the
	// next round's tree 0 picks up where the refill trees left off.
	round_base_ += (uint64_t)param.t * bpc_;
	inner_run_end_();   // deferred malicious chi-fold check (no-op if semi)
	exit_session_();
}

int64_t SilentFerret::round_capacity() const {
	return param.t - param.refill_trees;
}

void SilentFerret::produce_range(block *out, int64_t tree_begin,
                                 int64_t n_trees) const {
	assert(tree_begin >= 0 && n_trees >= 0 &&
	       tree_begin + n_trees <= round_capacity() &&
	       "produce_range out of round bounds");
	produce_range_(out, tree_begin, n_trees);
}

void SilentFerret::produce_range_(block *out, int64_t tree_begin,
                                  int64_t n_trees) const {
	const int64_t chunk = chunk_size();
	const int64_t cggm_off = kConsistCheckCotNum + param.k;
	const AuthValueFerret *pre = reinterpret_cast<const AuthValueFerret *>(
	    carry_curr_.data() + kConsistCheckCotNum);

	// Per-call (thread-local) scratch + a PRG forked to this range's LPN
	// offset. Counters are contiguous across the range, so one PRG advances
	// naturally through it (one AES key-schedule amortized over n_trees).
	block k_scratch[kMaxTreeDepth];
	PRG lpn_prg(&lpn_key_);
	lpn_prg.seek(round_base_ + (uint64_t)tree_begin * bpc_);

	for (int64_t i = 0; i < n_trees; ++i) {
		const int64_t j = tree_begin + i;
		AuthValueFerret *o = reinterpret_cast<AuthValueFerret *>(out + i * chunk);
		if (is_ot_sender()) {
			gadget_send_->produce_tree(o, (int)j, k_scratch);
		} else {
			const block *base_j =
			    carry_curr_.data() + cggm_off + j * param.tree_depth;
			gadget_recv_->produce_tree(o, base_j, (int)j, k_scratch);
		}
		lpn_->compute_slice(lpn_prg, o, pre, chunk);  // advances by bpc_ → tree j+1
	}
}

// Wire-free per-tree body for the serial cursor API (next / run / next_n):
// produce the single tree at the cursor. Same index scheme as
// produce_range, so the two paths are bit-identical.
void SilentFerret::process_one_tree_(AuthValueFerret *out) {
	produce_range_(reinterpret_cast<block *>(out), tree_idx_, 1);
	tree_idx_++;
}

}  // namespace emp
