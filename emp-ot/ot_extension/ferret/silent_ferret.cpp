// Out-of-line definitions for SilentFerret. See silent_ferret.h for the
// API and the prepaid / wire-free / rolling-base rationale.

#include "emp-ot/ot_extension/ferret/silent_ferret.h"
#include "emp-ot/common/lpn.h"
#include <algorithm>
#include <cassert>
#include <thread>
#include <vector>

namespace emp {

// Per-tree cGGM correction/eval scratch (tree_depth blocks). Stack-allocated
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
	// Deterministic LPN PRG blocks consumed per chunk; tree with global
	// counter G folds the stream at G * bpc_ (see produce_trees_).
	bpc_ = lpn_->blocks_per_chunk(chunk_size());
	lpn_key_       = zero_block;
	cggm_seed_key_ = zero_block;
}

SilentFerret::~SilentFerret() = default;

int64_t SilentFerret::round_capacity() const {
	return param.t - param.refill_trees;
}
int64_t SilentFerret::cots_per_round() const {
	return round_capacity() * chunk_size();
}
int64_t SilentFerret::prepared_capacity() const {
	return n_rounds_ * cots_per_round();
}

// No-arg begin: a single prepaid round (K = 1). Rollover past it is live.
void SilentFerret::begin() { begin_batch_(cots_per_round()); }

void SilentFerret::begin(int64_t n_ots) { begin_batch_(n_ots); }

// Prepay K = ceil(n_ots / cots_per_round()) rounds: emit every round's
// correction traffic and run every malicious check here, storing only the
// receiver's corrections (the sender re-derives its seeds). The base rolls
// forward as in the normal path; we keep a pristine base0 so the consume
// roll can restart from round 0.
void SilentFerret::begin_batch_(int64_t n_ots) {
	enter_session_();

	// Bootstrap (once) writes round-0's base COTs into carry_next_; swap so
	// carry_curr_ holds them. On a re-prepay (setup_done) carry_curr_ already
	// holds this batch's round-0 base (left by the previous end()).
	const bool need_swap = !setup_done;
	bootstrap_();
	if (need_swap) std::swap(carry_curr_, carry_next_);

	if (n_threads_ > 1 && !pool_)
		pool_ = std::make_unique<ThreadPool>((size_t)n_threads_);

	// Sender's cGGM-root key = the gadget's own per-tree PRG key. Ferret's
	// run_next_tree pulls tree g's seed as gadget-prg block g; deriving seed(g)
	// = PRG(this key) seek'd to g reproduces exactly that, so a no-arg
	// SilentFerret is byte-for-byte wire-identical to Ferret (verified by
	// trace_equiv). SilentFerret never advances gadget_send_->prg itself (it uses
	// prepare_all/produce_tree, not run_next_tree), so the key is stable for the
	// instance lifetime → same (round,tree) re-derives the same seed at prepay
	// and at consume.
	if (is_ot_sender() && !cggm_seed_key_set_) {
		cggm_seed_key_ = gadget_send_->prg.seed();
		cggm_seed_key_set_ = true;
	}

	const int64_t cpr = cots_per_round();
	int64_t K = (n_ots <= 0) ? 1 : (n_ots + cpr - 1) / cpr;
	n_rounds_       = K;
	batch_n_ots_    = (n_ots <= 0) ? cpr : n_ots;
	abs_round_base_ = abs_round_;

	// Pristine round-0 base for the consume restart (saved before any check
	// mutates carry_curr_'s consistency-check region).
	base0_.resize(carry_curr_.size());
	std::copy(carry_curr_.begin(), carry_curr_.end(), base0_.begin());

	if (!is_ot_sender())
		c_rounds_.resize((size_t)K * param.t * param.tree_depth);

	std::vector<block> seed_scratch;
	if (is_ot_sender()) seed_scratch.resize(param.t);

	// Batch-wide chi-check accumulators (one F(2^128) scalar each). Every round's
	// VW (and, receiver, chi_alpha = phi) is folded in as the round is produced,
	// so the whole K-round check needs O(1) state, not the per-leaf vectors.
	acc_vw_  = zero_block;
	acc_phi_ = zero_block;

	const block *base = nullptr;  // cGGM-correction region of carry_curr_
	for (int64_t r = 0; r < K; ++r) {
		const uint64_t abs = abs_round_base_ + (uint64_t)r;
		// Round-begin: reset the gadget's VW and (once) seed the LPN PRG.
		inner_run_begin_();
		if (!lpn_key_set_) { lpn_key_ = lpn_->prg_key(); lpn_key_set_ = true; }

		base = carry_curr_.data() + (kConsistCheckCotNum + param.k);
		if (is_ot_sender()) {
			PRG sp(&cggm_seed_key_);
			sp.seek(abs * (uint64_t)param.t);
			sp.random_block(seed_scratch.data(), param.t);
			gadget_send_->prepare_all(pool_.get(), batch_, base,
			                          seed_scratch.data());
		} else {
			block *c_out =
			    c_rounds_.data() + (size_t)r * param.t * param.tree_depth;
			gadget_recv_->prepare_all(pool_.get(), batch_, base, c_out);
		}

		// Fold this round's chi-check into the batch accumulators — no I/O. The
		// single batched check (Ferret App. C, m = K*t) runs once after the loop.
		if (is_ot_sender()) gadget_send_->fold_round_check(acc_vw_);
		else                gadget_recv_->fold_round_check(acc_vw_, acc_phi_);
		roll_base_(abs);    // carry_curr_ <- base_{r+1} (wire-free)
	}

	// One malicious check over the whole prepay, masked by round-0's 128 consist-
	// check COTs (G2: pristine base0_, finalize once). The FS transcript stayed
	// append-only in (round,tree) order across the loop, so each round's chi was
	// sampled post-commitment (G1). No-op when semi-honest.
	if (is_ot_sender())
		gadget_send_->finalize_batched_packed_sender(acc_vw_, base0_.data());
	else
		gadget_recv_->finalize_batched_packed_receiver(
		    acc_vw_, acc_phi_, base0_.data());

	// All traffic shipped. Restore round-0's base and position the consumer
	// at round 0; consume re-rolls the base wire-free from here.
	std::copy(base0_.begin(), base0_.end(), carry_curr_.begin());
	consume_round_ = 0;
	local_tree_    = 0;
}

void SilentFerret::end() {
	// Roll any unconsumed prepaid rounds forward to base_K so a following
	// begin() continues the base chain (and the absolute counter) without
	// re-shipping — counter reuse would repeat chi/LPN streams.
	for (int64_t r = consume_round_; r < n_rounds_; ++r)
		roll_base_(abs_round_base_ + (uint64_t)r);
	abs_round_ = abs_round_base_ + (uint64_t)n_rounds_;
	exit_session_();
}

void SilentFerret::next(block *out) {
	assert_in_session_();
	ensure_tree_available_();
	process_one_tree_(reinterpret_cast<AuthValueFerret *>(out));
}

void SilentFerret::next_chunks_parallel(block *out, int64_t n_chunks,
                                        int n_threads) {
	assert_in_session_();
	if (n_chunks <= 0) return;
	const int T = (n_threads < 0) ? n_threads_ : n_threads;
	if (T <= 1) {
		const int64_t chunk = chunk_size();
		for (int64_t i = 0; i < n_chunks; ++i)
			next(out + i * chunk);
		return;
	}

	const int64_t chunk = chunk_size();
	int64_t done = 0;
	// The online thread count is caller-selected and may differ from the
	// begin-time pool size, so this path uses short-lived workers per slice.
	// The intended bulk draws split whole chunk ranges, which keeps that setup
	// cost bounded by useful work.
	std::vector<std::thread> ths;
	ths.reserve((size_t)T);
	while (done < n_chunks) {
		ensure_tree_available_();
		const int64_t avail = round_capacity() - local_tree_;
		const int64_t take = std::min<int64_t>(avail, n_chunks - done);
		const int64_t base_tree = local_tree_;

		ths.clear();
		const int64_t per = (take + T - 1) / T;
		for (int t = 0; t < T; ++t) {
			const int64_t tree_begin = base_tree + t * per;
			if (tree_begin >= base_tree + take) break;
			const int64_t count =
			    std::min<int64_t>(per, base_tree + take - tree_begin);
			block *dst = out + (done + (tree_begin - base_tree)) * chunk;
			ths.emplace_back([this, dst, tree_begin, count]() {
				produce_range(dst, tree_begin, count);
			});
		}
		for (auto& th : ths) th.join();

		local_tree_ += take;
		done += take;
	}
}

void SilentFerret::ensure_tree_available_() {
	if (local_tree_ != round_capacity()) return;
	if (consume_round_ + 1 < n_rounds_) {
		// Wire-free roll into the next prepaid round.
		roll_base_(abs_round_base_ + (uint64_t)consume_round_);
		consume_round_++;
		local_tree_ = 0;
	} else {
		// Prepaid budget exhausted: ship the next batch (live comm).
		end();
		begin(batch_n_ots_);
	}
}

// Produce the single tree at the cursor (no rollover — next() handles that).
void SilentFerret::process_one_tree_(AuthValueFerret *out) {
	produce_trees_(reinterpret_cast<block *>(out),
	               abs_round_base_ + (uint64_t)consume_round_, local_tree_, 1,
	               carry_curr_.data());
	local_tree_++;
}

void SilentFerret::produce_range(block *out, int64_t tree_begin,
                                 int64_t n_trees) const {
	assert(tree_begin >= 0 && n_trees >= 0 &&
	       tree_begin + n_trees <= round_capacity() &&
	       "produce_range out of current-round bounds");
	produce_trees_(out, abs_round_base_ + (uint64_t)consume_round_, tree_begin,
	               n_trees, carry_curr_.data());
}

void SilentFerret::roll_base_(uint64_t abs_round) {
	// The round's refill trees [round_capacity, t) produce the next round's
	// M base COTs; write them into carry_next_ and swap.
	produce_trees_(carry_next_.data(), abs_round, round_capacity(),
	               param.refill_trees, carry_curr_.data());
	std::swap(carry_curr_, carry_next_);
}

void SilentFerret::produce_trees_(block *out, uint64_t abs_round,
                                  int64_t local_begin, int64_t n,
                                  const block *base_for_round) const {
	const int64_t chunk    = chunk_size();
	const int64_t cggm_off = kConsistCheckCotNum + param.k;
	const AuthValueFerret *pre = reinterpret_cast<const AuthValueFerret *>(
	    base_for_round + kConsistCheckCotNum);

	// One global tree counter G = abs_round*t + local addresses both streams;
	// the range is contiguous in G, so one forked PRG advances naturally
	// through it (one AES key-schedule amortized over the range).
	const uint64_t G0 =
	    abs_round * (uint64_t)param.t + (uint64_t)local_begin;
	PRG lpn_prg(&lpn_key_);
	lpn_prg.seek(G0 * bpc_);
	// Receiver corrections are indexed by batch-local round.
	const int64_t r = (int64_t)(abs_round - abs_round_base_);

	block scratch[kMaxTreeDepth];  // k0 (sender) / kr (receiver) sink
	PRG seed_prg(&cggm_seed_key_); // sender only; zero key (unused) on receiver
	if (is_ot_sender()) seed_prg.seek(G0);

	for (int64_t m = 0; m < n; ++m) {
		const int64_t i = local_begin + m;
		AuthValueFerret *o =
		    reinterpret_cast<AuthValueFerret *>(out + m * chunk);
		if (is_ot_sender()) {
			block seed;
			seed_prg.random_block(&seed, 1);
			gadget_send_->produce_tree(o, seed, scratch);
		} else {
			const block *base_j =
			    base_for_round + cggm_off + i * param.tree_depth;
			const block *c_i =
			    c_rounds_.data() + (size_t)(r * param.t + i) * param.tree_depth;
			gadget_recv_->produce_tree(o, base_j, c_i, scratch);
		}
		lpn_->compute_slice(lpn_prg, o, pre, chunk);  // advances by bpc_
	}
}

}  // namespace emp
