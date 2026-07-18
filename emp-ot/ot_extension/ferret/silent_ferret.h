#ifndef EMP_SILENT_FERRET_H_
#define EMP_SILENT_FERRET_H_
#include "emp-ot/ot_extension/ferret/ferret.h"
#include <emp-tool/emp-tool.h>   // ThreadPool
#include <memory>

namespace emp {

/*
 * SilentFerret — a Ferret RCOT whose consume path does NO wire I/O.
 *
 * begin() concentrates all MPCOT correction traffic and the malicious
 * consistency-check round-trip up front; next() / produce_range() then
 * re-derive each tree's leaves locally and run the LPN amplification with
 * the wire idle. Malicious security is preserved: each tree's chi-fold is
 * folded and the packed check completed during begin(), before any
 * user-visible output, with the exact same FS chi seeds as Ferret (the
 * socket sends stay in tree order).
 *
 * Prepaid multi-round (begin(n_ots)):
 *   Ferret is a bootstrapping construction — each round's base COTs are the
 *   previous round's refill output, so a round's traffic cannot move earlier
 *   than the round before it is *produced*. But producing a round (cGGM eval
 *   + LPN) is wire-free, so begin(n_ots) drives K = ceil(n_ots / cots_per_
 *   round()) round-cycles back-to-back, emitting every round's corrections
 *   and check during begin(). The consumer then draws up to prepared_
 *   capacity() COTs across all K rounds without touching the wire.
 *
 *   The K-round wire transcript is bit-identical to K serial rollovers, so
 *   malicious security is unchanged.
 *
 * Memory-light: nothing the wire already carried is re-stored. The next
 * round's base is re-derived from the previous one on the fly (a rolling
 * ping-pong base, exactly as the normal path), so the only per-round
 * persistent state is what cannot be reproduced locally — the receiver's
 * received corrections (~t * tree_depth blocks / round). The sender keeps
 * nothing per round: its cGGM roots are re-derived from a secret key via a
 * seek'd PRG. Resident base buffers stay at three (one retained batch
 * boundary + two rolling), flat in K.
 *
 * No-arg begin() is the K = 1 special case: one round prepaid, consumed
 * wire-free, with a live (communicating) rollover when the round's budget is
 * exhausted — behaviorally identical to plain Ferret's per-round streaming.
 *
 * Subclasses Ferret and reuses its bootstrap / LPN / gadget / round-end
 * check; overrides the lifecycle to add the prepay loop and the rolling
 * wire-free consume.
 */
class SilentFerret : public Ferret {
public:
	// `n_threads` sizes the begin()-time expansion pool (<=1 → serial,
	// no pool). Other args mirror Ferret.
	SilentFerret(int party, IOChannel *io, bool malicious = true,
	             PrimalLPNParameter param = tuning::ferret_b13,
	             std::unique_ptr<OT> base_ot = nullptr,
	             int n_threads = 1);
	~SilentFerret() override;

	// Unlike Ferret (sender send-dominant per tree), the consume path moves
	// no bytes for either role — all traffic is in begin().
	static constexpr bool kSenderSendsOnExtend = false;

	// Single-round begin (== begin(cots_per_round()), K = 1).
	void begin() override;

	// Prepaid begin: prepare enough rounds that up to `n_ots` COTs can be
	// drawn with NO wire I/O. All correction traffic and all K malicious
	// checks happen here. K = ceil(n_ots / cots_per_round()). After this,
	// produce up to prepared_capacity() COTs via next() / next_n() / run()
	// (sequential, auto-rolls rounds wire-free), next_chunks_parallel()
	// (cursor-ordered, auto-rolls, internally threaded), or produce_range()
	// (one round at a time, concurrent within the round); then end().
	void begin(int64_t n_ots);

	void next(block *out) override;
	void end() override;

	// Cursor-ordered bulk draw with the same auto-rollover semantics as
	// next(). Produces `n_chunks * chunk_size()` COTs into `out`, splitting
	// each current-round slice across up to `n_threads` caller-visible worker
	// threads. Pass n_threads < 0 to use the constructor's n_threads. The call
	// itself mutates the stream cursor; do not call it concurrently with
	// next()/next_n()/produce_range() on the same instance.
	//
	// This intentionally works in whole chunks only. Buffering sub-chunk tails
	// remains the base next_n() contract; consumers that want threaded filling
	// should size their COT buffer to a chunk multiple.
	void next_chunks_parallel(block *out, int64_t n_chunks, int n_threads = -1);

	// User-visible COTs per round and across the whole prepaid batch.
	int64_t cots_per_round() const;        // round_capacity() * chunk_size()
	int64_t prepared_capacity() const;     // n_rounds_ * cots_per_round()

	// Number of user-addressable trees per round (call after begin()).
	int64_t round_capacity() const;

	// Thread-safe, index-addressed batch produce within the *current* round
	// (the one next() is positioned in; round 0 right after begin()). Writes
	// trees [tree_begin, tree_begin + n_trees) of the current round into
	// `out` (n_trees * chunk_size() COTs). No wire I/O and no shared mutable
	// state: the consumer may call it concurrently from its own threads with
	// disjoint [tree_begin, n_trees) ranges and disjoint `out` buffers.
	// Output is identical regardless of order or thread, and bit-identical
	// to the serial next() path.
	//
	// Within one round use EITHER produce_range OR the cursor (next/run/
	// next_n), not both. To span rounds, drive the cursor (which rolls the
	// base wire-free) — produce_range stays within the current round because
	// the rolling base is single-round state.
	void produce_range(block *out, int64_t tree_begin, int64_t n_trees) const;

protected:
	void process_one_tree_(AuthValueFerret *out) override;

private:
	int n_threads_ = 1;
	int batch_ = 1;                    // trees per parallel wave at begin()
	std::unique_ptr<ThreadPool> pool_; // null when n_threads_ <= 1

	// ---- Deterministic, index-addressed re-derivation -----------------
	// Tree counter G = abs_round * param.t + local_tree is the single key
	// for both re-derivation streams, so any tree is reproducible from its
	// (round, local) index alone — order-independent and identical between
	// the begin()-time prepay and the consume-time re-derive.
	//   LPN:  fold the stream at counter G * bpc_ (PRG forked from lpn_key_).
	//   seed: sender's cGGM root at counter G (PRG forked from cggm_seed_key_).
	uint64_t bpc_ = 0;                 // LPN PRG blocks per chunk
	block    lpn_key_;                 // captured after the one-shot LPN reseed
	bool     lpn_key_set_ = false;
	block    cggm_seed_key_;           // sender's secret cGGM-root key
	bool     cggm_seed_key_set_ = false;

	// ---- Prepaid-batch state ------------------------------------------
	int64_t  n_rounds_ = 1;            // K: rounds prepaid by the last begin()
	int64_t  batch_n_ots_ = 0;         // re-prepaid on live rollover past K
	uint64_t abs_round_ = 0;           // running absolute round index
	uint64_t abs_round_base_ = 0;      // abs index of this batch's round 0
	int64_t  consume_round_ = 0;       // batch-local round next() is in [0,K)
	int64_t  local_tree_ = 0;          // user tree within consume_round_

	// Receiver only: the prepaid corrections, K * t * tree_depth blocks.
	// (Sender re-derives seeds, so it keeps nothing per round.)
	std::vector<block> c_rounds_;

	// Batch-boundary scratch: holds pristine base_0 during prepay/check, then
	// retains the already-computed base_K while the consumer rolls from base_0.
	// Its [0,128) base_0 region is the single mask for the batched check.
	BlockVec base0_;

	// Batched malicious-check accumulators (Ferret App. C over m = K*t trees):
	// the running XOR of every round's VW (both roles) and chi_alpha = phi
	// (receiver). One F(2^128) scalar each — the whole K-round check is folded
	// incrementally, so no per-tree/per-leaf state is retained. Set in begin().
	block acc_vw_  = zero_block;
	block acc_phi_ = zero_block;

	// begin()/end() core (the K-round prepay and the batch teardown).
	void begin_batch_(int64_t n_ots);

	// If the cursor has consumed the current round, roll to the next prepaid
	// round or live-reprepay exactly as next() does.
	void ensure_tree_available_();

	// Produce `n` consecutive trees [local_begin, local_begin + n) of
	// absolute round `abs_round` into `out` (out + m*chunk = tree
	// local_begin+m). Reads `base_for_round` (the round's M base COTs) and,
	// receiver-side, c_rounds_[(abs_round - abs_round_base_) ...]; sender-side
	// re-derives seeds from cggm_seed_key_. No wire I/O; thread-safe / const.
	void produce_trees_(block *out, uint64_t abs_round, int64_t local_begin,
	                    int64_t n, const block *base_for_round) const;

	// Roll the rolling base from `abs_round`'s refill into carry_next_, then
	// swap so carry_curr_ becomes the next round's base. Wire-free.
	void roll_base_(uint64_t abs_round);
};

}  // namespace emp
#endif  // EMP_SILENT_FERRET_H_
