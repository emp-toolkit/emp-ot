#ifndef EMP_SILENT_FERRET_H_
#define EMP_SILENT_FERRET_H_
#include "emp-ot/ot_extension/ferret/ferret.h"
#include <emp-tool/emp-tool.h>   // ThreadPool
#include <memory>

namespace emp {

/*
 * SilentFerret — a Ferret RCOT whose per-chunk next() does NO wire I/O.
 *
 * All MPCOT correction traffic is concentrated in begin() (one batched
 * flush), where the round's trees are expanded in parallel — a batch at a
 * time via a thread pool — so next() / refill only re-derive each tree's
 * leaves locally and run the LPN amplification. Malicious security is
 * preserved: the per-tree chi-fold contributions are folded during
 * begin() (using the exact same per-tree FS chi seeds as Ferret, since
 * the socket sends stay in tree order), and the single consistency-check
 * round-trip is deferred to end(). The wire therefore sees traffic at
 * exactly two points — begin() (corrections) and end() (the check) —
 * never inside next().
 *
 * Memory-light: the sender keeps per-tree cGGM root seeds, the receiver
 * the corrections; leaves are re-expanded at consume rather than stored,
 * so peak begin() scratch is bounded by the batch size, not the whole
 * round.
 *
 * Subclasses Ferret and reuses its bootstrap / ping-pong buffers / LPN /
 * round-end check; overrides only begin() (append the up-front prepare)
 * and process_one_tree_ (the wire-free per-tree body).
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

	// Unlike Ferret (sender send-dominant per tree), next() moves no bytes
	// for either role — all traffic is in begin()/end().
	static constexpr bool kSenderSendsOnExtend = false;

	void begin() override;
	void end() override;

	// Number of user-addressable trees in the current round (call after
	// begin()). produce_range / the cursor API may draw up to this many
	// trees before the round must be closed with end().
	int64_t round_capacity() const;

	// Thread-safe, index-addressed batch produce. Writes trees
	// [tree_begin, tree_begin + n_trees) of the current round into `out`
	// (n_trees * chunk_size() COTs). No wire I/O and no shared mutable
	// state: the *consumer* drives the threading — it may call this
	// concurrently from its own threads with disjoint [tree_begin, n_trees)
	// ranges and disjoint `out` buffers (and interleave its own work while
	// the data is cache-hot). Output is identical regardless of order or
	// thread, and bit-identical to the serial next()/run() path.
	//
	// Valid between begin() and end(); requires tree_begin + n_trees <=
	// round_capacity(). Within one session use EITHER produce_range OR the
	// cursor API (next/run/next_n), not both (they don't share the cursor).
	void produce_range(block *out, int64_t tree_begin, int64_t n_trees) const;

protected:
	void process_one_tree_(AuthValueFerret *out) override;

private:
	int n_threads_ = 1;
	int batch_ = 1;                    // trees per parallel wave at begin()
	std::unique_ptr<ThreadPool> pool_; // null when n_threads_ <= 1

	// LPN slicing without the shared lpn_->prg_ cursor: tree j of the
	// current round folds the LPN stream at counter round_base_ + j*bpc_,
	// using a PRG forked from lpn_key_. Lets any tree be produced from its
	// index alone (order-independent, thread-safe). round_base_ advances by
	// param.t * bpc_ each round (covers user + refill trees).
	uint64_t round_base_ = 0;
	uint64_t bpc_ = 0;
	block    lpn_key_;

	// Core index-addressed produce shared by produce_range (user trees),
	// process_one_tree_ (cursor, one tree) and end() (refill tail). Writes
	// trees [tree_begin, tree_begin+n_trees) into `out`. No capacity assert
	// (refill uses indices >= round_capacity()); thread-safe / const.
	void produce_range_(block *out, int64_t tree_begin, int64_t n_trees) const;
};

}  // namespace emp
#endif  // EMP_SILENT_FERRET_H_
