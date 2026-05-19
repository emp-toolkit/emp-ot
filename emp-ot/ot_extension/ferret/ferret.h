#ifndef EMP_FERRET_H_
#define EMP_FERRET_H_
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/tuning.h"
#include <climits>
#include <memory>

// Forward-declare ferret internals so the public header doesn't pull
// in the cGGM transitive closure.
// The .cpp #includes the real headers; std::unique_ptr<T> works with
// forward-declared T as long as the dtor is out-of-line (it is).

namespace emp {

// Default base OT for Ferret. Forwarded into the inner SoftSpokenOT<8>
// bootstrap (or the inner ferret_b10 in the tiered-bootstrap path).
// Change here to swap; OTExtension's contract just needs any
// malicious-secure (when malicious=true) OT.
using FerretBaseOT = OTCSW;

class MPCOT_Sender;
class MPCOT_Receiver;
template <typename Ops, int d> class Lpn;

// Ops adapter for the unified Lpn template, in Ferret's degenerate
// F_2 case: the "AuthValue" is a single block (raw RCOT carrier;
// no val/mac structure). Folding is plain XOR with no carry concern,
// so partial/final reduce are no-ops and kLpnSafeAddsPerReduce can
// be infinite (one batch).
struct FerretF2LpnOps {
  using AuthValue = block;
  static constexpr int kLpnSafeAddsPerReduce =
      std::numeric_limits<int>::max();
  static inline void auth_add_into(block &acc, const block &x) {
    acc = acc ^ x;
  }
  static inline void auth_partial_reduce(block &) {}
  static inline void auth_final_reduce  (block &) {}
};

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
class Ferret: public OTExtension {
public:
	PrimalLPNParameter param;

	// `base_ot` is forwarded to the internal SoftSpokenOT<8> bootstrap.
	// Default (nullptr) → the base allocates an OTCSW.
	Ferret(int party, IOChannel *io, bool malicious = true,
			PrimalLPNParameter param = tuning::ferret_b13,
			std::unique_ptr<OT> base_ot = nullptr);

	~Ferret();

	// Override the base set_delta to also propagate Δ into the
	// sender-side mpcot state. Pre-bootstrap only.
	void set_delta(const bool *bits) override;

	// OTExtension contract. Each do_rcot_*_next call produces exactly
	// `chunk_ots()` = 2^tree_depth RCOT outputs (one cGGM tree's
	// leaves).
	//
	// Lifecycle:
	//   begin()  — swaps in fresh M base COTs (from the previous
	//              end's refill, or from setup's SoftSpoken
	//              bootstrap on the first call); resets per-round
	//              chi-fold state and exchanges a fresh LPN seed.
	//   next()   — produces one cGGM tree's leaves into `out`. If
	//              the round is full (param.t - refill_trees trees
	//              already produced this round), automatically
	//              triggers end() then begin() before producing the
	//              user's tree — i.e. transparent rollover.
	//   end()    — runs refill_trees more trees writing into the
	//              next-round buffer, then runs the malicious
	//              chi-fold consistency check on this round's
	//              accumulated VW (covering both user-visible and
	//              refill trees). Always leaves next_round's M
	//              fresh and ready for the next begin().
	int64_t chunk_ots() const override;          // = 2^tree_depth

protected:
	void do_rcot_send_begin() override;
	void do_rcot_send_next(block* out) override;
	void do_rcot_send_end() override;
	void do_rcot_recv_begin() override;
	void do_rcot_recv_next(block* out) override;
	void do_rcot_recv_end() override;

private:
	// Wire-touching bootstrap: builds the first round's M base COTs via
	// SoftSpokenOT<8>. Idempotent — early-out after first run via the
	// inherited `setup_done`. Called from both do_rcot_*_begin paths
	// on first entry.
	void bootstrap_base_cots_();

	int tree_idx_;          // current tree index within the round, 0..param.t-1
	bool lpn_seed_set_ = false;   // lpn_f2 has been seeded for this Ferret's lifetime

	// Two ping-pong base buffers, each refill_trees * leave_n blocks.
	// `curr_` holds the round's M base COTs (cGGM corrections, LPN
	// base, chi-check 128). `next_` is where the round's last
	// refill_trees trees write their output (= next round's base).
	// Swapped at every round boundary.
	BlockVec ot_pre_data_curr_;
	BlockVec ot_pre_data_next_;

	// Exactly one of these is populated, depending on `party`.
	std::unique_ptr<MPCOT_Sender>   mpcot_sender;
	std::unique_ptr<MPCOT_Receiver> mpcot_receiver;
	std::unique_ptr<Lpn<FerretF2LpnOps, 10>> lpn_f2;
};

}  // namespace emp
#endif  // EMP_FERRET_COT_H_
