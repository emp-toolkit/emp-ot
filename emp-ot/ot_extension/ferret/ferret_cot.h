#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/ot_extension/ot_extension.h"
#include "emp-ot/ot_extension/ferret/constants.h"
#include <memory>

// Forward-declare ferret internals so the public header doesn't pull
// in the cGGM transitive closure.
// The .cpp #includes the real headers; std::unique_ptr<T> works with
// forward-declared T as long as the dtor is out-of-line (it is).

namespace emp {
class MPCOT_Sender;
class MPCOT_Receiver;
template <int d> class LpnF2;
}  // namespace emp

namespace emp {

/*
 * Ferret COT binary version
 * [REF] Implementation of "Ferret: Fast Extension for coRRElated oT with small communication"
 * https://eprint.iacr.org/2020/924.pdf
 *
 */
class FerretCOT: public OTExtension {
public:
	PrimalLPNParameter param;

	// `base_ot` is forwarded to the internal SoftSpokenOT<8> bootstrap.
	// Default (nullptr) → SoftSpoken constructs its own OTPVW base.
	FerretCOT(int party, IOChannel *io, bool malicious = true,
			PrimalLPNParameter param = ferret_b13,
			std::unique_ptr<OT> base_ot = nullptr);

	~FerretCOT();

	// Replace the ctor-sampled Δ with one supplied by an outer protocol.
	// Sender-only; must fire before the streaming bootstrap consumes Δ
	// (i.e. before the first rcot_*_begin call).
	// delta_bool[0] must be true (the COT LSB convention).
	void set_delta(const bool *delta_bool);

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
	// SoftSpokenOT<8>. Idempotent — early-out after first run. Called
	// from both do_rcot_*_begin paths on first entry.
	void bootstrap_base_cots_();

	int party;
	int tree_idx_;        // current tree index within the round, 0..param.t-1
	bool is_malicious;
	bool bootstrap_done_;

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
	std::unique_ptr<LpnF2<10>> lpn_f2;
	std::unique_ptr<OT> base_ot_;  // forwarded into SoftSpoken on first cold-start bootstrap
};

}  // namespace emp
#endif  // EMP_FERRET_COT_H_
