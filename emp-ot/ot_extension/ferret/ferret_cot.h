#ifndef EMP_FERRET_COT_H_
#define EMP_FERRET_COT_H_
#include "emp-ot/ot.h"
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
class FerretCOT: public RandomCOT {
public:
	PrimalLPNParameter param;

	// `base_ot` is forwarded to the internal SoftSpokenOT<8> bootstrap.
	// Default (nullptr) → SoftSpoken constructs its own OTPVW base.
	FerretCOT(int party, IOChannel *io, bool malicious = false, bool run_setup = true,
			PrimalLPNParameter param = ferret_b13,
			std::unique_ptr<OT> base_ot = nullptr);

	~FerretCOT();

	// ALICE supplies Δ; BOB has no Δ.
	void setup(block Deltain);
	void setup();

	// Streaming RCOT API. Each rcot_*_next call produces exactly
	// `chunk_ots()` = leave_n = 2^log_bin_sz RCOT outputs (one
	// cGGM tree's leaves).
	//
	// Lifecycle:
	//   begin()  — swaps in fresh M base COTs (from the previous
	//              end's refill, or from setup's SoftSpoken
	//              bootstrap on the first call); resets per-round
	//              chi-fold state and exchanges a fresh LPN seed.
	//   next()   — produces one cGGM tree's leaves into `out`. If
	//              the round is full (tree_n - refill_trees trees
	//              already produced this round), automatically
	//              triggers end() then begin() before producing the
	//              user's tree — i.e. transparent rollover.
	//   end()    — runs refill_trees more trees writing into the
	//              next-round buffer, then runs the malicious
	//              chi-fold consistency check on this round's
	//              accumulated VW (covering both user-visible and
	//              refill trees). Always leaves next_round's M
	//              fresh and ready for the next begin().
	int64_t chunk_ots() const;          // = leave_n
	void rcot_send_begin();
	void rcot_send_next(block* out);    // writes chunk_ots() blocks
	void rcot_send_end();
	void rcot_recv_begin();
	void rcot_recv_next(block* out);    // writes chunk_ots() blocks
	void rcot_recv_end();

	// Standard one-shot interface (RandomCOT contract). Wrappers
	// around the streaming API: begin → loop _next → end, with a
	// stack-local kChunkOTs buffer for the trailing partial tree
	// when num isn't a multiple of leave_n. RandomCOT::send_cot /
	// recv_cot build the chosen-message correction layer on top.
	void rcot_send(block* data, int64_t num) override;
	void rcot_recv(block* data, int64_t num) override;

private:
	int party;
	int64_t M;            // base COTs per round = k + tree_n*(h-1) + 128
	int64_t refill_trees; // = ceil(M / leave_n); last refill_trees of each
	                      // round refill the next-round ot_pre_data buffer.
	int tree_idx_;        // current tree index within the round, 0..tree_n-1
	bool is_malicious;
	bool extend_initialized;

	// Two ping-pong base buffers, each refill_trees * leave_n blocks.
	// `curr_` holds the round's M base COTs (cGGM corrections, LPN
	// base, chi-check 128). `next_` is where the round's last
	// refill_trees trees write their output (= next round's base).
	// Swapped at every round boundary.
	BlockVec ot_pre_data_curr_;
	BlockVec ot_pre_data_next_;

	// Leftover buffer for the standard one-shot rcot_send / rcot_recv
	// wrappers. When num isn't a multiple of chunk_ots(), the tail
	// _next call lands here; subsequent rcot_send/recv calls drain
	// the unused suffix before producing more chunks. Keeps small-num
	// repeated calls cheap (no fresh tree per call).
	BlockVec leftover_;
	int      leftover_pos_   = 0;
	int      leftover_count_ = 0;

	// Exactly one of these is populated, depending on `party`.
	std::unique_ptr<MPCOT_Sender>   mpcot_sender;
	std::unique_ptr<MPCOT_Receiver> mpcot_receiver;
	std::unique_ptr<LpnF2<10>> lpn_f2;
	std::unique_ptr<OT> base_ot_;  // forwarded into SoftSpoken on first cold-start bootstrap
};

}  // namespace emp
#endif  // EMP_FERRET_COT_H_
