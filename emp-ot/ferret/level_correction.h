#ifndef EMP_OT_LEVEL_CORRECTION_H__
#define EMP_OT_LEVEL_CORRECTION_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/preot.h"

namespace emp {

// Per-batch level-correction strategy used by SPCOT to ship the
// per-level XOR-sums K0[i] / K1[i] (sender) and recover the per-level
// punctured-side values K_recv[i] (receiver) over the wire.
//
// Today this is implemented over OTPre (pair-OT bridge): per level
// the sender sends two κ-bit blocks, the receiver picks one with its
// choice bit. Half-Tree (cGGM) will swap in a strategy that sends a
// single κ-bit correction per level by exploiting the leveled
// correlation against the global Δ. The interface is intentionally
// shaped so that swap is local: SPCOT and MpcotReg call only the
// virtuals below; nothing else changes.
//
// Cursor / lifecycle (per mpcot batch of `tree_n` trees):
//   prepare_batch();
//   for each tree i in [0, tree_n):
//     sender:   advance_one_tree();           // pre-send setup
//     receiver: drain_choice_bits_one_tree(b, n);
//   ... then per tree, in any order (potentially in parallel):
//     sender:   send_tree(i, io, K0, K1, n, secret_sum_f2)
//     receiver: recv_tree(i, io, K_recv, b, n, &secret_sum_f2)

class LevelCorrectionSender {
public:
	virtual ~LevelCorrectionSender() = default;
	// Cursor reset before the batch; per-tree pre-send advance.
	virtual void prepare_batch() = 0;
	virtual void advance_one_tree() = 0;
	// Send n level corrections + the trailing secret_sum_f2 block.
	// K0[i] / K1[i] are the two XOR-sums at level i+1 of the GGM
	// tree (i ∈ [0, n)). n = depth - 1 today.
	virtual void send_tree(int tree_index, IOChannel* io,
	                       const block* K0, const block* K1, int n,
	                       block secret_sum_f2) = 0;
};

class LevelCorrectionRecver {
public:
	virtual ~LevelCorrectionRecver() = default;
	virtual void prepare_batch() = 0;
	// Drain n choice bits for the next tree into b_out (the receiver's
	// per-level "NOT alpha_i" array). Advances the cursor by n.
	virtual void drain_choice_bits_one_tree(bool* b_out, int n) = 0;
	// Receive n level corrections + secret_sum_f2; populate K_recv[i]
	// with K^{ᾱ_i}_{i+1} for i ∈ [0, n).
	virtual void recv_tree(int tree_index, IOChannel* io,
	                       block* K_recv, const bool* b, int n,
	                       block* secret_sum_f2_out) = 0;
};

// ---------------------------------------------------------------------
// Stage-1 implementations: thin wrappers around OTPre. Byte-trace
// identical to the pre-strategy code path.

class OTPreCorrectionSender : public LevelCorrectionSender {
	OTPre* ot_;
public:
	explicit OTPreCorrectionSender(OTPre* ot) : ot_(ot) {}
	void prepare_batch() override { ot_->reset(); }
	void advance_one_tree() override { ot_->choices_sender(); }
	void send_tree(int tree_index, IOChannel* io,
	               const block* K0, const block* K1, int n,
	               block secret_sum_f2) override {
		ot_->send(K0, K1, n, io, tree_index);
		io->send_data(&secret_sum_f2, sizeof(block));
	}
};

class OTPreCorrectionRecver : public LevelCorrectionRecver {
	OTPre* ot_;
public:
	explicit OTPreCorrectionRecver(OTPre* ot) : ot_(ot) {}
	void prepare_batch() override { ot_->reset(); }
	void drain_choice_bits_one_tree(bool* b_out, int /*n*/) override {
		ot_->choices_recver(b_out);
	}
	void recv_tree(int tree_index, IOChannel* io,
	               block* K_recv, const bool* b, int n,
	               block* secret_sum_f2_out) override {
		ot_->recv(K_recv, b, n, io, tree_index);
		io->recv_data(secret_sum_f2_out, sizeof(block));
	}
};

}  // namespace emp
#endif  // EMP_OT_LEVEL_CORRECTION_H__
