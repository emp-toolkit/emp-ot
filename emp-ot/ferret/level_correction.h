#ifndef EMP_OT_LEVEL_CORRECTION_H__
#define EMP_OT_LEVEL_CORRECTION_H__
#include "emp-tool/emp-tool.h"

namespace emp {

// Per-batch level-correction strategy used by SPCOT to ship the
// per-level XOR-sums K^0_i (sender) and recover the per-level
// punctured-side values K^{ᾱ_i}_i (receiver) over the wire.
//
// Half-Tree (cGGM, ePrint 2022/1431 Fig 4) backs this with a single
// κ-bit correction per level c_i = K_{r_i} XOR K^0_i, derived
// directly from the precomputed base COTs (no OTPre indirection).
// The receiver derives K^{ᾱ_i}_i = M_{r_i} XOR c_i.
//
// Cursor / lifecycle (per mpcot batch of `tree_n` trees):
//   prepare_batch();
//   for each tree i in [0, tree_n):
//     sender:   advance_one_tree();           // pre-send setup
//     receiver: drain_choice_bits_one_tree(b, n);
//   ... then per tree, in any order (parallel):
//     sender:   send_tree(i, io, K0, n, secret_sum_f2)
//     receiver: recv_tree(i, io, K_recv, n, &secret_sum_f2)

class LevelCorrectionSender {
public:
	virtual ~LevelCorrectionSender() = default;
	virtual void prepare_batch() = 0;
	virtual void advance_one_tree() = 0;
	// Send n level corrections + the trailing secret_sum_f2 block.
	// K0[i] = the "left-side" XOR-sum at level i+1 of the cGGM tree,
	// for i ∈ [0, n).
	virtual void send_tree(int tree_index, IOChannel* io,
	                       const block* K0, int n,
	                       block secret_sum_f2) = 0;
};

class LevelCorrectionRecver {
public:
	virtual ~LevelCorrectionRecver() = default;
	virtual void prepare_batch() = 0;
	// Drain n choice bits for the next tree into b_out (the receiver's
	// per-level "NOT alpha_i" array, derived from the base COT's r_i).
	virtual void drain_choice_bits_one_tree(bool* b_out, int n) = 0;
	// Receive n level corrections + secret_sum_f2; populate K_recv[i]
	// with K^{ᾱ_{i+1}}_{i+1} for i ∈ [0, n).
	virtual void recv_tree(int tree_index, IOChannel* io,
	                       block* K_recv, int n,
	                       block* secret_sum_f2_out) = 0;
};

// ---------------------------------------------------------------------
// cGGM-based implementation. Holds a pointer into the FerretCOT
// pre_cot_data array (sender: K_{r_i}; receiver: M_{r_i}). The
// receiver's per-level r_i is the LSB of M_{r_i} (the standard
// LSB-of-output choice convention used throughout ferret).

class CGGMCorrectionSender : public LevelCorrectionSender {
	const block* base_;       // pre_cot_data, length cots_per_tree_*tree_n_
	int cots_per_tree_;
public:
	CGGMCorrectionSender(const block* base, int cots_per_tree)
		: base_(base), cots_per_tree_(cots_per_tree) {}
	void prepare_batch() override {}
	void advance_one_tree() override {}
	void send_tree(int tree_index, IOChannel* io,
	               const block* K0, int n,
	               block secret_sum_f2) override {
		// c_i = K_{r_i} XOR K0[i-1] for i = 1..n.
		std::vector<block> c(n);
		const block* K = base_ + tree_index * cots_per_tree_;
		for (int i = 0; i < n; ++i) c[i] = K[i] ^ K0[i];
		io->send_block(c.data(), n);
		io->send_data(&secret_sum_f2, sizeof(block));
	}
};

class CGGMCorrectionRecver : public LevelCorrectionRecver {
	const block* base_;       // pre_cot_data
	int cots_per_tree_;
public:
	CGGMCorrectionRecver(const block* base, int cots_per_tree)
		: base_(base), cots_per_tree_(cots_per_tree) {}
	void prepare_batch() override {}
	// Cursor across trees; each call advances by `n`.
	void drain_choice_bits_one_tree(bool* b_out, int n) override {
		// b_out[i] = NOT alpha_{i+1} = r_{i+1} = LSB(M_{r_{i+1}}).
		const block* M = base_ + cursor_;
		for (int i = 0; i < n; ++i) b_out[i] = getLSB(M[i]);
		cursor_ += n;
	}
	void recv_tree(int tree_index, IOChannel* io,
	               block* K_recv, int n,
	               block* secret_sum_f2_out) override {
		std::vector<block> c(n);
		io->recv_block(c.data(), n);
		io->recv_data(secret_sum_f2_out, sizeof(block));
		// K^{ᾱ_i}_i = M_{r_i} XOR c_i.
		const block* M = base_ + tree_index * cots_per_tree_;
		for (int i = 0; i < n; ++i) K_recv[i] = M[i] ^ c[i];
	}
private:
	int cursor_ = 0;
};

}  // namespace emp
#endif  // EMP_OT_LEVEL_CORRECTION_H__
