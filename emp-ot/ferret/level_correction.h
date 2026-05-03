#ifndef EMP_OT_LEVEL_CORRECTION_H__
#define EMP_OT_LEVEL_CORRECTION_H__
#include "emp-tool/emp-tool.h"
#include <vector>

namespace emp {

// Per-batch level-correction objects used by SPCOT to ship the
// per-level XOR-sums K^0_i (sender) and recover the per-level
// punctured-side values K^{ᾱ_i}_i (receiver) over the wire.
//
// Half-Tree (cGGM, ePrint 2022/1431 Fig 4): one κ-bit correction
// per level c_i = K_{r_i} XOR K^0_i, derived directly from the
// precomputed base COTs. Receiver derives K^{ᾱ_i}_i = M_{r_i} XOR c_i.
//
// Cursor / lifecycle (per mpcot batch of `tree_n` trees):
//   sender:   advance_one_tree()                              // per tree
//   receiver: drain_choice_bits_one_tree(b, n)                // per tree
//   then per tree, in any order (parallel):
//     sender:   send_tree(i, io, K0, n, secret_sum_f2)
//     receiver: recv_tree(i, io, K_recv, n, &secret_sum_f2)

class CGGMCorrectionSender {
	const block* base_;       // pre_cot_data, length cots_per_tree_*tree_n
	int cots_per_tree_;
public:
	CGGMCorrectionSender(const block* base, int cots_per_tree)
		: base_(base), cots_per_tree_(cots_per_tree) {}
	void advance_one_tree() {}  // sender has no per-tree cursor work
	void send_tree(int tree_index, IOChannel* io,
	               const block* K0, int n, block secret_sum_f2) {
		// c_i = K_{r_i} XOR K0[i-1] for i = 1..n.
		std::vector<block> c(n);
		const block* K = base_ + tree_index * cots_per_tree_;
		for (int i = 0; i < n; ++i) c[i] = K[i] ^ K0[i];
		io->send_block(c.data(), n);
		io->send_data(&secret_sum_f2, sizeof(block));
	}
};

class CGGMCorrectionRecver {
	const block* base_;       // pre_cot_data
	int cots_per_tree_;
	int cursor_ = 0;
public:
	CGGMCorrectionRecver(const block* base, int cots_per_tree)
		: base_(base), cots_per_tree_(cots_per_tree) {}
	// Cursor across trees; each call advances by `n`. b_out[i] =
	// NOT alpha_{i+1} = r_{i+1} = LSB(M_{r_{i+1}}).
	void drain_choice_bits_one_tree(bool* b_out, int n) {
		const block* M = base_ + cursor_;
		for (int i = 0; i < n; ++i) b_out[i] = getLSB(M[i]);
		cursor_ += n;
	}
	void recv_tree(int tree_index, IOChannel* io,
	               block* K_recv, int n, block* secret_sum_f2_out) {
		std::vector<block> c(n);
		io->recv_block(c.data(), n);
		io->recv_data(secret_sum_f2_out, sizeof(block));
		// K^{ᾱ_i}_i = M_{r_i} XOR c_i.
		const block* M = base_ + tree_index * cots_per_tree_;
		for (int i = 0; i < n; ++i) K_recv[i] = M[i] ^ c[i];
	}
};

}  // namespace emp
#endif  // EMP_OT_LEVEL_CORRECTION_H__
