#ifndef EMP_OT_SPCOT_H__
#define EMP_OT_SPCOT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot_extension/cggm.h"
#include "emp-ot/ot_extension/ferret/constants.h"
#include "emp-ot/ot_extension/ferret/test_random.h"

// Single-point COT under Half-Tree (cGGM, Guo-Yang-Wang-Zhang-
// Xie-Liu-Zhao, ePrint 2022/1431, Figure 4 in the F_COT-hybrid
// model). Two pieces:
//   1) class SPCOT_Sender — wraps cggm::build_sender and applies
//      the LSB-of-output choice convention via secret_sum_f2.
//   2) class SPCOT_Recver — wraps cggm::eval_receiver and applies
//      the inverse correction.
//
// MpcotReg is the only consumer of these classes; it owns the
// per-tree level-correction wire format (one κ-bit c_i per level,
// derived from the precomputed base COTs).

namespace emp {

// ---------------------------------------------------------------------
// SPCOT sender. Public state (m, secret_sum_f2) is read by MpcotReg
// after compute() to ship the cGGM level corrections + secret_sum_f2
// over the wire.

class SPCOT_Sender { public:
	block seed;
	block delta;
	block *ggm_tree;
	BlockVec m;             // depth-1 entries; MpcotReg accesses via m[j]
	int depth, leave_n;
	block secret_sum_f2;

	SPCOT_Sender(IOChannel * /*io*/, int depth_in)
			: m(depth_in - 1),
			  depth(depth_in), leave_n(1 << (depth_in - 1)) {
		if (!ferret_test::maybe_test_seed(&seed)) {
			PRG prg;
			prg.random_block(&seed, 1);
		}
	}

	// Build the depth-`depth` cGGM tree, then apply the SPCOT-specific
	// per-leaf correction so bit-0 of every leaf carries the COT
	// choice signal (with bit-0 of the punctured leaf carrying `secret`).
	void compute(block* ggm_tree_mem, block secret) {
		this->delta    = secret;
		this->ggm_tree = ggm_tree_mem;
		// m[i] = K^0_{i+1} for i ∈ [0, depth-1).
		cggm::build_sender(depth - 1, secret, seed, ggm_tree, m.data());
		apply_punctured_correction(secret);
	}

	// Clear bit 0 of every leaf so the per-leaf COT outputs use the
	// LSB convention; emit secret_sum_f2 = (XOR of all leaves) XOR
	// secret. The receiver, who knows every leaf except the punctured
	// one, reconstructs the punctured leaf by XORing its known leaves
	// into secret_sum_f2 — which deposits `secret` at bit 0 of that
	// leaf. Under cGGM, XOR(all leaves) = Δ (leveled correlation), so
	// secret_sum_f2 reduces to the per-tree LSB parity bit; the
	// reconstruction algebra still lands on v'[α] XOR Δ as desired.
	void apply_punctured_correction(block secret) {
		secret_sum_f2 = secret;
		for (int i = 0; i < leave_n; ++i) {
			ggm_tree[i]   = ggm_tree[i] & lsb_clear_mask;
			secret_sum_f2 = secret_sum_f2 ^ ggm_tree[i];
		}
	}

	void consistency_check_msg_gen(block *V) {
		BlockVec chi(leave_n);
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi.data(), digest[0], leave_n);
		vector_inn_prdt_sum_red(V, chi.data(), ggm_tree, leave_n);
	}
};

// ---------------------------------------------------------------------
// SPCOT receiver. Public state (m, b, choice_pos, secret_sum_f2) is
// written by MpcotReg before/after compute().

class SPCOT_Recver {
public:
	block *ggm_tree;
	BlockVec m;                              // depth-1 entries
	default_init_vector<unsigned char> b;    // depth-1 entries; one byte
	                                         // each. MpcotReg writes via b[j]
	                                         // = getLSB(...); reads as truthy.
	int choice_pos, depth, leave_n;
	block secret_sum_f2;

	SPCOT_Recver(IOChannel * /*io*/, int depth_in)
			: m(depth_in - 1), b(depth_in - 1),
			  depth(depth_in), leave_n(1 << (depth_in - 1)) {}

	// Pack b[0..depth-2] (NOT alpha_j, MSB-first) into choice_pos == alpha.
	int get_index() {
		choice_pos = 0;
		for(int i = 0; i < depth-1; ++i) {
			choice_pos<<=1;
			if(!b[i])
				choice_pos +=1;
		}
		return choice_pos;
	}

	// Reconstruct the cGGM tree (every leaf except the punctured one),
	// then apply the SPCOT-specific correction that recovers the
	// punctured leaf's value (with `delta` at its bit 0). m[i] is
	// K_recv[i] = K^{ᾱ_{i+1}}_{i+1}, set by MpcotReg from M_{r_i} XOR c_i.
	void compute(block* ggm_tree_mem) {
		this->ggm_tree = ggm_tree_mem;
		get_index();  // idempotent; ensures choice_pos == alpha.
		cggm::eval_receiver(depth - 1, choice_pos, m.data(), ggm_tree);
		apply_punctured_correction();
	}

	// Mirror of SPCOT_Sender::apply_punctured_correction. eval_receiver
	// left ggm_tree[choice_pos] = zero_block; the XOR-then-overwrite
	// fills it with (XOR of known leaves) XOR secret_sum_f2, which
	// equals the sender's leaf at choice_pos with `delta` deposited
	// at bit 0.
	void apply_punctured_correction() {
		block nodes_sum = zero_block;
		for (int i = 0; i < leave_n; ++i) {
			ggm_tree[i] = ggm_tree[i] & lsb_clear_mask;
			nodes_sum   = nodes_sum ^ ggm_tree[i];
		}
		ggm_tree[choice_pos] = nodes_sum ^ secret_sum_f2;
	}

	void consistency_check_msg_gen(block *chi_alpha, block *W) {
		BlockVec chi(leave_n);
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi.data(), digest[0], leave_n);
		*chi_alpha = chi[choice_pos];
		vector_inn_prdt_sum_red(W, chi.data(), ggm_tree, leave_n);
	}
};

}  // namespace emp
#endif  // EMP_OT_SPCOT_H__
