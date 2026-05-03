#ifndef EMP_OT_SPCOT_H__
#define EMP_OT_SPCOT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ferret/constants.h"
#include "emp-ot/ferret/test_random.h"

// Single-point COT under Half-Tree (cGGM, Guo-Yang-Wang-Zhang-
// Xie-Liu-Zhao, ePrint 2022/1431, Figure 4 in the F_COT-hybrid
// model). Three pieces:
//   1) namespace emp::cggm — the correlated-GGM tree (Fig 3):
//      sender FullEval and receiver PuncFullEval. Hash H is
//      emp-tool's CCRH (= π(σ(x)) ⊕ σ(x), Theorem 4.3).
//   2) class SPCOT_Sender — wraps cggm::build_sender and applies
//      the LSB-of-output choice convention via secret_sum_f2.
//   3) class SPCOT_Recver — wraps cggm::eval_receiver and applies
//      the inverse correction.
//
// MpcotReg is the only consumer of these classes; it owns the
// per-tree level-correction wire format (one κ-bit c_i per level,
// derived from the precomputed base COTs).

namespace emp {

// ---------------------------------------------------------------------
// cGGM tree (Half-Tree Fig 3). At every non-leaf:
//   left  = H(parent)
//   right = parent XOR left
// Root children are (k, Δ XOR k); the leveled correlation
// `Δ = XOR of all nodes on level i` then holds for every i in [1, d].
//
// alpha bit convention: alpha_1 is MSB (alpha_j = bit (d-j) of
// alpha), matching the rest of ferret.

namespace cggm {

// Sender: build the depth-d cGGM tree given Δ and a top secret k.
// Writes 2^d leaves into `leaves` and the per-level left-side
// XOR-sums K^0_i for i ∈ [1, d] into `K0[i-1]`.
inline void build_sender(int d, block Delta, block k,
                         block* leaves, block* K0) {
    CCRH ccrh;

    // Level 1 (two children of the conceptual root).
    leaves[0] = k;
    leaves[1] = Delta ^ k;
    K0[0] = leaves[0];

    // Levels 2..d.
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        // Expand in place from index parents-1 downward so a parent
        // at index j produces children at 2j and 2j+1 without
        // clobbering yet-to-be-expanded parents.
        for (int j = parents - 1; j >= 0; --j) {
            block parent = leaves[j];
            block left   = ccrh.H(parent);
            block right  = parent ^ left;
            leaves[2 * j]     = left;
            leaves[2 * j + 1] = right;
        }
        block sum = zero_block;
        for (int j = 0; j < (1 << i); j += 2)
            sum = sum ^ leaves[j];
        K0[i - 1] = sum;
    }
}

// Receiver: reconstruct the depth-d cGGM tree from the punctured
// path `alpha` (d bits, MSB-first) and d corrections K_recv[i] =
// K^{ᾱ_{i+1}}_{i+1}. After return, leaves[x] holds the correct
// cGGM leaf for every x != alpha; leaves[alpha] is zero_block (the
// SPCOT-layer apply_punctured_correction step fills it with
// secret_sum_f2 ⊕ XOR(known leaves), which equals sender's leaf at
// alpha XOR Δ — the COT relation).
inline void eval_receiver(int d, int alpha,
                          const block* K_recv, block* leaves) {
    const int Q = 1 << d;
    for (int i = 0; i < Q; ++i) leaves[i] = zero_block;

    CCRH ccrh;

    // path = prefixsum_{i-1}(alpha): integer formed by alpha_1..alpha_{i-1}
    // (top-down, MSB-first). Doubles per level; alpha_i appended at end.
    int path = 0;

    // Level 1: receiver knows the alpha_bar_1-side root child only.
    {
        const int alpha_1     = (alpha >> (d - 1)) & 1;
        const int alpha_bar_1 = 1 - alpha_1;
        leaves[alpha_bar_1] = K_recv[0];
        path = alpha_1;
    }

    // Levels 2..d. At each, every parent on level i-1 except the
    // on-path one (at index `path`) is fully known; we expand them,
    // then recover the on-path level-i node on the alpha_bar_i side
    // via K_recv[i-1] XOR (XOR of expanded alpha_bar_i-side nodes).
    for (int i = 2; i <= d; ++i) {
        const int parents = 1 << (i - 1);
        for (int j = parents - 1; j >= 0; --j) {
            block parent = leaves[j];
            block left   = ccrh.H(parent);
            block right  = parent ^ left;
            leaves[2 * j]     = left;
            leaves[2 * j + 1] = right;
        }

        const int alpha_i     = (alpha >> (d - i)) & 1;
        const int alpha_bar_i = 1 - alpha_i;
        const int on_path_lvl = path * 2 + alpha_i;
        const int sibling_lvl = path * 2 + alpha_bar_i;

        // Zero the on-path node's two children (junk from the H(0)
        // expansion above; sibling will be overwritten via K_recv;
        // on_path stays zero as the new puncture).
        leaves[2 * path]     = zero_block;
        leaves[2 * path + 1] = zero_block;

        block sum = zero_block;
        for (int j = alpha_bar_i; j < (1 << i); j += 2)
            sum = sum ^ leaves[j];
        leaves[sibling_lvl] = sum ^ K_recv[i - 1];

        path = on_path_lvl;
    }
}

}  // namespace cggm

// ---------------------------------------------------------------------
// SPCOT sender. Public state (m, secret_sum_f2) is read by MpcotReg
// after compute() to ship the cGGM level corrections + secret_sum_f2
// over the wire.

class SPCOT_Sender { public:
	block seed;
	block delta;
	block *ggm_tree, *m;
	int depth, leave_n;
	block secret_sum_f2;

	SPCOT_Sender(IOChannel * /*io*/, int depth_in)
			: depth(depth_in), leave_n(1 << (depth_in - 1)),
			  m(new block[depth_in - 1]) {
		if (!ferret_test::maybe_test_seed(&seed)) {
			PRG prg;
			prg.random_block(&seed, 1);
		}
	}

	~SPCOT_Sender() {
		delete[] m;
	}

	// Build the depth-`depth` cGGM tree, then apply the SPCOT-specific
	// per-leaf correction so bit-0 of every leaf carries the COT
	// choice signal (with bit-0 of the punctured leaf carrying `secret`).
	void compute(block* ggm_tree_mem, block secret) {
		this->delta    = secret;
		this->ggm_tree = ggm_tree_mem;
		// m[i] = K^0_{i+1} for i ∈ [0, depth-1).
		cggm::build_sender(depth - 1, secret, seed, ggm_tree, m);
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
		block *chi = new block[leave_n];
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi, digest[0], leave_n);
		vector_inn_prdt_sum_red(V, chi, ggm_tree, leave_n);
		delete[] chi;
	}
};

// ---------------------------------------------------------------------
// SPCOT receiver. Public state (m, b, choice_pos, secret_sum_f2) is
// written by MpcotReg before/after compute().

class SPCOT_Recver {
public:
	block *ggm_tree, *m;
	bool *b;
	int choice_pos, depth, leave_n;
	block secret_sum_f2;

	SPCOT_Recver(IOChannel * /*io*/, int depth_in)
			: m(new block[depth_in - 1]), b(new bool[depth_in - 1]),
			  depth(depth_in), leave_n(1 << (depth_in - 1)) {}

	~SPCOT_Recver(){
		delete[] m;
		delete[] b;
	}

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
		cggm::eval_receiver(depth - 1, choice_pos, m, ggm_tree);
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
		block *chi = new block[leave_n];
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi, digest[0], leave_n);
		*chi_alpha = chi[choice_pos];
		vector_inn_prdt_sum_red(W, chi, ggm_tree, leave_n);
		delete[] chi;
	}
};

}  // namespace emp
#endif  // EMP_OT_SPCOT_H__
