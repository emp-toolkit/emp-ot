#ifndef EMP_OT_SPCOT_RECVER_H__
#define EMP_OT_SPCOT_RECVER_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/constants.h"
#include "emp-ot/ferret/cggm.h"

namespace emp {

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

	int get_index() {
		choice_pos = 0;
		for(int i = 0; i < depth-1; ++i) {
			choice_pos<<=1;
			if(!b[i])
				choice_pos +=1;
		}
		return choice_pos;
	}

	// Reconstruct the GGM tree (every leaf except the punctured one),
	// then apply the SPCOT-specific correction that recovers the
	// punctured leaf's value (with `delta` at its bit 0). `b[]` is the
	// OT choice array = NOT alpha_j, MSB-first; get_index() already
	// folds it into choice_pos == alpha, and m[i] is precisely the
	// shared K_recv[i] = K_{alpha_bar_{i+1}}^{i+1}.
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
		// X
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
#endif
