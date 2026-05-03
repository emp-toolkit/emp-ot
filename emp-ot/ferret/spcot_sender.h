#ifndef EMP_OT_SPCOT_SENDER_H__
#define EMP_OT_SPCOT_SENDER_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/ferret/constants.h"
#include "emp-ot/ferret/level_correction.h"
#include "emp-ot/ferret/test_random.h"
#include "emp-ot/pprf.h"

namespace emp {

class SPCOT_Sender { public:
	block seed;
	block delta;
	block *ggm_tree, *m;
	int depth, leave_n;
	block secret_sum_f2;

	SPCOT_Sender(IOChannel * /*io*/, int depth_in)
			: depth(depth_in), leave_n(1 << (depth_in - 1)),
			  m(new block[(depth_in - 1) * 2]) {
		if (!ferret_test::maybe_test_seed(&seed)) {
			PRG prg;
			prg.random_block(&seed, 1);
		}
	}

	~SPCOT_Sender() {
		delete[] m;
	}

	// Build the depth-`depth` GGM tree, then apply the SPCOT-specific
	// per-leaf correction so bit-0 of every leaf carries the COT
	// choice signal (with bit-0 of the punctured leaf carrying `secret`).
	void compute(block* ggm_tree_mem, block secret) {
		this->delta    = secret;
		this->ggm_tree = ggm_tree_mem;
		pprf::build_sender(depth - 1, seed, ggm_tree, m, m + depth - 1);
		apply_punctured_correction(secret);
	}

	// Hand the per-level XOR-sums (m[0..depth-2] = K0, m[depth-1..]
	// = K1) to the level-correction strategy along with the trailing
	// secret_sum_f2.
	void send_levels(LevelCorrectionSender& lc, IOChannel* io2, int s) {
		lc.send_tree(s, io2, m, &m[depth-1], depth-1, secret_sum_f2);
	}

	// SPCOT-specific post-PPRF step: clear bit 0 of every leaf so the
	// per-leaf COT outputs use the LSB convention, then emit
	// secret_sum_f2 = (XOR of all leaves) XOR secret. The receiver,
	// who knows every leaf except the punctured one, reconstructs the
	// punctured leaf's value by XORing its known leaves into
	// secret_sum_f2 — which deposits `secret` at bit 0 of that leaf.
	void apply_punctured_correction(block secret) {
		secret_sum_f2 = secret;
		for (int i = 0; i < leave_n; ++i) {
			ggm_tree[i]   = ggm_tree[i] & lsb_clear_mask;
			secret_sum_f2 = secret_sum_f2 ^ ggm_tree[i];
		}
	}

	void consistency_check_msg_gen(block *V) {
		// X
		block *chi = new block[leave_n];
		Hash hash;
		block digest[2];
		hash.hash_once(digest, &secret_sum_f2, sizeof(block));
		uni_hash_coeff_gen(chi, digest[0], leave_n);

		vector_inn_prdt_sum_red(V, chi, ggm_tree, leave_n);
		delete[] chi;
	}
};

}  // namespace emp
#endif
