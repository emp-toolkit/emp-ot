#ifndef EMP_OT_MPCOT_REG_H__
#define EMP_OT_MPCOT_REG_H__

#include <emp-tool/emp-tool.h>
#include <vector>
#include "emp-ot/ot_extension/ferret/spcot.h"

namespace emp {

// Multi-point COT over a regular sparse vector. Drives `tree_n`
// parallel single-point COT trees of height `tree_height` (= log2 of
// `leave_n` + 1) through cGGM (Half-Tree, ePrint 2022/1431, Fig 4),
// then if malicious mode is on runs the consistency check that
// consumes 128 base COTs.
//
// pre_cot_data layout (passed in by FerretCOT::extend):
//   [0 .. tree_n*(h-1)) : per-tree base COTs feeding the cGGM
//                         level corrections. ALICE has K_{r_i};
//                         BOB has M_{r_i} = K_{r_i} XOR r_i*Delta.
//   [0 .. 128)          : ALSO consumed by the malicious-mode
//                         consistency check (aliasing — both reads
//                         are non-destructive and the security
//                         argument covers both uses).
class MpcotReg {
public:
	// Security parameter kappa (in bits). The consistency check
	// consumes exactly this many base COTs to bind the
	// receiver's punctured-position choices.
	static constexpr int kConsistCheckCotNum = 128;

	int party;
	int item_n, idx_max;
	int tree_height, leave_n;
	int tree_n;
	bool is_malicious;

	IOChannel *netio;
	block Delta_f2k;
	std::vector<block> consist_check_chi_alpha;
	std::vector<block> consist_check_VW;

	GaloisFieldPacking pack;

	MpcotReg(int party, int n, int t, int log_bin_sz, IOChannel *io)
			: party(party),
			  item_n(t), idx_max(n),
			  tree_height(log_bin_sz + 1), leave_n(1 << log_bin_sz),
			  tree_n(t),
			  is_malicious(false),
			  netio(io) {}

	void set_malicious() { is_malicious = true; }

	void sender_init(block delta) { Delta_f2k = delta; }
	void recver_init() {}

	// MPFSS over F_{2^k}. Drives `tree_n` SPCOT trees, each covering
	// `leave_n` slots of `sparse_vector`. Trees expand one at a time:
	// each iteration is a full mini-SPCOT (build/recv corrections,
	// reconstruct cGGM tree, accumulate consistency-check msg) before
	// the next tree starts. If malicious, the round-final F_{2^k}
	// consistency check binds the receiver's punctured-position
	// choices to the base COTs across all trees.
	void mpcot(block * sparse_vector, block *pre_cot_data) {
		consist_check_VW.assign(item_n, zero_block);
		if (party == BOB) consist_check_chi_alpha.assign(item_n, zero_block);

		const int n_lvl = tree_height - 1;  // cGGM corrections per tree
		BlockVec c(n_lvl);                  // reused across trees

		for (int i = 0; i < tree_n; ++i) {
			block* leaves_i = sparse_vector + i * leave_n;
			const block* base_i = pre_cot_data + i * n_lvl;

			if (party == ALICE) {
				SPCOT_Sender s(netio, tree_height);
				s.compute(leaves_i, Delta_f2k);
				// cGGM level corrections: c_j = K_{r_j} XOR K^0_j.
				for (int j = 0; j < n_lvl; ++j) c[j] = base_i[j] ^ s.m[j];
				netio->send_block(c.data(), n_lvl);
				netio->send_data(&s.secret_sum_f2, sizeof(block));
				netio->flush();
				if (is_malicious) s.consistency_check_msg_gen(&consist_check_VW[i]);
			} else {
				SPCOT_Recver r(netio, tree_height);
				// b_j = NOT alpha_{j+1} = r_{j+1} = LSB(M_{r_{j+1}}).
				for (int j = 0; j < n_lvl; ++j) r.b[j] = getLSB(base_i[j]);
				netio->recv_block(c.data(), n_lvl);
				netio->recv_data(&r.secret_sum_f2, sizeof(block));
				// Recover K^{ᾱ_j}_{j+1} = M_{r_{j+1}} XOR c_{j+1}.
				for (int j = 0; j < n_lvl; ++j) r.m[j] = base_i[j] ^ c[j];
				r.compute(leaves_i);
				if (is_malicious)
					r.consistency_check_msg_gen(&consist_check_chi_alpha[i],
					                            &consist_check_VW[i]);
			}
		}

		if (is_malicious) {
			if (party == ALICE) consistency_check_f2k_sender(pre_cot_data);
			else                consistency_check_f2k_receiver(pre_cot_data);
		}
	}

private:
	// Sender-side malicious-check (F_{2^k}). Receives the receiver's
	// 128-bit correction (chi_alpha applied to the base COTs), folds
	// it into our XOR-sum of the per-tree V responses, hashes, and
	// sends the digest.
	void consistency_check_f2k_sender(block *pre_cot_data) {
		block r1, r2;
		vector_self_xor(&r1, consist_check_VW.data(), tree_n);

		bool x_prime[kConsistCheckCotNum];
		netio->recv_data(x_prime, kConsistCheckCotNum * sizeof(bool));
		for (int i = 0; i < kConsistCheckCotNum; ++i)
			if (x_prime[i])
				pre_cot_data[i] = pre_cot_data[i] ^ Delta_f2k;
		pack.packing(&r2, pre_cot_data);
		r1 = r1 ^ r2;

		block dig[2];
		Hash hash;
		hash.hash_once(dig, &r1, sizeof(block));
		netio->send_data(dig, 2 * sizeof(block));
		netio->flush();
	}

	// Receiver-side malicious-check (F_{2^k}). Sends a 128-bit
	// correction derived from XOR(chi_alpha) and the LSBs of the base
	// COTs, then hashes its own XOR-sum of W with the packed base
	// COTs, and aborts on digest mismatch.
	void consistency_check_f2k_receiver(block *pre_cot_data) {
		block r1, r2;
		vector_self_xor(&r1, consist_check_VW.data(), tree_n);
		vector_self_xor(&r2, consist_check_chi_alpha.data(), tree_n);

		uint64_t pos[2];
		pos[0] = _mm_extract_epi64(r2, 0);
		pos[1] = _mm_extract_epi64(r2, 1);
		bool pre_cot_bool[kConsistCheckCotNum];
		for (int i = 0; i < 2; ++i) {
			for (int j = 0; j < 64; ++j) {
				pre_cot_bool[i * 64 + j] =
					((pos[i] & 1) == 1) ^ getLSB(pre_cot_data[i * 64 + j]);
				pos[i] >>= 1;
			}
		}
		netio->send_data(pre_cot_bool, kConsistCheckCotNum * sizeof(bool));
		netio->flush();

		block r3;
		pack.packing(&r3, pre_cot_data);
		r1 = r1 ^ r3;

		block dig[2];
		Hash hash;
		hash.hash_once(dig, &r1, sizeof(block));
		block recv[2];
		netio->recv_data(recv, 2 * sizeof(block));
		if (!cmpBlock(dig, recv, 2))
			std::cout << "SPCOT consistency check fails" << std::endl;
	}
};

}  // namespace emp
#endif
