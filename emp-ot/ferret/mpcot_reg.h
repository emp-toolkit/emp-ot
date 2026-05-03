#ifndef EMP_OT_MPCOT_REG_H__
#define EMP_OT_MPCOT_REG_H__

#include <emp-tool/emp-tool.h>
#include <future>
#include <vector>
#include "emp-ot/ferret/spcot_sender.h"
#include "emp-ot/ferret/spcot_recver.h"
#include "emp-ot/ferret/level_correction.h"

namespace emp {
using std::future;

// Multi-point COT over a regular sparse vector. Drives `tree_n`
// parallel single-point COT trees of height `tree_height` (= log2 of
// `leave_n` + 1) through OTPre, then if malicious mode is on runs
// the consistency check that consumes 128 base COTs.
class MpcotReg {
public:
	// Security parameter kappa (in bits). The consistency check
	// consumes exactly this many pre-OT base COTs to bind the
	// receiver's punctured-position choices.
	static constexpr int kConsistCheckCotNum = 128;

	int party, threads;
	int item_n, idx_max;
	int tree_height, leave_n;
	int tree_n;
	int consist_check_cot_num;
	bool is_malicious;

	IOChannel *netio;
	IOChannel **ios;
	block Delta_f2k;
	std::vector<block> consist_check_chi_alpha;
	std::vector<block> consist_check_VW;
	ThreadPool *pool;

	GaloisFieldPacking pack;

	MpcotReg(int party, int threads, int n, int t, int log_bin_sz, ThreadPool * pool, IOChannel **ios)
			: party(party), threads(threads),
			  item_n(t), idx_max(n),
			  tree_height(log_bin_sz + 1), leave_n(1 << log_bin_sz),
			  tree_n(t),
			  consist_check_cot_num(kConsistCheckCotNum),
			  is_malicious(false),
			  netio(ios[0]), ios(ios), pool(pool) {}

	void set_malicious() { is_malicious = true; }

	void sender_init(block delta) { Delta_f2k = delta; }
	void recver_init() {}

	// MPFSS over F_{2^k}. Drives `tree_n` SPCOT trees in parallel,
	// each covering `leave_n` slots of `sparse_vector`. If malicious,
	// follows up with the F_{2^k} consistency check that binds the
	// receiver's punctured-position choices to the base COTs.
	void mpcot(block * sparse_vector, LevelCorrectionSender* lc_send,
	           LevelCorrectionRecver* lc_recv, block *pre_cot_data) {
		consist_check_VW.assign(item_n, zero_block);
		if (party == BOB) consist_check_chi_alpha.assign(item_n, zero_block);

		if (party == ALICE) {
			std::vector<SPCOT_Sender*> senders;
			init_spcot_workers(senders, *lc_send);
			exec_parallel(senders, [&](SPCOT_Sender* s, int i, int t) {
				s->compute(sparse_vector + i * leave_n, Delta_f2k);
				s->send_levels(*lc_send, ios[t], i);
				ios[t]->flush();
				if (is_malicious) s->consistency_check_msg_gen(&consist_check_VW[i]);
			});
			for (auto* p : senders) delete p;
		} else {
			std::vector<SPCOT_Recver*> recvers;
			init_spcot_workers(recvers, *lc_recv);
			exec_parallel(recvers, [&](SPCOT_Recver* r, int i, int t) {
				r->recv_levels(*lc_recv, ios[t], i);
				r->compute(sparse_vector + i * leave_n);
				if (is_malicious)
					r->consistency_check_msg_gen(&consist_check_chi_alpha[i],
					                             &consist_check_VW[i]);
			});
			for (auto* p : recvers) delete p;
		}

		if (is_malicious) {
			if (party == ALICE) consistency_check_f2k_sender(pre_cot_data);
			else                consistency_check_f2k_receiver(pre_cot_data);
		}
	}

private:
	// Construct `tree_n` SPCOT workers, advancing the OTPre cursor by
	// one batch per worker. Sender just bumps the cursor; receiver
	// also drains the choice bits into each worker's `b` and computes
	// its puncture index.
	template <typename Worker, typename LC>
	void init_spcot_workers(std::vector<Worker*>& out, LC& lc) {
		out.reserve(tree_n);
		for (int i = 0; i < tree_n; ++i) {
			out.push_back(new Worker(netio, tree_height));
			if constexpr (std::is_same_v<Worker, SPCOT_Sender>) {
				lc.advance_one_tree();
			} else {
				lc.drain_choice_bits_one_tree(out[i]->b, tree_height - 1);
				out[i]->get_index();  // populates choice_pos
			}
		}
		netio->flush();
		lc.prepare_batch();
	}

	// Distribute work over `threads` worker pool threads. Each thread
	// gets a contiguous slice of [0, tree_n) and its own IOChannel
	// (ios[t]). The per_worker callback receives (worker, i, t).
	template <typename Worker, typename Fn>
	void exec_parallel(std::vector<Worker*>& workers, Fn per_worker) {
		std::vector<future<void>> fut;
		const int width = tree_n / threads;
		for (int t = 0; t < threads - 1; ++t) {
			const int start = t * width, end = start + width;
			fut.push_back(pool->enqueue([&workers, start, end, t, &per_worker]() {
				for (int i = start; i < end; ++i)
					per_worker(workers[i], i, t);
			}));
		}
		const int start = (threads - 1) * width;
		const int t     = threads - 1;
		for (int i = start; i < tree_n; ++i)
			per_worker(workers[i], i, t);
		for (auto& f : fut) f.get();
	}

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
