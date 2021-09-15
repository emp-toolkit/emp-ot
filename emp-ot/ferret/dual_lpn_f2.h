#ifndef EMP_DUAL_LPN_F2K_H__
#define EMP_DUAL_LPN_F2K_H__

#include "emp-tool/emp-tool.h"
using namespace emp;

//Implementation of local linear code on F_2^k
//Performance highly dependent on the CPU cache size
template<typename IO>
class DualLpnF2 { public:
	int party;
	int64_t n, np;
	ThreadPool * pool;
	IO *io;
	int threads;
	block seed;

	const int batch_n = 8;
	const int batch_n_exp = 1 << batch_n;

	DualLpnF2 (int party, int64_t n, int64_t np, ThreadPool * pool,
			IO *io, int threads) {
		this->party = party;
		this->n = n;
		this->np = np;
		this->pool = pool;
		this->io = io;
		this->threads = threads;
	}

// temporarily assume n can be divided by 16*8,
// and np can be divided by 8 (satisfied by current parameters)
	void task(block * nn, const block * kk, int64_t start, int64_t end, int64_t kk_start) {
		PRP prp(seed);
		int64_t i = kk_start, j = start;

		block pre_table[batch_n_exp];
		block idx_data[8];
		const block *data_p = kk;
		while(i < np) {
			pre_table[0] = zero_block;
			pre_table[1] = data_p[0];
			for(int p = 1; p < batch_n; ++p) {
				int half_nodes_n = 1 << p;
				for(int q = 0; q < half_nodes_n; ++q) {
					pre_table[half_nodes_n+q] = pre_table[q] ^ data_p[p];
				}
			}

			j = start;
			while(j < end) {
				idx_data[0] = makeBlock(0, i);
				idx_data[1] = makeBlock(1, i);
				idx_data[2] = makeBlock(2, i);
				idx_data[3] = makeBlock(3, i);
				idx_data[4] = makeBlock(4, i);
				idx_data[5] = makeBlock(5, i);
				idx_data[6] = makeBlock(6, i);
				idx_data[7] = makeBlock(7, i);
				prp.permute_block(idx_data, 8);
				uint8_t *idx_ptr = (uint8_t*)idx_data;
				for(int p = 0; p < 16*8; ++p) {
					nn[j+p] ^= pre_table[idx_ptr[p]];
				}
				j += batch_n * 16 * 8;
			}
			data_p += batch_n;
			i += batch_n;
		}
	}

	void compute(block * nn, const block * kk, const block &shared_seed) {
		vector<std::future<void>> fut;
		int64_t width = n/threads;
		seed = shared_seed;
		for(int i = 0; i < threads - 1; ++i) {
			int64_t start = i * width;
			int64_t end = min((i+1)* width, n);
			fut.push_back(pool->enqueue([this, nn, kk, start, end]() {
				task(nn, kk, start, end, 0);
			}));
		}
		int64_t start = (threads - 1) * width;
		int64_t end = min(threads * width, n);
		task(nn, kk, start, end, 0);

		for (auto &f: fut) f.get();
	}

	// H := (I | U)
	void compute_opt(block * nn, const block * kk, const block &shared_seed) {
		vector<std::future<void>> fut;
		memcpy(nn, kk, n*sizeof(block));
		int64_t width = n/threads;
		seed = shared_seed;
		for(int i = 0; i < threads - 1; ++i) {
			int64_t start = i * width;
			int64_t end = min((i+1)* width, n);
			fut.push_back(pool->enqueue([this, nn, kk, start, end]() {
				task(nn, kk, start, end, n);
			}));
		}
		int64_t start = (threads - 1) * width;
		int64_t end = min(threads * width, n);
		task(nn, kk, start, end, n);

		for (auto &f: fut) f.get();
	}
};
#endif
