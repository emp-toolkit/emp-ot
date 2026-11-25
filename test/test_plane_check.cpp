// PlaneCheck (ot_extension/plane_check.h), the malicious consistency check of
// IKNP and SoftSpoken, driven directly on synthetic chunks. Both parties derive
// the same chunks from a shared seed: Δ (bit 0 set), the receiver's choice bits
// U and planes V (plane 0 = U), and the sender's planes W_p = V_p ⊕ Δ_p·U
// (plane 0 = 0). A case flips bits of the sender's planes, as a wrong
// correction does, and the sender must accept iff the case flips nothing:
//   * no flips;
//   * one bit of one plane, in the first chunk or in the closing one-block
//     chunk that stands in for the sacrificial chunk;
//   * two bits of one plane, in different blocks;
//   * one bit in each of two planes on one anti-diagonal (COT j of plane p,
//     with j + p fixed), and one bit in each of 126 planes along a whole
//     anti-diagonal. Folding each block's COTs with the fixed weights X^j,
//     planes with X^p, adds each of these to zero; comparing every plane on
//     its own does not.
// Two-party via `run`.
#include "test/test.h"
#include "emp-ot/ot_extension/plane_check.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iterator>
#include <vector>

using namespace emp;

namespace {

constexpr int kPlanes = PlaneCheck::kPlanes;
// Chunk sizes in 128-COT blocks. The odd sizes reach the inner product's tail.
constexpr int64_t kChunks[] = {3, 5, 1};

struct Flip {
	int chunk;
	int plane;
	int64_t cot;   // COT index within the chunk
};

void flip_bit(block *plane, int64_t cot) {
	uint64_t w[2];
	std::memcpy(w, &plane[cot / 128], sizeof(w));
	w[(cot % 128) / 64] ^= uint64_t{1} << (cot % 64);
	std::memcpy(&plane[cot / 128], w, sizeof(w));
}

// One check over fresh synthetic chunks on its own channel. Returns the
// sender's verdict (ALICE); BOB returns true.
bool run_case(NetIO *anchor, int party, const std::vector<Flip> &flips) {
	auto io = anchor->make_sibling();
	block seed;
	if (party == ALICE) {
		PRG().random_block(&seed, 1);
		io->send_block(&seed, 1);
		io->flush();
	} else {
		io->recv_block(&seed, 1);
	}
	io->enable_fs(/*send_first=*/party == ALICE);
	PRG shared(&seed);
	bool delta[kPlanes];
	shared.random_bool(delta, kPlanes);
	delta[0] = true;
	const block sid = makeBlock(0, 0x706c616e65);   // any nonzero id

	PlaneCheck check;
	check.reset();
	for (int c = 0; c < static_cast<int>(std::size(kChunks)); ++c) {
		const int64_t bs = kChunks[c];
		BlockVec u(bs), v(kPlanes * bs), w(kPlanes * bs);
		shared.random_block(u.data(), bs);
		shared.random_block(v.data(), kPlanes * bs);
		for (int64_t i = 0; i < bs; ++i) {
			v[i] = u[i];
			w[i] = zero_block;
		}
		for (int p = 1; p < kPlanes; ++p)
			for (int64_t i = 0; i < bs; ++i)
				w[p * bs + i] = delta[p] ? v[p * bs + i] ^ u[i] : v[p * bs + i];
		for (const Flip &f : flips)
			if (f.chunk == c) flip_bit(w.data() + f.plane * bs, f.cot);

		// Where the receiver's corrections would cross: move the transcript.
		block step;
		shared.random_block(&step, 1);
		if (party == BOB) {
			io->send_block(&step, 1);
			io->flush();
		} else {
			io->recv_block(&step, 1);
		}
		check.fold(io.get(), sid, party == ALICE ? w.data() : v.data(), bs);
	}

	if (party == BOB) {
		check.send(io.get(), sid);
		io->flush();
		return true;
	}
	return check.verify(io.get(), sid, delta);
}

}  // namespace

int main(int argc, char **argv) {
	const int party = parse_party(argv);
	const int port = peer_port();
	auto anchor = party == ALICE ? NetIO::listen(port, /*quiet=*/true)
	                             : NetIO::connect(peer_ip(), port, /*quiet=*/true);
	anchor->sync();

	std::vector<Flip> diagonal;
	for (int p = 1; p <= 126; ++p) diagonal.push_back({0, p, 126 - p});
	struct Case {
		const char *name;
		std::vector<Flip> flips;
	};
	const Case cases[] = {
		{"no flips", {}},
		{"one bit of one plane", {{0, 5, 0}}},
		{"one bit of one plane, closing chunk", {{2, 7, 5}}},
		{"two bits of one plane", {{0, 9, 3}, {0, 9, 200}}},
		{"an anti-diagonal pair", {{0, 1, 1}, {0, 2, 0}}},
		{"a whole anti-diagonal", diagonal},
	};
	for (const Case &c : cases) {
		const bool accepted = run_case(anchor.get(), party, c.flips);
		if (party == ALICE) {
			std::cout << c.name << ": " << (accepted ? "accepted" : "rejected")
			          << std::endl;
			expecting(accepted == c.flips.empty(),
			          "PlaneCheck verdict does not match the planes");
		}
	}
	return 0;
}
