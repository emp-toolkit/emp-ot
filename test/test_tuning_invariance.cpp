// Output-invariance of every LOCAL-class knob that `make tune` may
// override (see tuning.h "Per-machine overrides"). For each knob, run
// the same computation at the extreme candidate values and assert
// bit-identical results — a knob that shapes outputs (and therefore
// the transcript) is AGREEMENT/SECURITY-class and must never be in the
// tuner's registry; this test is the mechanical guard on that boundary.
//
// Knobs covered:
//   1. sfvole butterfly tile T          (T in {8, 16, 32})
//   2. cGGM expand tile                 (Tile in {4, 8, 64}, both LSB modes)
//   3. LPN batch M                      (M in {16, 32, 64})
//   4. COT chosen-input MITCCRH tile    (BatchSize in {4, 8, 16})
//
// Single-process (no IO / no `run`).
#include "emp-ot/emp-ot.h"
#include "emp-ot/ot_extension/softspoken/sfvole_butterfly.h"
#include "emp-ot/common/cggm.h"
#include "emp-ot/common/lpn.h"
#include <cstring>
#include <iostream>
#include <vector>
using namespace emp;
using namespace std;

static int failures = 0;

static void check(const char* tag, bool ok) {
	cout << (ok ? "[OK]   " : "[FAIL] ") << tag << "\n";
	if (!ok) ++failures;
}

static bool blocks_equal(const block* a, const block* b, int64_t n) {
	return memcmp(a, b, sizeof(block) * (size_t)n) == 0;
}

// ---- 1. sfvole butterfly tile -------------------------------------
// Sender and receiver kernels at T in {8,16,32} over the same leaves /
// session key / counter window, at a tile-aligned bs and a ragged one
// (exercises the n_valid tail path).
template <int k, int T>
static void run_sfvole(const block* leaves, const AES_KEY* K, int64_t bs,
                       block* u, block* v_planes, block* w_planes) {
	constexpr int Q = 1 << k;
	softspoken::sfvole_sender_butterfly<k, T>(leaves, K, /*b0=*/7, bs, u, v_planes);
	softspoken::sfvole_receiver_butterfly<k, T>(/*alpha=*/Q - 2, leaves, K,
	                                            /*b0=*/7, bs, w_planes);
}

template <int k>
static void test_sfvole_tiles() {
	constexpr int Q = 1 << k;
	PRG prg;
	BlockVec leaves(Q);
	prg.random_block(leaves.data(), Q);
	AES_KEY K;
	AES_set_encrypt_key(makeBlock(1, 2), &K);

	for (int64_t bs : {int64_t{64}, int64_t{52}}) {
		BlockVec u8(bs), v8(k * bs), w8(k * bs);
		BlockVec uT(bs), vT(k * bs), wT(k * bs);
		run_sfvole<k, 8>(leaves.data(), &K, bs, u8.data(), v8.data(), w8.data());

		bool ok = true;
		run_sfvole<k, 16>(leaves.data(), &K, bs, uT.data(), vT.data(), wT.data());
		ok = ok && blocks_equal(u8.data(), uT.data(), bs)
		        && blocks_equal(v8.data(), vT.data(), k * bs)
		        && blocks_equal(w8.data(), wT.data(), k * bs);
		run_sfvole<k, 32>(leaves.data(), &K, bs, uT.data(), vT.data(), wT.data());
		ok = ok && blocks_equal(u8.data(), uT.data(), bs)
		        && blocks_equal(v8.data(), vT.data(), k * bs)
		        && blocks_equal(w8.data(), wT.data(), k * bs);

		char tag[64];
		snprintf(tag, sizeof(tag), "sfvole tile T {8,16,32}: k=%d bs=%lld",
		         k, (long long)bs);
		check(tag, ok);
	}
}

// ---- 2. cGGM tile --------------------------------------------------
template <bool ClearLSB>
static void test_cggm_tiles(const char* mode) {
	constexpr int d = 13;
	constexpr int64_t Q = int64_t{1} << d;
	PRG prg;
	block Delta, root;
	prg.random_block(&Delta, 1);
	prg.random_block(&root, 1);

	BlockVec leaves_a(Q), leaves_b(Q);
	block K0_a[d], K0_b[d];

	cggm::build_sender<8, ClearLSB>(d, Delta, root, leaves_a.data(), K0_a);
	bool ok = true;
	cggm::build_sender<4, ClearLSB>(d, Delta, root, leaves_b.data(), K0_b);
	ok = ok && blocks_equal(leaves_a.data(), leaves_b.data(), Q)
	        && blocks_equal(K0_a, K0_b, d);
	cggm::build_sender<64, ClearLSB>(d, Delta, root, leaves_b.data(), K0_b);
	ok = ok && blocks_equal(leaves_a.data(), leaves_b.data(), Q)
	        && blocks_equal(K0_a, K0_b, d);

	// Receiver eval at both tile extremes, K_recv derived from the build:
	// level i's correction is the alpha_bar_i-side sum (left = K0, right
	// = K0 ^ Delta).
	const int alpha = 0x0AB3 & (int)(Q - 1);
	block K_recv[d];
	for (int i = 1; i <= d; ++i) {
		const int alpha_i = (alpha >> (d - i)) & 1;
		K_recv[i - 1] = alpha_i ? K0_a[i - 1] : (K0_a[i - 1] ^ Delta);
	}
	BlockVec eval_a(Q), eval_b(Q);
	cggm::eval_receiver<4, ClearLSB>(d, alpha, K_recv, eval_a.data());
	cggm::eval_receiver<64, ClearLSB>(d, alpha, K_recv, eval_b.data());
	ok = ok && blocks_equal(eval_a.data(), eval_b.data(), Q);

	char tag[64];
	snprintf(tag, sizeof(tag), "cggm tile {4,8,64} build+eval: %s", mode);
	check(tag, ok);
}

// ---- 3. LPN batch M -------------------------------------------------
static void test_lpn_batches() {
	constexpr int logk = 17;                  // 2 MiB table
	constexpr int64_t kk = int64_t{1} << logk;
	constexpr int64_t n = 8192;               // production shape: 2^tree_depth
	PRG prg;
	vector<AuthValueFerret> pre(kk), base(n);
	prg.random_block(reinterpret_cast<block*>(pre.data()), kk);
	prg.random_block(reinterpret_cast<block*>(base.data()), n);
	block seed;
	prg.random_block(&seed, 1);

	Lpn<AuthValueFerret, 10> lpn((int)kk);

	auto fold = [&](auto m_tag, vector<AuthValueFerret>& out, block* sentinel) {
		out = base;
		PRG p(&seed);
		constexpr int M2 = decltype(m_tag)::value;
		lpn.compute_slice_as<M2>(p, out.data(), pre.data(), n);
		p.random_block(sentinel, 1);   // equal iff PRG consumption matched
	};

	vector<AuthValueFerret> ref, got;
	block sent_ref, sent_got;
	fold(integral_constant<int, 32>{}, ref, &sent_ref);

	bool ok = true;
	fold(integral_constant<int, 16>{}, got, &sent_got);
	ok = ok && blocks_equal(reinterpret_cast<block*>(ref.data()),
	                        reinterpret_cast<block*>(got.data()), n)
	        && cmpBlock(&sent_ref, &sent_got, 1);
	fold(integral_constant<int, 64>{}, got, &sent_got);
	ok = ok && blocks_equal(reinterpret_cast<block*>(ref.data()),
	                        reinterpret_cast<block*>(got.data()), n)
	        && cmpBlock(&sent_ref, &sent_got, 1);

	check("lpn batch M {16,32,64}: fold + PRG cursor", ok);
}

// ---- 4. COT chosen-input MITCCRH tile -------------------------------
// Reproduce COT::send's hashing pattern (H=2 pads per OT) and recv's
// (H=1) at BatchSize {4, 8, 16} over the same gid stream; the resulting
// pad sequences must be identical (keys are gid-bucketed, so the
// OT-index -> key map does not see the tile).
template <int B, int H>
static void run_mitccrh_pattern(block S, const block* in, int64_t n_ot,
                                block* out) {
	MITCCRH<B> m;
	m.setS(S);
	block pad[2 * B];
	for (int64_t i = 0; i < n_ot; i += B) {
		const int64_t take = std::min<int64_t>(B, n_ot - i);
		for (int64_t j = 0; j < take; ++j)
			for (int h = 0; h < H; ++h)
				pad[H * j + h] = in[H * (i + j) + h];
		m.template hash<B, H>(pad);
		memcpy(out + H * i, pad, sizeof(block) * (size_t)(H * take));
	}
}

template <int H>
static void test_mitccrh_tiles(const char* mode) {
	constexpr int64_t n_ot = 100;   // not a multiple of any tile: tail exercised
	PRG prg;
	BlockVec in(H * n_ot), ref(H * n_ot), got(H * n_ot);
	prg.random_block(in.data(), H * n_ot);
	block S;
	prg.random_block(&S, 1);

	run_mitccrh_pattern<8, H>(S, in.data(), n_ot, ref.data());
	bool ok = true;
	run_mitccrh_pattern<4, H>(S, in.data(), n_ot, got.data());
	ok = ok && blocks_equal(ref.data(), got.data(), H * n_ot);
	run_mitccrh_pattern<16, H>(S, in.data(), n_ot, got.data());
	ok = ok && blocks_equal(ref.data(), got.data(), H * n_ot);

	char tag[64];
	snprintf(tag, sizeof(tag), "mitccrh tile {4,8,16}: %s", mode);
	check(tag, ok);
}

int main() {
	test_sfvole_tiles<2>();
	test_sfvole_tiles<4>();
	test_sfvole_tiles<8>();
	test_cggm_tiles<false>("softspoken flavor (keep LSB)");
	test_cggm_tiles<true>("ferret flavor (clear LSB)");
	test_lpn_batches();
	test_mitccrh_tiles<2>("sender pattern (H=2)");
	test_mitccrh_tiles<1>("receiver pattern (H=1)");
	if (failures) {
		cout << failures << " invariance check(s) FAILED\n";
		return 1;
	}
	cout << "all tuning knobs output-invariant\n";
	return 0;
}
