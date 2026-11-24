// The sVOLE multi-point gadget (common/mp_gadget.h) for both secret-sum
// carriers, AuthValueFp and AuthValueF2k: the sender's traffic is captured and
// replayed into the receiver, so each tree runs in one process (semi-honest,
// so there is no check round trip). Checks that every tree yields the sVOLE
// relation, and that the receiver's punctured leaf is not the cGGM leaf
// itself: every cGGM level XORs to cggm_delta, which all trees share, so the
// receiver knows that leaf up to cggm_delta and the gadget must hash it. For
// F_p it also checks the property that hashing buys: the linear system a
// receiver can form from its punctured leaves, in Δ and the low 64 bits of
// cggm_delta, has no solution. Those checks read the receiver's raw cGGM tree,
// which the test rebuilds under the key it expects the gadget to use; a check
// ties that tree to the gadget's leaves, and the trees run in round 1, so the
// gadget's round enters the key. It also checks cggm::TreeKeys on its own.
//
// Single-process (no IO / no `run`).
#include "emp-ot/emp-ot.h"
#include "emp-ot/svole/f2k_vole.h"
#include "emp-ot/svole/fp_vole.h"
#include <cstring>
#include <iostream>
#include <type_traits>
#include <vector>
using namespace emp;
using namespace std;

static int failures = 0;

static void check(const char *tag, bool ok) {
	cout << (ok ? "[OK]   " : "[FAIL] ") << tag << "\n";
	if (!ok) ++failures;
}

// Records the sender's traffic. A semi-honest sender only sends.
class CaptureIO final : public IOChannel {
public:
	vector<uint8_t> bytes;
	void send_data_internal(const void *p, int64_t n) override {
		const uint8_t *b = static_cast<const uint8_t *>(p);
		bytes.insert(bytes.end(), b, b + n);
	}
	void recv_data_internal(void *, int64_t) override {
		error("CaptureIO: unexpected receive");
	}
};

// Replays captured bytes to the receiver, which only receives.
class ReplayIO final : public IOChannel {
public:
	explicit ReplayIO(const vector<uint8_t> &bytes) : bytes_(bytes) {}
	void send_data_internal(const void *, int64_t) override {}
	void recv_data_internal(void *out, int64_t n) override {
		expecting(n >= 0 && pos_ + n <= (int64_t)bytes_.size(),
		          "ReplayIO: out of input");
		memcpy(out, bytes_.data() + pos_, (size_t)n);
		pos_ += n;
	}

private:
	const vector<uint8_t> &bytes_;
	int64_t pos_ = 0;
};

// The field operations the test needs, per carrier.
struct FpOps {
	using AV = AuthValueFp;
	using F = uint64_t;
	static F rand(PRG &prg) { uint64_t x; prg.random_data_unaligned(&x, sizeof(x)); return mod(x); }
	static F mul_add(F a, F b, F c) { return add_mod(mult_mod(a, b), c); }
	static bool eq(F a, F b) { return a == b; }
};
struct F2kOps {
	using AV = AuthValueF2k;
	using F = block;
	static F rand(PRG &prg) { block x; prg.random_block(&x, 1); return x; }
	static F mul_add(F a, F b, F c) { block r; gfmul(a, b, &r); return r ^ c; }
	static bool eq(F a, F b) { return cmpBlock(&a, &b, 1); }
};

// One semi-honest run of `trees` trees on both sides, in the gadget's second
// round, with what the test needs from each tree: both parties' leaves, the
// punctured slot, the receiver's point value β, and the receiver's raw cGGM
// tree (punctured slot zero) and the XOR of its leaves.
template <typename Ops>
struct Run {
	using AV = typename Ops::AV;
	using F = typename Ops::F;
	block cggm_delta;
	F delta;
	vector<F> beta;
	vector<vector<AV>> v, w;   // sender's and receiver's leaves
	vector<uint32_t> rev;      // the punctured slot
	vector<vector<block>> raw; // the receiver's raw cGGM tree
	vector<block> known;       // XOR of the receiver's raw cGGM leaves
	block gadget_sid;
	uint64_t round;
};

template <typename Ops>
static Run<Ops> run_trees(int trees, int depth) {
	using AV = typename Ops::AV;
	using F = typename Ops::F;
	const int64_t leaves = int64_t{1} << depth;
	Run<Ops> r;

	block seed = makeBlock(0x5eed, 0x6ad9e7);
	PRG prg(&seed);
	// cggm_delta plays the inner Ferret's Δ: LSB 1, so a receiver base COT's
	// LSB is its choice bit. F2k's sVOLE Δ is that same block; Fp's is an
	// independent field element.
	prg.random_block(&r.cggm_delta, 1);
	r.cggm_delta = r.cggm_delta | makeBlock(0, 1);
	if constexpr (is_same_v<F, block>) r.delta = r.cggm_delta;
	else r.delta = Ops::rand(prg);

	// Base COTs: the sender holds q (LSB 0), the receiver q ^ b·cggm_delta.
	vector<block> base_s((size_t)trees * depth), base_r(base_s.size());
	for (size_t j = 0; j < base_s.size(); ++j) {
		block q;
		prg.random_block(&q, 1);
		q = q & makeBlock(~0ULL, ~1ULL);
		bool b;
		prg.random_bool(&b, 1);
		base_s[j] = q;
		base_r[j] = b ? (q ^ r.cggm_delta) : q;
	}
	// One VOLE pair per tree: the sender's key K, the receiver's (β, M = K + β·Δ).
	vector<F> K(trees), M(trees);
	r.beta.resize(trees);
	for (int i = 0; i < trees; ++i) {
		K[i] = Ops::rand(prg);
		r.beta[i] = Ops::rand(prg);
		M[i] = Ops::mul_add(r.beta[i], r.delta, K[i]);
	}

	r.gadget_sid = makeBlock(0x51d, 1);
	r.round = 1;   // an empty round 0 first, so the round enters the key
	CaptureIO cap;
	MultiPointGadgetSender<AV> snd(trees, depth, &cap);
	snd.set_sid(r.gadget_sid);
	snd.set_cggm_delta(r.cggm_delta);
	snd.set_delta(r.delta);
	for (uint64_t g = 0; g <= r.round; ++g) snd.run_begin();
	r.v.assign(trees, vector<AV>(leaves));
	for (int i = 0; i < trees; ++i)
		snd.run_next_tree(r.v[i].data(), base_s.data() + (size_t)i * depth, i, K[i]);

	ReplayIO rep(cap.bytes);
	MultiPointGadgetReceiver<AV> rcv(trees, depth, &rep);
	rcv.set_sid(r.gadget_sid);
	for (uint64_t g = 0; g <= r.round; ++g) rcv.run_begin();
	cggm::TreeKeys keys;   // the gadget's tree keys, as the test expects them
	keys.reset(r.gadget_sid);
	// Per tree on the wire: the corrections, then secret_sum.
	const size_t per_tree = (size_t)depth * sizeof(block) + sizeof(F);
	r.w.assign(trees, vector<AV>(leaves));
	for (int i = 0; i < trees; ++i) {
		const block *base_i = base_r.data() + (size_t)i * depth;
		r.rev.push_back(rcv.run_next_tree(r.w[i].data(), base_i, i, M[i]));
		// The receiver's raw cGGM tree, rebuilt from its base COTs and the
		// corrections it received.
		vector<block> c(depth), k_recv(depth), raw(leaves);
		memcpy(c.data(), cap.bytes.data() + (size_t)i * per_tree, depth * sizeof(block));
		uint32_t alpha = 0;
		for (int j = 0; j < depth; ++j) {
			alpha = (alpha << 1) | (getLSB(base_i[j]) ? 0u : 1u);
			k_recv[j] = base_i[j] ^ c[j];
		}
		r.known.push_back(cggm::eval_receiver<cggm::kTile, AV::kClearLeafLSB>(
		    depth, (int)alpha, k_recv.data(), raw.data(), keys.key(r.round, i)));
		r.raw.push_back(raw);
	}
	return r;
}

template <typename Ops>
static void check_carrier(const char *name) {
	using AV = typename Ops::AV;
	const int trees = 6, depth = 6;
	const Run<Ops> r = run_trees<Ops>(trees, depth);
	bool relation = true, hashed = true, same_tree = true;
	// The raw trees the test rebuilt, hashed with the gadget's leaf-hash stream
	// for the round, must give the receiver's leaves: the test keyed them as the
	// gadget did, so the checks below read the gadget's actual trees.
	MITCCRH<> leaf_hash;
	leaf_hash.setS(leaf_hash_start(r.gadget_sid, r.round));
	for (int i = 0; i < trees; ++i) {
		const uint32_t rev = r.rev[i];
		vector<block> hashed_raw = r.raw[i];
		hash_leaves(leaf_hash, hashed_raw.data(), (int64_t)hashed_raw.size());
		for (size_t j = 0; j < hashed_raw.size(); ++j)
			if (j != rev)
				same_tree &= Ops::eq(AV::auth_from_block(hashed_raw[j]).mac, r.w[i][j].mac);
		for (size_t j = 0; j < r.w[i].size(); ++j)
			if (j != rev) relation &= Ops::eq(r.w[i][j].mac, r.v[i][j].mac);
		relation &= Ops::eq(r.w[i][rev].mac,
		                    Ops::mul_add(r.beta[i], r.delta, r.v[i][rev].mac));
		// The raw tree XORs to cggm_delta ^ the punctured leaf, so the unhashed
		// leaf is known to the receiver up to cggm_delta. The sender's
		// punctured mac must not be that leaf.
		hashed &= !Ops::eq(AV::auth_from_block(r.known[i] ^ r.cggm_delta).mac,
		                   r.v[i][rev].mac);
	}
	const string tag = string(name);
	check((tag + ": the test's raw trees are the gadget's trees").c_str(), same_tree);
	check((tag + ": every tree yields the sVOLE relation").c_str(), relation);
	check((tag + ": the punctured leaf is not the cGGM leaf").c_str(), hashed);
}

static uint64_t fp_sub(uint64_t a, uint64_t b) { return a >= b ? a - b : a + PR - b; }
static uint64_t fp_inv(uint64_t a) {
	uint64_t r = 1, e = PR - 2;
	for (; e; e >>= 1, a = mult_mod(a, a))
		if (e & 1) r = mult_mod(r, a);
	return r;
}

// If the receiver's punctured mac were mod(low64(cggm leaf)) + β·Δ, each tree
// would give it one F_p-linear equation in Δ and the low 64 bits d_b of
// cggm_delta: the leaf is known ^ cggm_delta, and
// Y ^ D = Y + Σ_b 2^b (1 - 2·y_b)·d_b over the integers (Y = low64(known)).
// 80 trees give 80 equations in 65 unknowns. With the leaves hashed the
// system must have no solution.
static void check_fp_linear_system() {
	const int trees = 80, depth = 4, C = 65;
	const Run<FpOps> r = run_trees<FpOps>(trees, depth);
	vector<vector<uint64_t>> A(trees, vector<uint64_t>(C + 1));
	for (int i = 0; i < trees; ++i) {
		uint64_t y;
		memcpy(&y, &r.known[i], sizeof(y));
		for (int b = 0; b < 64; ++b) {
			const uint64_t pw = mod(uint64_t{1} << b);
			A[i][b] = ((y >> b) & 1) ? fp_sub(0, pw) : pw;
		}
		A[i][64] = r.beta[i];
		A[i][C] = fp_sub(r.w[i][r.rev[i]].mac, mod(y));
	}
	// Gauss-Jordan; then count the rows left as 0 = c with c != 0.
	int rank = 0;
	for (int c = 0; c < C && rank < trees; ++c) {
		int piv = -1;
		for (int i = rank; i < trees; ++i)
			if (A[i][c] != 0) { piv = i; break; }
		if (piv < 0) continue;
		swap(A[piv], A[rank]);
		const uint64_t inv = fp_inv(A[rank][c]);
		for (int k = c; k <= C; ++k) A[rank][k] = mult_mod(A[rank][k], inv);
		for (int i = 0; i < trees; ++i) {
			if (i == rank || A[i][c] == 0) continue;
			const uint64_t f = A[i][c];
			for (int k = c; k <= C; ++k)
				A[i][k] = fp_sub(A[i][k], mult_mod(f, A[rank][k]));
		}
		++rank;
	}
	int inconsistent = 0;
	for (int i = rank; i < trees; ++i) inconsistent += A[i][C] != 0;
	check("Fp: the receiver's linear system in Δ has no solution",
	      rank == C && inconsistent > 0);
}

// The cGGM tree keys (cggm::TreeKeys): tree (round, index) is keyed by
// SessionID::derive()'s step at that index, every (round, index) gets its own
// key, and the key reaches the hash, so one root and Δ give a different tree
// under another tree's key. A receiver evaluating under the sender's key
// rebuilds the sender's tree; the protocol tests cover that end to end.
static void check_tree_keys() {
	const block g = makeBlock(0x7ee5, 0x6e75);
	cggm::TreeKeys keys;
	keys.reset(g);

	SessionID parent(g);
	bool derive_step = true;
	for (uint64_t i = 0; i < 4; ++i) {
		const block want = parent.derive().value();
		const block got = keys.key(0, i);
		derive_step &= cmpBlock(&want, &got, 1);
	}
	check("tree keys: key(0, i) is the id's i-th derive() child", derive_step);

	const block k00 = keys.key(0, 0), k01 = keys.key(0, 1), k10 = keys.key(1, 0);
	check("tree keys: distinct per (round, index)",
	      !cmpBlock(&k00, &k01, 1) && !cmpBlock(&k00, &k10, 1) &&
	          !cmpBlock(&k01, &k10, 1));

	const int d = 6;
	const int64_t leaves = int64_t{1} << d;
	block Delta = makeBlock(0xde17a, 1), root = makeBlock(0x5007, 0x5eed);
	vector<block> a(leaves), b(leaves), ka(d), kb(d);
	cggm::build_sender(d, Delta, root, a.data(), ka.data(), k00);
	cggm::build_sender(d, Delta, root, b.data(), kb.data(), k01);
	bool all_differ = true;
	for (int64_t j = 0; j < leaves; ++j) all_differ &= !cmpBlock(&a[j], &b[j], 1);
	// Level 1 is (root, root ^ Δ) under any key; every hashed level differs.
	bool sums_differ = true;
	for (int i = 1; i < d; ++i) sums_differ &= !cmpBlock(&ka[i], &kb[i], 1);
	check("tree keys: another tree's key gives another tree",
	      all_differ && sums_differ);
}

int main() {
	check_tree_keys();
	check_carrier<FpOps>("Fp");
	check_carrier<F2kOps>("F2k");
	check_fp_linear_system();
	if (failures) {
		cout << failures << " check(s) failed\n";
		return 1;
	}
	cout << "all mp_gadget checks passed\n";
	return 0;
}
