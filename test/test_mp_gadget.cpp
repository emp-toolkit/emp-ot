// The sVOLE multi-point gadget (common/mp_gadget.h) for both secret-sum
// carriers, AuthValueFp and AuthValueF2k: the sender's traffic is captured and
// replayed into the receiver, so each tree runs in one process (semi-honest,
// so there is no check round trip). Checks that every tree yields the sVOLE
// relation, and that the receiver's punctured leaf is not the cGGM leaf
// itself: every cGGM level XORs to cggm_delta, which all trees share, so the
// receiver knows that leaf up to cggm_delta and the gadget must hash it.
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
	static F rand(PRG &prg) { uint64_t x; prg.random_data(&x, sizeof(x)); return mod(x); }
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

template <typename Ops>
static void check_carrier(const char *name) {
	using AV = typename Ops::AV;
	using F = typename Ops::F;
	constexpr int kTrees = 6, kDepth = 6;
	constexpr int64_t kLeaves = int64_t{1} << kDepth;

	block seed = makeBlock(0x5eed, 0x6ad9e7);
	PRG prg(&seed);
	// cggm_delta plays the inner Ferret's Δ: LSB 1, so a receiver base COT's
	// LSB is its choice bit. F2k's sVOLE Δ is that same block; Fp's is an
	// independent field element.
	block cggm_delta;
	prg.random_block(&cggm_delta, 1);
	cggm_delta = cggm_delta | makeBlock(0, 1);
	F delta;
	if constexpr (is_same_v<F, block>) delta = cggm_delta;
	else delta = Ops::rand(prg);

	// Base COTs: the sender holds q (LSB 0), the receiver q ^ b·cggm_delta.
	vector<block> base_s((size_t)kTrees * kDepth), base_r(base_s.size());
	for (size_t j = 0; j < base_s.size(); ++j) {
		block q;
		prg.random_block(&q, 1);
		q = q & makeBlock(~0ULL, ~1ULL);
		bool b;
		prg.random_bool(&b, 1);
		base_s[j] = q;
		base_r[j] = b ? (q ^ cggm_delta) : q;
	}
	// One VOLE pair per tree: the sender's key K, the receiver's (β, M = K + β·Δ).
	vector<F> K(kTrees), beta(kTrees), M(kTrees);
	for (int i = 0; i < kTrees; ++i) {
		K[i] = Ops::rand(prg);
		beta[i] = Ops::rand(prg);
		M[i] = Ops::mul_add(beta[i], delta, K[i]);
	}

	CaptureIO cap;
	MultiPointGadgetSender<AV> snd(kTrees, kDepth, &cap);
	snd.sid = makeBlock(0x51d, 1);
	snd.set_cggm_delta(cggm_delta);
	snd.set_delta(delta);
	snd.run_begin();
	vector<vector<AV>> v(kTrees, vector<AV>(kLeaves));
	for (int i = 0; i < kTrees; ++i)
		snd.run_next_tree(v[i].data(), base_s.data() + (size_t)i * kDepth, i, K[i]);

	ReplayIO rep(cap.bytes);
	MultiPointGadgetReceiver<AV> rcv(kTrees, kDepth, &rep);
	rcv.sid = snd.sid;
	rcv.run_begin();
	// Per tree on the wire: the kDepth corrections, then secret_sum.
	const size_t per_tree = kDepth * sizeof(block) + sizeof(F);
	bool relation = true, hashed = true;
	for (int i = 0; i < kTrees; ++i) {
		const block *base_i = base_r.data() + (size_t)i * kDepth;
		vector<AV> w(kLeaves);
		const uint32_t rev = rcv.run_next_tree(w.data(), base_i, i, M[i]);
		for (int64_t j = 0; j < kLeaves; ++j)
			if (j != (int64_t)rev) relation &= Ops::eq(w[j].mac, v[i][j].mac);
		relation &= Ops::eq(w[rev].mac, Ops::mul_add(beta[i], delta, v[i][rev].mac));

		// Rebuild the receiver's raw cGGM tree: its XOR is cggm_delta ^ the
		// punctured leaf, so the unhashed leaf would be known to it up to
		// cggm_delta. The sender's punctured mac must not be that leaf.
		block c[kDepth], k_recv[kDepth];
		memcpy(c, cap.bytes.data() + (size_t)i * per_tree, sizeof(c));
		uint32_t alpha = 0;
		for (int j = 0; j < kDepth; ++j) {
			alpha = (alpha << 1) | (getLSB(base_i[j]) ? 0u : 1u);
			k_recv[j] = base_i[j] ^ c[j];
		}
		vector<block> raw(kLeaves);
		const block known = cggm::eval_receiver<cggm::kTile, AV::kClearLeafLSB>(
		    kDepth, (int)alpha, k_recv, raw.data());
		hashed &= !Ops::eq(AV::auth_from_block(known ^ cggm_delta).mac, v[i][rev].mac);
	}
	const string tag = string(name);
	check((tag + ": every tree yields the sVOLE relation").c_str(), relation);
	check((tag + ": the punctured leaf is not the cGGM leaf").c_str(), hashed);
}

int main() {
	check_carrier<FpOps>("Fp");
	check_carrier<F2kOps>("F2k");
	if (failures) {
		cout << failures << " check(s) failed\n";
		return 1;
	}
	cout << "all mp_gadget checks passed\n";
	return 0;
}
