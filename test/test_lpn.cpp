// Lpn<AuthValue, d> with GF(2^128) coefficients (common/lpn.h): the fold
// against a one-gfmul-per-entry reference of the documented stream layout,
// the Δ-holder's mac-only fold, the VOLE relation across both parties' folds,
// and the PRG accounting that slicing relies on.
//
// Single-process (no IO / no `run`).
#include "emp-ot/emp-ot.h"
#include "emp-ot/common/lpn.h"
#include <cstring>
#include <iostream>
#include <vector>
using namespace emp;
using namespace std;

static int failures = 0;

static void check(const char *tag, bool ok) {
	cout << (ok ? "[OK]   " : "[FAIL] ") << tag << "\n";
	if (!ok) ++failures;
}

static constexpr int kD = 10;
using F2kVec = vector<AuthValueF2k>;

static block gf(block a, block b) {
	block r;
	gfmul(a, b, &r);
	return r;
}

static bool same(const F2kVec &a, const F2kVec &b) {
	return a.size() == b.size()
	    && memcmp(a.data(), b.data(), sizeof(AuthValueF2k) * a.size()) == 0;
}

static F2kVec random_values(PRG &prg, int64_t n) {
	F2kVec v((size_t)n);
	prg.random_block(reinterpret_cast<block *>(v.data()), 2 * n);
	return v;
}

// The stream layout lpn.h documents, one gfmul per entry: each group of four
// rows draws d blocks of indices (row j's l-th index is uint32 word j·d + l)
// and then 4·d coefficients (a_{j,l} is block 4·l + j).
static void ref_fold(PRG &prg, int64_t k, F2kVec &out, const F2kVec &pre,
                     bool fold_val) {
	const int64_t n = (int64_t)out.size();
	for (int64_t g = 0; 4 * g < n; ++g) {
		block rnd[5 * kD];
		prg.random_block(rnd, 5 * kD);
		const uint32_t *w = reinterpret_cast<const uint32_t *>(rnd);
		const block *coef = rnd + kD;
		for (int j = 0; j < 4 && 4 * g + j < n; ++j) {
			AuthValueF2k &o = out[(size_t)(4 * g + j)];
			for (int l = 0; l < kD; ++l) {
				const AuthValueF2k &e = pre[w[j * kD + l] & (k - 1)];
				o.mac = o.mac ^ gf(coef[4 * l + j], e.mac);
				if (fold_val) o.val = o.val ^ gf(coef[4 * l + j], e.val);
			}
		}
	}
}

// compute_slice against the reference, at whole and partial groups, plus the
// PRG cursor against blocks_per_chunk.
static void test_reference() {
	constexpr int64_t k = 1 << 12;
	PRG prg;
	const F2kVec pre = random_values(prg, k);
	block seed;
	prg.random_block(&seed, 1);
	bool ok = true;
	for (int64_t n : {int64_t{4096}, int64_t{4096 + 3}, int64_t{6}, int64_t{1}}) {
		const F2kVec base = random_values(prg, n);
		for (bool fold_val : {true, false}) {
			Lpn<AuthValueF2k, kD> lpn((int)k);
			if (!fold_val) lpn.fold_mac_only();
			F2kVec got = base, want = base;
			PRG p(&seed), q(&seed);
			lpn.compute_slice(p, got.data(), pre.data(), n);
			ref_fold(q, k, want, pre, fold_val);
			ok = ok && same(got, want) && p.position() == q.position()
			        && p.position() == lpn.blocks_per_chunk(n);
		}
	}
	check("f2k fold == per-entry gfmul reference (whole + partial groups)", ok);
}

// The serial path (instance PRG) carries its stream across calls: two
// consecutive slices equal one reference fold over their concatenation.
static void test_serial_slices() {
	constexpr int64_t k = 1 << 12, n = 4096;
	PRG prg;
	const F2kVec pre = random_values(prg, k);
	const F2kVec base = random_values(prg, 2 * n);
	block seed;
	prg.random_block(&seed, 1);
	Lpn<AuthValueF2k, kD> lpn((int)k);
	lpn.reseed(seed);
	F2kVec got = base, want = base;
	lpn.compute_slice(got.data(), pre.data(), n);
	lpn.compute_slice(got.data() + n, pre.data(), n);
	PRG q(&seed);
	ref_fold(q, k, want, pre, /*fold_val=*/true);
	check("f2k serial slices continue one stream", same(got, want));
}

// Both parties fold their own halves with the same matrix: the receiver folds
// (val, mac), the Δ-holder folds its keys mac-only. mac ^ key = val·Δ must
// hold on every output, and the Δ-holder's val must stay 0.
static void test_vole_relation() {
	constexpr int64_t k = 1 << 12, n = 4096 + 2;
	PRG prg;
	block delta;
	prg.random_block(&delta, 1);
	auto correlate = [&](const F2kVec &recv) {
		F2kVec send(recv.size());
		for (size_t i = 0; i < recv.size(); ++i)
			send[i] = AuthValueF2k{zero_block, recv[i].mac ^ gf(recv[i].val, delta)};
		return send;
	};
	const F2kVec pre_r = random_values(prg, k), pre_s = correlate(pre_r);
	F2kVec out_r = random_values(prg, n), out_s = correlate(out_r);
	block seed;
	prg.random_block(&seed, 1);
	Lpn<AuthValueF2k, kD> lpn_r((int)k), lpn_s((int)k);
	lpn_s.fold_mac_only();
	PRG pr(&seed), ps(&seed);
	lpn_r.compute_slice(pr, out_r.data(), pre_r.data(), n);
	lpn_s.compute_slice(ps, out_s.data(), pre_s.data(), n);
	bool ok = true;
	for (int64_t i = 0; i < n; ++i) {
		ok = ok && cmpBlock(&out_s[i].val, &zero_block, 1);
		const block lhs = out_r[i].mac ^ out_s[i].mac;
		const block rhs = gf(out_r[i].val, delta);
		ok = ok && cmpBlock(&lhs, &rhs, 1);
	}
	check("f2k receiver + mac-only Δ-holder folds keep mac ^ key = val·Δ", ok);
}

int main() {
	test_reference();
	test_serial_slices();
	test_vole_relation();
	if (failures) {
		cout << failures << " check(s) failed\n";
		return 1;
	}
	cout << "all checks passed\n";
	return 0;
}
