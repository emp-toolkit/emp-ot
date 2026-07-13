// `make tune` — per-machine sweep of emp-ot's LOCAL-class tuning knobs.
//
// Measures every candidate value of every registry knob at its PRODUCTION
// shape and emits emp-ot/tuning_local.h overriding exactly the knobs whose
// best candidate beats the shipped default by more than the measured noise
// band. The registry contains only LOCAL knobs (output- and wire-invariant;
// enforced by test_tuning_invariance) — AGREEMENT and SECURITY parameters
// have no override channel at all (see tuning.h).
//
// Every knob is a template parameter, so all candidates are instantiated
// side by side in this one binary and selected at runtime: one build, one
// run, no reconfigure loop.
//
// Methodology (docs/performance-tuning.md "Methodology requirements"):
//   - candidates measured INTERLEAVED across rounds (A,B,C,A,B,C...),
//     never back-to-back batches — machine state drifts;
//   - median across kRounds rounds per candidate;
//   - noise band = the default candidate's spread across rounds; a
//     candidate that does not beat the default by more than the band
//     (and at least 1%) is not emitted;
//   - a short cool-down between rounds on fanless (Apple) hosts.
//
// Usage:
//   emp-ot-tune                 # dry run: print the sweep + verdicts
//   emp-ot-tune --emit <path>   # also write <path> (make tune does this)
// Header-only usage on purpose: the tuner links no emp-ot objects, so
// the build can compile it first, run the sweep on an otherwise idle
// machine, and only then compile the library WITH the emitted overrides
// (see tools/CMakeLists.txt tune-auto).
#include "emp-ot/ot_extension/softspoken/sfvole_butterfly.h"
#include "emp-ot/ot_extension/ferret/ferret.h"   // AuthValueFerret (header-defined)
#include "emp-ot/common/cggm.h"
#include "emp-ot/common/lpn.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <utime.h>
#ifdef __APPLE__
#include <pthread.h>
#include <sys/sysctl.h>
#endif
using namespace emp;
using namespace std;

static constexpr int kRounds = 5;
static constexpr double kMinRunMs = 30.0;   // per timed window (x3 per measurement)
static constexpr double kMinWinFrac = 0.01; // never emit for <1%

// Pin the sweep to performance cores where the OS lets short bursts drift
// to efficiency cores (Apple): without this, medians taken on an
// efficiency core are wildly inflated and the noise band swallows every
// verdict.
static void pin_quality_of_service() {
#ifdef __APPLE__
	pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
}

// ---------------------------------------------------------------------
// Timing scaffolding
// ---------------------------------------------------------------------
static double time_once_ms(const function<void()>& fn) {
	auto t0 = chrono::steady_clock::now();
	fn();
	auto t1 = chrono::steady_clock::now();
	return chrono::duration<double, milli>(t1 - t0).count();
}

// ns per `units_per_call` work items. One "measurement" is the best of
// three consecutive timed windows (each >= kMinRunMs of work): the min
// discards intra-window scheduler/background hiccups, while cross-round
// drift is still visible to the caller's median over rounds.
static double measure_ns_per_unit(const function<void()>& fn, double units_per_call) {
	fn();  // warm
	double one = time_once_ms(fn);
	int reps = std::max(1, (int)(kMinRunMs / std::max(one, 1e-3)));
	double best_ms = 1e300;
	for (int w = 0; w < 3; ++w) {
		auto t0 = chrono::steady_clock::now();
		for (int r = 0; r < reps; ++r) fn();
		auto t1 = chrono::steady_clock::now();
		best_ms = std::min(best_ms,
		                   chrono::duration<double, milli>(t1 - t0).count());
	}
	return best_ms * 1e6 / (reps * units_per_call);
}

struct Candidate {
	string label;                // e.g. "T=16"
	string define;               // e.g. "#define EMP_TUNE_SFVOLE_TILE_K2 16"
	bool is_default = false;
	function<void()> fn;
	double units = 1.0;
	vector<double> rounds_ns;    // one entry per round
	double median_ns() const {
		auto v = rounds_ns;
		sort(v.begin(), v.end());
		return v[v.size() / 2];
	}
};

struct Verdict {
	string knob;
	string define;               // empty = keep default
	string note;
};

// Sweep one knob: interleave candidates across rounds, pick the winner,
// gate on the default's noise band. Returns the verdict + prints the table.
static Verdict sweep(const string& knob, vector<Candidate>& cands) {
	for (int r = 0; r < kRounds; ++r) {
		// rotate the starting candidate each round
		for (size_t i = 0; i < cands.size(); ++i) {
			auto& c = cands[(i + r) % cands.size()];
			c.rounds_ns.push_back(measure_ns_per_unit(c.fn, c.units));
		}
#ifdef __APPLE__
		this_thread::sleep_for(chrono::milliseconds(500));  // fanless cool-down
#endif
	}

	const Candidate* def = nullptr;
	const Candidate* best = nullptr;
	for (auto& c : cands) {
		if (c.is_default) def = &c;
		if (!best || c.median_ns() < best->median_ns()) best = &c;
	}
	// noise band: default candidate's interquartile-ish spread across
	// rounds (min/max dropped — a single descheduled round must not
	// swallow every verdict).
	auto dv = def->rounds_ns;
	sort(dv.begin(), dv.end());
	double band = (dv[dv.size() - 2] - dv[1]) / def->median_ns();

	printf("  %-24s", knob.c_str());
	for (auto& c : cands)
		printf("  %s=%.3f%s", c.label.c_str(), c.median_ns(),
		       c.is_default ? "*" : "");
	printf("   (noise %.1f%%)\n", band * 100);

	double win = 1.0 - best->median_ns() / def->median_ns();
	char note[160];
	if (best == def || win <= std::max(band, kMinWinFrac)) {
		snprintf(note, sizeof(note),
		         "%s: best %s within noise/threshold (win %.1f%%, band %.1f%%) -> default kept",
		         knob.c_str(), best->label.c_str(), win * 100, band * 100);
		return {knob, "", note};
	}
	snprintf(note, sizeof(note), "%s: %s beats default by %.1f%% (band %.1f%%) -> override",
	         knob.c_str(), best->label.c_str(), win * 100, band * 100);
	return {knob, best->define, note};
}

// ---------------------------------------------------------------------
// Knob 1: sfvole butterfly tile T (per k) — production chunk shape.
// ---------------------------------------------------------------------
template <int k, int T>
static Candidate sfvole_candidate(bool is_default) {
	constexpr int Q = 1 << k;
	constexpr int n = 128 / k;
	const int64_t bs = emp::tuning::softspoken_chunk_blocks<k>();
	auto leaves = make_shared<BlockVec>(size_t(n) * Q);
	auto planes = make_shared<BlockVec>(size_t(128) * bs);
	auto u      = make_shared<BlockVec>(bs);
	PRG prg;
	prg.random_block(leaves->data(), n * Q);
	auto key = make_shared<AES_KEY>();
	AES_set_encrypt_key(makeBlock(0, 42), key.get());

	Candidate c;
	c.label = "T=" + to_string(T);
	c.define = "#define EMP_TUNE_SFVOLE_TILE_K" + to_string(k) + " " + to_string(T);
	c.is_default = is_default;
	c.units = 128.0 * bs;   // OTs per call
	c.fn = [=]() {
		for (int i = 0; i < n; ++i)
			softspoken::sfvole_sender_butterfly<k, T>(
			    leaves->data() + i * Q, key.get(), 0, bs,
			    u->data(), planes->data() + (size_t)i * k * bs);
	};
	return c;
}

// ---------------------------------------------------------------------
// Knobs 2+3, scored JOINTLY: cGGM expand tile x LPN batch M on a
// Ferret-shaped composite — per "tree": build a depth-13 cGGM tree into
// an out slice, then LPN-fold that slice against the production 8 MiB
// pre table, exactly the per-tree sequence of Ferret::process_one_tree_.
// Isolated kernel sweeps mis-rank these two knobs on small shared
// caches (Graviton 2/3: the tile that wins with the tree alone loses
// once the LPN table co-resides), so the winner is the (tile, M) PAIR
// on the composite, and the emitted defines come from that pair.
// ---------------------------------------------------------------------
template <int Tile, int M>
static Candidate cggm_lpn_candidate(bool is_default) {
	constexpr int d = 13;
	constexpr int64_t slice = int64_t{1} << d;    // one tree of leaves
	constexpr int64_t kk = int64_t{1} << 19;      // b13: 8 MiB pre table
	constexpr int64_t out_n = int64_t{1} << 20;   // 16 MiB rotating out
	auto pre = make_shared<vector<AuthValueFerret>>(kk);
	auto out = make_shared<vector<AuthValueFerret>>(out_n);
	auto K0  = make_shared<BlockVec>(d);
	auto lpn = make_shared<Lpn<AuthValueFerret, 10>>((int)kk);
	auto prg = make_shared<PRG>();
	auto pos = make_shared<int64_t>(0);
	PRG fill;
	fill.random_block(reinterpret_cast<block*>(pre->data()), kk);
	block Delta;
	fill.random_block(&Delta, 1);

	Candidate c;
	c.label = "t" + to_string(Tile) + "/M" + to_string(M);
	// Emit only the components that differ from the shipped defaults, so
	// a winning pair that keeps one default half doesn't restate it.
	if (Tile != tuning::cggm_tile_arch_default())
		c.define = "#define EMP_TUNE_CGGM_TILE " + to_string(Tile);
	if (M != 32) {
		if (!c.define.empty()) c.define += "\n";
		c.define += "#define EMP_TUNE_LPN_BATCH_M " + to_string(M);
	}
	c.is_default = is_default;
	c.units = double(slice);   // ns per produced leaf (tree + fold)
	c.fn = [=]() {
		block* lv = reinterpret_cast<block*>(out->data() + *pos);
		block root;
		prg->random_block(&root, 1);
		cggm::build_sender<Tile, true>(d, Delta, root, lv, K0->data());
		lpn->compute_slice_as<M>(*prg, out->data() + *pos, pre->data(), slice);
		*pos = (*pos + slice) % (out_n - slice);
	};
	return c;
}

// ---------------------------------------------------------------------
// Knob 4: COT chosen-input MITCCRH tile — sender pattern (2 pads/OT).
// ---------------------------------------------------------------------
template <int B>
static Candidate cot_tile_candidate(bool is_default) {
	constexpr int64_t n_ot = 4096;
	auto data = make_shared<BlockVec>(2 * n_ot);
	PRG prg;
	prg.random_block(data->data(), 2 * n_ot);
	block S;
	prg.random_block(&S, 1);

	Candidate c;
	c.label = "tile=" + to_string(B);
	c.define = "#define EMP_TUNE_COT_TILE " + to_string(B);
	c.is_default = is_default;
	c.units = double(n_ot);
	c.fn = [=]() {
		MITCCRH<B> m;
		m.setS(S);
		block pad[2 * B];
		for (int64_t i = 0; i < n_ot; i += B) {
			memcpy(pad, data->data() + 2 * i, sizeof(block) * 2 * B);
			m.template hash<B, 2>(pad);
		}
	};
	return c;
}

// ---------------------------------------------------------------------
static string cpu_brand() {
	char buf[256] = {0};
#ifdef __APPLE__
	size_t len = sizeof(buf) - 1;
	if (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) != 0)
		buf[0] = 0;
#else
	if (FILE* f = fopen("/proc/cpuinfo", "r")) {
		char line[512];
		while (fgets(line, sizeof(line), f)) {
			if (strncmp(line, "model name", 10) == 0) {
				const char* colon = strchr(line, ':');
				if (colon) snprintf(buf, sizeof(buf), "%s", colon + 1);
				break;
			}
		}
		fclose(f);
	}
#endif
	string s(buf);
	while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
	size_t start = s.find_first_not_of(' ');
	return start == string::npos ? "unknown" : s.substr(start);
}

int main(int argc, char** argv) {
	string emit_path;
	bool only_if_absent = false;
	for (int i = 1; i < argc; ++i) {
		if (string(argv[i]) == "--emit" && i + 1 < argc) emit_path = argv[i + 1];
		if (string(argv[i]) == "--emit-if-absent" && i + 1 < argc) {
			emit_path = argv[i + 1];
			only_if_absent = true;
		}
	}
	// Auto-tune mode (`--emit-if-absent`, used by the Release build hook):
	// an existing file wins — tuning is once per machine, re-tune is the
	// explicit `tune` target or `tune-clean` + rebuild.
	if (only_if_absent && !emit_path.empty()) {
		if (ifstream(emit_path).good()) {
			printf("emp-ot tune: %s exists — keeping it (run `tune-clean` or "
			       "the `tune` target to re-sweep)\n", emit_path.c_str());
			return 0;
		}
	}

	printf("emp-ot tune: %d rounds, interleaved, median-scored; default marked *\n",
	       kRounds);
	printf("host: %s\n\n", cpu_brand().c_str());

	pin_quality_of_service();
	// Sustained warmup so frequency/scheduler state reflects a real
	// workload before the first measurement (fanless parts ramp slowly;
	// short bursts otherwise land on efficiency cores).
	{
		volatile uint64_t sink = 0;
		auto t0 = chrono::steady_clock::now();
		while (chrono::duration<double>(chrono::steady_clock::now() - t0).count() < 1.0)
			for (int i = 0; i < 1000; ++i) sink += i * 2654435761u;
	}

	vector<Verdict> verdicts;

	// k=2 and k=4 tiles: swept for the record but NEVER auto-emitted.
	// At these k the wall time is dominated by two-party scheduling (the
	// tile changes each party's chunk duration, flipping a sleep/wake
	// rendezvous at the per-chunk recv), so kernel-level rankings do not
	// transfer to e2e — measured misses in BOTH directions across Intel,
	// AMD, and Graviton. Set EMP_TUNE_SFVOLE_TILE_K{2,4} manually after
	// your own two-party A/B if your deployment is k<=4 on a fast link.
	{
		vector<Candidate> c = {sfvole_candidate<2, 8>(true),
		                       sfvole_candidate<2, 16>(false),
		                       sfvole_candidate<2, 32>(false)};
		Verdict v = sweep("sfvole_tile k=2 (ns/OT)", c);
		if (!v.define.empty()) {
			v.note += "  [informational only -- k=2 tile is not auto-emitted;"
			          " kernel rankings do not transfer to e2e]";
			v.define.clear();
		}
		verdicts.push_back(v);
	}
	{
		vector<Candidate> c = {sfvole_candidate<4, 8>(true),
		                       sfvole_candidate<4, 16>(false),
		                       sfvole_candidate<4, 32>(false)};
		Verdict v = sweep("sfvole_tile k=4 (ns/OT)", c);
		if (!v.define.empty()) {
			v.note += "  [informational only -- k=4 tile is not auto-emitted;"
			          " kernel rankings do not transfer to e2e]";
			v.define.clear();
		}
		verdicts.push_back(v);
	}
	{
		vector<Candidate> c = {sfvole_candidate<8, 8>(true),
		                       sfvole_candidate<8, 16>(false),
		                       sfvole_candidate<8, 32>(false)};
		verdicts.push_back(sweep("sfvole_tile k=8 (ns/OT)", c));
	}
	{
		// Joint cggm_tile x lpn_batch_m on the Ferret-shaped composite;
		// the default pair is (arch default tile, M=32).
		constexpr int def = tuning::cggm_tile_arch_default();
		vector<Candidate> c;
		auto add_row = [&]<int Tile>() {
			c.push_back(cggm_lpn_candidate<Tile, 16>(false));
			c.push_back(cggm_lpn_candidate<Tile, 32>(Tile == def));
			c.push_back(cggm_lpn_candidate<Tile, 64>(false));
		};
		add_row.template operator()<4>();
		add_row.template operator()<8>();
		add_row.template operator()<16>();
		add_row.template operator()<32>();
		add_row.template operator()<64>();
		verdicts.push_back(sweep("cggm_tile x lpn_M (ns/leaf, tree+fold)", c));
	}
	{
		vector<Candidate> c = {cot_tile_candidate<8>(true),
		                       cot_tile_candidate<4>(false),
		                       cot_tile_candidate<16>(false)};
		verdicts.push_back(sweep("cot_tile (ns/OT, H=2)", c));
	}

	printf("\n");
	int n_override = 0;
	for (auto& v : verdicts) {
		printf("[tune] %s\n", v.note.c_str());
		if (!v.define.empty()) ++n_override;
	}

	if (emit_path.empty()) {
		printf("\n(dry run; pass --emit <path> or use `make tune` to write tuning_local.h)\n");
		return 0;
	}

	time_t now = time(nullptr);
	char date[32];
	strftime(date, sizeof(date), "%Y-%m-%d", localtime(&now));

	ofstream f(emit_path);
	if (!f) {
		fprintf(stderr, "cannot write %s\n", emit_path.c_str());
		return 1;
	}
	f << "// GENERATED by emp-ot-tune (`make tune`) " << date << " -- do not commit.\n";
	f << "// host: " << cpu_brand() << "\n";
	f << "// Overrides LOCAL-class knobs only (see tuning.h); delete this file\n";
	f << "// or run `make tune-clean` to return to the shipped defaults.\n";
	for (auto& v : verdicts) f << "// " << v.note << "\n";
	f << "\n";
	for (auto& v : verdicts)
		if (!v.define.empty()) f << v.define << "\n";
	f.close();
	printf("\nwrote %s (%d override%s)\n", emit_path.c_str(), n_override,
	       n_override == 1 ? "" : "s");

	// The include of tuning_local.h is behind __has_include, so compiler
	// depfiles recorded no dependency on it while it didn't exist — a
	// plain rebuild would NOT pick the new file up. Touch tuning.h (its
	// includer, which every consumer depends on) so the next compile of
	// every affected TU is forced. Done here, not in the CMake target,
	// so it happens exactly when the file is (re)written and never on
	// no-op runs.
	string tuning_h = emit_path;
	size_t slash = tuning_h.find_last_of('/');
	tuning_h = (slash == string::npos ? string("") : tuning_h.substr(0, slash + 1))
	           + "tuning.h";
	if (utime(tuning_h.c_str(), nullptr) == 0)
		printf("touched %s -- rebuild applies the overrides\n", tuning_h.c_str());
	else
		printf("WARNING: could not touch %s -- run `touch` on it manually or "
		       "the rebuild will NOT apply the overrides\n", tuning_h.c_str());
	return 0;
}
