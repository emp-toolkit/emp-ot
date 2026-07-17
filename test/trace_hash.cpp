// Per-protocol wire-trace hash. For each OT / sVOLE protocol in the
// repo, opens a fresh NetIO + Fiat-Shamir, runs the protocol, prints
// the FS send/recv digests, then tears down the NetIO. A fresh
// connection per protocol gives every protocol independent state and
// independent FS transcripts — the hashes depend only on that one
// protocol's wire bytes.
//
// Refactor verification:
//   EMP_TEST_MODE=1 ./run ./build/trace_hash > before.txt
//   <apply refactor>
//   EMP_TEST_MODE=1 ./run ./build/trace_hash > after.txt
//   diff before.txt after.txt    # must be empty for wire-equivalence
//
// The runner script invokes the binary on both parties; each party's
// stdout is its own table. A reproducible-byte refactor leaves both
// tables byte-identical to the pre-refactor capture.

#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include "test/test.h"
#include <iomanip>
#include <sstream>
using namespace emp;
using namespace std;

// Open a fresh NetIO + FS, run `body(io)`, snapshot per-direction
// digests, print (ALICE only — the BOB-side hashes are the inverse
// pair and would just produce a duplicate table). Each call uses
// the same port: the previous NetIO is destructed (TCP closed)
// before the next is constructed, so successive calls re-handshake
// on the same port.
template <typename Body>
static void measure(int party, int port, const string& name,
                    bool send_first, Body&& body) {
    // Start every protocol from the same deterministic seed state, so its
    // trace hash is independent of which protocols ran before it. The table
    // is order-independent: a protocol can be added or reordered without
    // disturbing the others' digests. (No-op effect outside EMP_TEST_MODE.)
    reset_test_seed_counter();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);
    io->enable_fs(send_first);
    body(io.get());
    io->flush();
    if (party == ALICE) {
        // First 8 B per direction — enough to spot any change, keeps the table tight.
        block sd = io->get_send_digest(), rd = io->get_recv_digest();
        cout << left << setw(22) << name
             << " send=" << to_hex(&sd, 8)
             << " recv=" << to_hex(&rd, 8) << "\n";
    }
}

// RCOT runner. Constructed inside body() so each protocol gets a
// fresh OT object too (just like a real caller would).
template <typename Make>
static void run_rcot(NetIO* io, int party, int64_t length, Make make,
                     bool malicious) {
    auto ot = make(io, malicious);
    block* b = new block[length];
    ot->rcot(b, length);
    delete[] b;
}

// sVOLE runner: single-role extend(). The caller may override the
// carrier-provided default Δ on the holder before bootstrap.
template <typename SVole, typename DeltaSetter>
static void run_svole(NetIO* io, int party, int64_t length,
                      bool malicious, DeltaSetter set_holder_delta) {
    SVole sv(party, io, malicious);
    if (sv.is_delta_holder()) set_holder_delta(sv);
    using AV = typename SVole::AuthValue;
    AV* b = new AV[length];
    sv.run(b, length);
    delete[] b;
}

// Base-OT runner: chosen-input send/recv. Inputs are deterministic.
template <typename BaseOT>
static void run_base_ot(NetIO* io, int party, int64_t length) {
    BaseOT ot(io);
    if (party == ALICE) {
        std::vector<block> m0(length), m1(length);
        for (int64_t i = 0; i < length; ++i) {
            m0[i] = makeBlock(0, i);
            m1[i] = makeBlock(1, i);
        }
        ot.send(m0.data(), m1.data(), length);
    } else {
        std::vector<block> out(length);
        std::vector<unsigned char> ch_buf(length);
        for (int64_t i = 0; i < length; ++i) ch_buf[i] = (i & 1) ? 1 : 0;
        ot.recv(out.data(), reinterpret_cast<const bool*>(ch_buf.data()),
                length);
    }
}

int main(int argc, char** argv) {
    int port, party;
    if (argc < 2) {
        cerr << "usage: trace_hash <party 1|2> <port>\n";
        return 1;
    }
    party = parse_party(argv);
    port = peer_port();
    if (!is_test_mode())
        cerr << "trace_hash: EMP_TEST_MODE not set; hashes "
                "will be non-deterministic\n";

    if (party == ALICE)
        cout << "# trace hashes (send / recv per protocol; alice view)\n";

    // Lengths: base OTs are slow per OT (public-key crypto), so 128
    // is plenty. RCOT stress is large enough to trigger Ferret's
    // per-round rollover (~1M RCOTs for b11) so the chi-fold path is
    // exercised; small enough that IKNP/SoftSpoken finish quickly.
    // Debug builds use ~16× smaller lengths so the suite finishes
    // in a reasonable CI window; wire-trace baseline in README.md is
    // Release-mode and won't match Debug-mode hashes.
    const int64_t base_len  = 128;
#ifdef NDEBUG
    const int64_t rcot_len  = (1LL << 22) + 101;
    const int64_t svole_len = 1 << 20;
#else
    const int64_t rcot_len  = (1LL << 18) + 101;
    const int64_t svole_len = 1 << 16;
#endif

    // Ferret and SilentFerret send byte-identical traffic only over a WHOLE
    // number of SilentFerret rounds: with a partial tail, SilentFerret
    // over-ships that round's corrections (a bounded effect, not a divergence).
    // Run both at a whole-rounds length so their rows match exactly -- the
    // table then *guards* the Ferret == SilentFerret communication equivalence
    // (a refactor that breaks it shows the two rows diverging). One round is
    // SilentFerret::cots_per_round() == (t - refill_trees) << tree_depth.
    const int64_t ferret_cpr =
        (tuning::ferret_b11.t - tuning::ferret_b11.refill_trees)
        << tuning::ferret_b11.tree_depth;
#ifdef NDEBUG
    const int64_t ferret_len = ferret_cpr * 2;   // 2 rounds → exercises rollover
#else
    const int64_t ferret_len = ferret_cpr;       // 1 round (smaller for CI)
#endif

    // FS send_first conventions per protocol family:
    //   RCOT extensions: is_ot_sender() = (party == ALICE).
    //   F2kVOLE: is_delta_holder() = (party == BOB).
    //   FpVOLE : is_delta_holder() = (party == ALICE).
    //   Base OTs: don't use FS internally; ALICE=true is arbitrary
    //             but agreed between parties.
    const bool rcot_sf = (party == ALICE);
    const bool f2k_sf  = (party == BOB);
    const bool fp_sf   = (party == ALICE);
    const bool base_sf = (party == ALICE);

    // Base OTs.
    measure(party, port, "CO",       base_sf, [&](NetIO* io){ run_base_ot<CO>      (io, party, base_len); });
    measure(party, port, "CSW",      base_sf, [&](NetIO* io){ run_base_ot<CSW>     (io, party, base_len); });
    measure(party, port, "PVW",      base_sf, [&](NetIO* io){ run_base_ot<PVW>     (io, party, base_len); });
    measure(party, port, "BMM",      base_sf, [&](NetIO* io){ run_base_ot<BMM>     (io, party, base_len); });

    for (bool mali : {false, true}) {
        const string mode = mali ? "mali" : "semi";

        measure(party, port, "IKNP " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, rcot_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<IKNP>(new IKNP(party, x, m));
                }, mali);
        });
        measure(party, port, "SoftSpoken<2> " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, rcot_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<SoftSpoken<2>>(
                        new SoftSpoken<2>(party, x, m));
                }, mali);
        });
        measure(party, port, "SoftSpoken<8> " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, rcot_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<SoftSpoken<8>>(
                        new SoftSpoken<8>(party, x, m));
                }, mali);
        });
        measure(party, port, "Ferret(b11) " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, ferret_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<Ferret>(
                        new Ferret(party, x, m, tuning::ferret_b11));
                }, mali);
        });
        measure(party, port, "SilentFerret(b11) " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, ferret_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<SilentFerret>(
                        new SilentFerret(party, x, m, tuning::ferret_b11));
                }, mali);
        });
        measure(party, port, "F2kVOLE " + mode, f2k_sf, [&](NetIO* io){
            // F2k: use Ferret's auto-sampled Δ (no set_delta call).
            run_svole<F2kVOLE<>>(io, party, svole_len, mali,
                [](auto&){ /* no-op: keep auto Δ */ });
        });
        measure(party, port, "FpVOLE " + mode, fp_sf, [&](NetIO* io){
            // Fp: keep the carrier's auto-sampled canonical nonzero Δ.
            run_svole<FpVOLE<>>(io, party, svole_len, mali,
                [](auto&){ /* no-op: keep auto Δ */ });
        });
    }
    return 0;
}
