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

// First 16 hex chars (8 B) of a block digest — enough to detect any
// real change while keeping the table readable.
static string hex16(block b) {
    unsigned char raw[16];
    memcpy(raw, &b, sizeof(b));
    ostringstream o;
    for (int i = 0; i < 8; ++i)
        o << hex << setw(2) << setfill('0') << (int)raw[i];
    return o.str();
}

// Open a fresh NetIO + FS, run `body(io)`, snapshot per-direction
// digests, print (ALICE only — the BOB-side hashes are the inverse
// pair and would just produce a duplicate table). Each call uses
// the same port: the previous NetIO is destructed (TCP closed)
// before the next is constructed, so successive calls re-handshake
// on the same port.
template <typename Body>
static void measure(int party, int port, const string& name,
                    bool send_first, Body&& body) {
    NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);
    io.enable_fs(send_first);
    body(&io);
    io.flush();
    if (party == ALICE) {
        cout << left << setw(22) << name
             << " send=" << hex16(io.get_send_digest())
             << " recv=" << hex16(io.get_recv_digest()) << "\n";
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

// sVOLE runner: single-role extend(). The caller decides whether to
// inject a Δ — F2k can use Ferret's auto-sampled Δ unchanged, while
// Fp needs an explicit non-zero Δ so the chi-fold check is meaningful.
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
    if (argc < 3) {
        cerr << "usage: trace_hash <party 1|2> <port>\n";
        return 1;
    }
    parse_party_and_port(argv, &party, &port);
    if (!is_test_mode())
        cerr << "trace_hash: EMP_TEST_MODE not set; hashes "
                "will be non-deterministic\n";

    if (party == ALICE)
        cout << "# trace hashes (send / recv per protocol; alice view)\n";

    // Lengths: base OTs are slow per OT (public-key crypto), so 128
    // is plenty. RCOT stress is large enough to trigger Ferret's
    // per-round rollover (~1M RCOTs for b11) so the chi-fold path is
    // exercised; small enough that IKNP/SoftSpoken finish quickly.
    const int64_t base_len  = 128;
    const int64_t rcot_len  = (1LL << 22) + 101;
    const int64_t svole_len = 1 << 20;

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
    measure(party, port, "OTCO",       base_sf, [&](NetIO* io){ run_base_ot<OTCO>      (io, party, base_len); });
    measure(party, port, "OTCSW",      base_sf, [&](NetIO* io){ run_base_ot<OTCSW>     (io, party, base_len); });
    measure(party, port, "OTPVW",      base_sf, [&](NetIO* io){ run_base_ot<OTPVW>     (io, party, base_len); });
    measure(party, port, "OTPVWKyber", base_sf, [&](NetIO* io){ run_base_ot<OTPVWKyber>(io, party, base_len); });

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
                    return std::unique_ptr<SoftSpokenOT<2>>(
                        new SoftSpokenOT<2>(party, x, m));
                }, mali);
        });
        measure(party, port, "SoftSpoken<8> " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, rcot_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<SoftSpokenOT<8>>(
                        new SoftSpokenOT<8>(party, x, m));
                }, mali);
        });
        measure(party, port, "Ferret(b11) " + mode, rcot_sf, [&](NetIO* io){
            run_rcot(io, party, rcot_len,
                [&](IOChannel* x, bool m) {
                    return std::unique_ptr<Ferret>(
                        new Ferret(party, x, m, tuning::ferret_b11));
                }, mali);
        });
        measure(party, port, "F2kVOLE " + mode, f2k_sf, [&](NetIO* io){
            // F2k: use Ferret's auto-sampled Δ (no set_delta call).
            run_svole<F2kVOLE<>>(io, party, svole_len, mali,
                [](auto&){ /* no-op: keep auto Δ */ });
        });
        measure(party, port, "FpVOLE " + mode, fp_sf, [&](NetIO* io){
            // Fp: AuthValueFp::resolve_delta returns 0, so the holder
            // must inject a non-zero Δ for a meaningful chi-fold check.
            // PRG keeps it reproducible under EMP_TEST_MODE.
            run_svole<FpVOLE<>>(io, party, svole_len, mali,
                [](auto& sv) {
                    PRG prg;
                    uint64_t d;
                    prg.random_data_unaligned(&d, sizeof(d));
                    sv.set_delta(d % AuthValueFp::PR_VAL);
                });
        });
    }
    return 0;
}
