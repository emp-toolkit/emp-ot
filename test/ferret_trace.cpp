// Verification harness for the ferret readability refactor.
//
// Usage (driven by ./run, which spawns ALICE + BOB):
//   ./run ./build/test/test_ferret_trace <prefix> snap
//     -- both parties run setup with OS randomness, snapshot post-setup
//        state to <prefix>.alice.snap / .bob.snap, exit.
//   ./run ./build/test/test_ferret_trace <prefix> trace
//     -- both parties load their snapshot, enable ferret_test deterministic
//        seeding, run rcot calls under TraceIO, dump every wire byte to
//        <prefix>.alice.trace / .bob.trace.
//
// Verification: snap once, trace twice (before + after refactor),
// `diff <prefix>.alice.trace <prefix>.alice.trace_after` must be empty.

#include "test/test.h"
#include "test/ferret_trace_io.h"
#include "emp-ot/ferret/test_random.h"
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <party> <port> <prefix> <snap|trace>\n", argv[0]);
        return 1;
    }
    int party, port;
    parse_party_and_port(argv, &party, &port);
    string prefix = argv[3];
    string mode   = argv[4];
    const char* tag = (party == ALICE) ? "alice" : "bob";
    string snap_path  = prefix + "." + tag + ".snap";
    string trace_path = prefix + "." + tag + ".trace";

    NetIO base(party == ALICE ? nullptr : "127.0.0.1", port, /*quiet=*/true);

    if (mode == "snap") {
        IOChannel* ios[1] = { &base };
        FerretCOT ot(party, 1, ios, /*malicious=*/false,
                     /*run_setup=*/true, ferret_b13);
        const int64_t sz = ot.state_size();
        vector<uint8_t> buf(sz);
        ot.assemble_state(buf.data(), sz);
        ofstream out(snap_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(buf.data()), sz);
        cout << tag << ": snapshot written (" << sz << " bytes)\n";
        return 0;
    }

    if (mode != "trace") {
        fprintf(stderr, "unknown mode: %s (want snap|trace)\n", mode.c_str());
        return 1;
    }

    // Wrap base IO in a tracer so every byte sent/received from this point
    // on lands in the trace file. Setup-phase IO is *not* in the trace
    // (snapshot was generated in a previous run).
    TraceIO trace(&base, trace_path);
    IOChannel* ios[1] = { &trace };
    FerretCOT ot(party, 1, ios, /*malicious=*/false,
                 /*run_setup=*/false, ferret_b13);
    // state_size() lazy-runs extend_initialization() so M (and the
    // resulting buffer length) are known before disassemble.
    const int64_t sz = ot.state_size();
    vector<uint8_t> buf(sz);
    ifstream in(snap_path, std::ios::binary);
    if (!in) { fprintf(stderr, "snapshot %s missing\n", snap_path.c_str()); return 1; }
    in.read(reinterpret_cast<char*>(buf.data()), sz);
    if (ot.disassemble_state(buf.data(), sz) != 0) {
        fprintf(stderr, "snapshot mismatch (params changed?)\n");
        return 1;
    }

    // Enable ferret-internal deterministic PRG seeding for the rcot path.
    ferret_test::test_seed_counter() = 1;

    // Two rcot calls of slightly different sizes to exercise the
    // silent-OT-buffer drain path (second call partially refills from
    // the leftover internal buffer of the first).
    constexpr int64_t N1 = (1 << 20) + 101;
    constexpr int64_t N2 = (1 << 19);
    vector<block> out1(N1), out2(N2);
    if (party == ALICE) {
        ot.rcot_send(out1.data(), N1);
        ot.rcot_send(out2.data(), N2);
    } else {
        ot.rcot_recv(out1.data(), N1);
        ot.rcot_recv(out2.data(), N2);
    }

    // Suppress dtor's pre-OT data file write — not part of the wire trace.
    ot.skip_file();
    cout << tag << ": trace written\n";
    return 0;
}
