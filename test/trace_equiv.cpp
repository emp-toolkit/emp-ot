// Trace-equivalence verification harness.
//
// Runs IKNP semi-honest RCOT under TraceIO, dumping every wire byte
// to <prefix>.alice.{send,recv} (Alice) or <prefix>.bob.{send,recv}
// (Bob). Two-party via the `run` script. Determinism comes from
// EMP_TEST_MODE=1 — without it, OS randomness is used and traces
// will differ run-to-run.
//
// Usage:
//   EMP_TEST_MODE=1 ./run ./build/trace_equiv before
//   EMP_TEST_MODE=1 ./run ./build/trace_equiv after
//   diff before.alice.send after.alice.send   # must be empty
//   diff before.alice.recv after.alice.recv   # must be empty
//   diff before.bob.send   after.bob.send     # must be empty
//   diff before.bob.recv   after.bob.recv     # must be empty
//
// Used to verify that an optimization / refactor doesn't change the
// observable wire bytes. The test mode flips both PRG default-
// construction and Group::get_rand_bn (the only OpenSSL-randomness
// site) to deterministic streams, so two runs of the same code at
// the same EMP_TEST_MODE setting produce byte-identical wires.
#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include "test/test.h"
using namespace emp;
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    if (argc < 4) {
        cerr << "usage: trace_equiv <party 1|2> <port> <prefix> [length_log]\n";
        return 1;
    }
    parse_party_and_port(argv, &party, &port);
    const string prefix = argv[3];
    const int length_log = (argc > 4) ? atoi(argv[4]) : 16;
    const int64_t length = (1LL << length_log) + 101;

    if (!is_test_mode()) {
        cerr << "trace_equiv: EMP_TEST_MODE not set; traces will be non-deterministic\n";
    }

    NetIO* under = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    const string party_tag = (party == ALICE) ? "alice" : "bob";
    TraceIO* io = new TraceIO(under, prefix + "." + party_tag);

    // Protocol bytes go through TraceIO; verify_rcot's verification
    // round-trip uses the underlying NetIO directly so the trace files
    // capture only the protocol's wire bytes, not test scaffolding.
    IKNP* iknp = new IKNP(io, /*malicious=*/false);
    block* b = new block[length];
    auto t0 = clock_start();
    if (party == ALICE) iknp->rcot_send(b, length);
    else                iknp->rcot_recv(b, length);
    io->flush();
    long long us = time_from(t0);
    verify_rcot(iknp, under, party, b, length);
    cout << "trace_equiv " << party_tag
         << " IKNP semi RCOT length=" << length
         << "  " << double(length) / us << " MOTps" << endl;

    delete[] b;
    delete iknp;
    delete io;
    delete under;
    return 0;
}
