// Wire-equivalence harness: prove a no-arg (K=1-per-round) SilentFerret sends the
// EXACT SAME BYTES as plain Ferret — not just the same byte count.
//
// Under EMP_TEST_MODE all randomness is deterministic, so two wire-equivalent
// protocols produce byte-identical TraceIO dumps. Each protocol runs in its OWN
// process (so ECGroup::rand_scalar's thread-local PRG starts fresh — it is not
// rewound by reset_test_seed_counter), teeing wire bytes to
// <prefix>.<party>.<mode>.{send,recv}. A driver then diffs ferret vs silent.
//
// N is a WHOLE number of rounds: SilentFerret prepares whole rounds, so a partial
// tail would make it over-ship that round's corrections (a known, bounded effect,
// not a wire-equivalence break).
//
//   EMP_TEST_MODE=1 ./run ./build/trace_ferret_equiv /tmp/tfe ferret
//   EMP_TEST_MODE=1 ./run ./build/trace_ferret_equiv /tmp/tfe silent
//   diff /tmp/tfe.alice.ferret.send /tmp/tfe.alice.silent.send   # must be empty
//   ... (and .recv, and bob)
#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include "emp-tool/runtime/io/trace_io.h"
#include "emp-tool/runtime/core/test_mode.h"
#include "test/test.h"
#include <string>
using namespace emp;
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    if (argc < 3) {
        cerr << "usage: trace_ferret_equiv <party 1|2> <port> [prefix] [mode]\n"
             << "       mode = ferret | silent (default ferret)\n";
        return 1;
    }
    set_test_mode(true);  // force determinism even without EMP_TEST_MODE=1
    parse_party_and_port(argv, &party, &port);
    const string prefix = (argc > 3) ? argv[3] : "/tmp/tfe";
    const string mode   = (argc > 4) ? argv[4] : "ferret";
    const int64_t rounds = (argc > 5) ? atoll(argv[5]) : 2;  // whole rounds
    const string tag    = (party == ALICE) ? "alice" : "bob";

    const PrimalLPNParameter param = tuning::ferret_b10;
    const int64_t chunk = int64_t{1} << param.tree_depth;
    const int64_t cpr   = (param.t - param.refill_trees) * chunk;
    const int64_t N     = cpr * rounds;       // whole rounds → (rounds-1) rollovers
    block* buf = new block[N];

    NetIO* net = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    net->sync();
    {
        TraceIO tio(net, prefix + "." + tag + "." + mode);
        if (mode == "silent") {
            SilentFerret s(party, &tio, /*malicious=*/true, param);
            s.rcot(buf, N);
        } else {
            Ferret f(party, &tio, /*malicious=*/true, param);
            f.rcot(buf, N);
        }
        tio.flush();
    }
    cout << "trace_ferret_equiv " << tag << " " << mode << " (" << rounds
         << " rounds, N=" << N << ") done" << endl;
    delete[] buf;
    delete net;
    return 0;
}
