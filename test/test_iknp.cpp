// IKNP RCOT correctness test (semi-honest + malicious). Two-party via `run`.
// Small fixed length so CI stays fast regardless of NDEBUG; timing lives in
// bench/bench_iknp.cpp.
#include "test/test.h"
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    constexpr int64_t length = (int64_t{1} << 14) + 101;

    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    auto run = [&](const char* name, IKNP* ot) {
        cout << name << " RCOT\t";
        check_rcot<IKNP>(ot, io.get(), party, length);
        cout << endl;
    };

    {
        IKNP* ot = new IKNP(party, io.get(), /*malicious=*/false);
        run("IKNP semi", ot);
        delete ot;
    }
    {
        IKNP* ot = new IKNP(party, io.get(), /*malicious=*/true);
        run("IKNP mali", ot);
        delete ot;
    }

    return 0;
}
