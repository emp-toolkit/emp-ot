// IKNP RCOT correctness test (semi-honest + malicious). Two-party via `run`.
// Small fixed length so CI stays fast regardless of NDEBUG; timing lives in
// bench/bench_iknp.cpp.
#include "test/test.h"
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    constexpr int64_t length = (int64_t{1} << 14) + 101;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    auto run = [&](const char* name, IKNP* ot) {
        cout << name << " RCOT\t";
        check_rcot<IKNP>(ot, io, party, length);
        cout << endl;
    };

    {
        IKNP* ot = new IKNP(party, io, /*malicious=*/false);
        run("IKNP semi", ot);
        delete ot;
    }
    {
        IKNP* ot = new IKNP(party, io, /*malicious=*/true);
        run("IKNP mali", ot);
        delete ot;
    }

    delete io;
    return 0;
}
