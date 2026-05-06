// IKNP RCOT-only bench (semi-honest + malicious). Two-party via `run`.
// Default length is sized for tighter timing on the RCOT path; matches
// what e.g. perf record / sample want.
#include "test/test.h"
using namespace std;

int main(int argc, char** argv) {
    int length, port, party;
    if (argc <= 3) length = (1 << 24) + 101;
    else           length = (1 << atoi(argv[3])) + 101;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    auto run = [&](const char* name, IKNP* ot) {
        uint64_t ds = 0, dr = 0;
        double us = test_rcot<IKNP>(ot, io, party, length, &ds, &dr);
        cout << name << " RCOT\t"
             << double(length) / us << " MOTps  "
             << "send=" << double(ds) / length << " B/COT  "
             << "recv=" << double(dr) / length << " B/COT" << endl;
    };

    cout << "# bench_iknp_rcot: length=" << length << endl;

    {
        IKNP* ot = new IKNP(io, false);
        run("IKNP semi", ot);
        delete ot;
    }
    {
        IKNP* ot = new IKNP(io, true);
        run("IKNP mali", ot);
        delete ot;
    }

    delete io;
    return 0;
}
