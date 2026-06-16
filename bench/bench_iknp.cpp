// IKNP RCOT throughput bench (semi-honest + malicious). Two-party via `run`.
// Default length is sized for tighter timing on the RCOT path; matches
// what e.g. perf record / sample want. Timing only -- correctness lives in
// test/test_iknp.cpp.
#include "bench/bench.h"
using namespace std;

int main(int argc, char** argv) {
    int port, party;
    int64_t length;
#ifdef NDEBUG
    constexpr int default_length_log = 24;
#else
    constexpr int default_length_log = 12;
#endif
    if (argc <= 3) length = (int64_t{1} << default_length_log) + 101;
    else           length = (int64_t{1} << atoi(argv[3])) + 101;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    auto run = [&](const char* name, IKNP* ot) {
        uint64_t ds = 0, dr = 0;
        double us = time_rcot<IKNP>(ot, io, party, length, &ds, &dr);
        cout << name << " RCOT\t"
             << double(length) / us << " MOTps  "
             << "send=" << double(ds) / length << " B/COT  "
             << "recv=" << double(dr) / length << " B/COT" << endl;
    };

    cout << "# bench_iknp: length=" << length << endl;

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
