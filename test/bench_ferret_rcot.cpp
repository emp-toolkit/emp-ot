// FerretCOT RCOT-only bench: RCOT (test_rcot). Two-party via `run`.
// Both semi-honest and malicious modes.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

static void bench_one(NetIO* io, int party, int64_t length, bool malicious) {
    const char* mode_name = malicious ? "mali" : "semi";
    FerretCOT* ot = new FerretCOT(party, io, malicious, true, ferret_b13);

    uint64_t ds = 0, dr = 0;
    double us = test_rcot<FerretCOT>(ot, io, party, length, &ds, &dr);
    cout << "FerretCOT " << mode_name << " RCOT\t"
         << double(length) / us << " MOTps  "
         << "send=" << double(ds) / length << " B/COT  "
         << "recv=" << double(dr) / length << " B/COT" << endl;

    delete ot;
}

int main(int argc, char** argv) {
    int length_log, port, party;
#ifdef NDEBUG
    constexpr int default_length_log = 24;
#else
    constexpr int default_length_log = 14;
#endif
    if (argc <= 3) length_log = default_length_log;
    else           length_log = atoi(argv[3]);
    if (length_log > 30) {
        cerr << "Large test size! comment me if you want to run this size" << endl;
        return 1;
    }
    const int64_t length = 1LL << length_log;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    cout << "# bench_ferret_rcot: length=" << length << endl;
    bench_one(io, party, length, /*malicious=*/false);
    bench_one(io, party, length, /*malicious=*/true);

    delete io;
    return 0;
}
