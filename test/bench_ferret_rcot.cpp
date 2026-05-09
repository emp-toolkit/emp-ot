// FerretCOT RCOT-only bench: RCOT (test_rcot). Two-party via `run`.
// Sweeps {b11, b12, b13} × {semi, mali}.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

static void bench_one(NetIO* io, int party, int64_t length, bool malicious,
                      const char* tag, const PrimalLPNParameter& param) {
    const char* mode_name = malicious ? "mali" : "semi";
    FerretCOT* ot = new FerretCOT(party, io, malicious, true, param);

    uint64_t ds = 0, dr = 0;
    double us = test_rcot<FerretCOT>(ot, io, party, length, &ds, &dr);
    cout << "FerretCOT " << tag << " " << mode_name << " RCOT\t"
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
    bench_one(io, party, length, /*malicious=*/false, "b11", ferret_b11);
    bench_one(io, party, length, /*malicious=*/true,  "b11", ferret_b11);
    bench_one(io, party, length, /*malicious=*/false, "b12", ferret_b12);
    bench_one(io, party, length, /*malicious=*/true,  "b12", ferret_b12);
    bench_one(io, party, length, /*malicious=*/false, "b13", ferret_b13);
    bench_one(io, party, length, /*malicious=*/true,  "b13", ferret_b13);

    delete io;
    return 0;
}
