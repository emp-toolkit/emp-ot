// Ferret RCOT throughput bench. Reports MOT/s and B/COT for each LPN
// parameter set {b11, b12, b13} × {semi, mali}. Two-party via `run`.
//
// Timing only: each row builds a Ferret instance, drives one rcot() call
// through time_rcot, and prints throughput plus the per-COT wire bytes.
// No correctness check -- that lives in test/test_ferret.cpp.
#include "bench/bench.h"
using namespace std;

static void bench_one(NetIO* io, int party, int64_t length, bool malicious,
                      const char* tag, const PrimalLPNParameter& param) {
    const char* mode_name = malicious ? "mali" : "semi";
    Ferret* ot = new Ferret(party, io, malicious, param);

    uint64_t ds = 0, dr = 0;
    double us = time_rcot<Ferret>(ot, io, party, length, &ds, &dr);
    cout << "Ferret " << tag << " " << mode_name << " RCOT\t"
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
    if (argc <= 2) length_log = default_length_log;
    else           length_log = atoi(argv[2]);
    if (length_log > 30) {
        cerr << "Large test size! comment me if you want to run this size" << endl;
        return 1;
    }
    const int64_t length = 1LL << length_log;

    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    cout << "# bench_ferret: length=" << length << endl;
    bench_one(io.get(), party, length, /*malicious=*/false, "b11", tuning::ferret_b11);
    bench_one(io.get(), party, length, /*malicious=*/true,  "b11", tuning::ferret_b11);
    bench_one(io.get(), party, length, /*malicious=*/false, "b12", tuning::ferret_b12);
    bench_one(io.get(), party, length, /*malicious=*/true,  "b12", tuning::ferret_b12);
    bench_one(io.get(), party, length, /*malicious=*/false, "b13", tuning::ferret_b13);
    bench_one(io.get(), party, length, /*malicious=*/true,  "b13", tuning::ferret_b13);

    return 0;
}
