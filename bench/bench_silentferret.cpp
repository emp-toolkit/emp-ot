// SilentFerret RCOT throughput: all wire traffic at begin(), wire-free
// next()/end(). Reports one-shot rcot() throughput (MOTps) and the per-COT
// wire bytes in each direction across the b11/b13 params in semi-honest and
// malicious modes. Correctness lives in test/test_silentferret.cpp.
#include "emp-ot/emp-ot.h"
#include "bench/bench.h"
using namespace std;

// One-shot RCOT throughput across a param/mode, driven via rcot().
static void bench_one(NetIO* io, int party, int64_t length, bool malicious,
                      const char* tag, const PrimalLPNParameter& param,
                      int n_threads) {
    const char* mode = malicious ? "mali" : "semi";
    SilentFerret* ot =
        new SilentFerret(party, io, malicious, param, nullptr, n_threads);
    uint64_t ds = 0, dr = 0;
    double us = time_rcot<SilentFerret>(ot, io, party, length, &ds, &dr);
    cout << "SilentFerret " << tag << " " << mode << " RCOT\t"
         << double(length) / us << " MOTps  "
         << "send=" << double(ds) / length << " B/COT  "
         << "recv=" << double(dr) / length << " B/COT" << endl;
    delete ot;
}

int main(int argc, char** argv) {
    int length_log, port, party;
#ifdef NDEBUG
    constexpr int default_length_log = 22;   // > b11 round budget → rollover
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

    const int n_threads = 4;
    cout << "# bench_silentferret: length=" << length
         << " threads=" << n_threads << endl;

    bench_one(io, party, length, /*malicious=*/false, "b11", tuning::ferret_b11, n_threads);
    bench_one(io, party, length, /*malicious=*/true,  "b11", tuning::ferret_b11, n_threads);
    bench_one(io, party, length, /*malicious=*/false, "b13", tuning::ferret_b13, n_threads);
    bench_one(io, party, length, /*malicious=*/true,  "b13", tuning::ferret_b13, n_threads);

    delete io;
    return 0;
}
