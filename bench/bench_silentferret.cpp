// SilentFerret RCOT throughput: all wire traffic at begin(), wire-free
// next()/end(). Reports one-shot rcot() throughput (MOTps) and the per-COT
// wire bytes in each direction across the b11/b13 params in semi-honest and
// malicious modes. Correctness lives in test/test_silentferret.cpp.
#include "emp-ot/emp-ot.h"
#include "bench/bench.h"
#include <algorithm>
#include <vector>
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

static double time_online_next(NetIO* io, int party, int64_t length,
                               bool malicious, const PrimalLPNParameter& param,
                               int begin_threads, int64_t* eff_len_out) {
    SilentFerret ot(party, io, malicious, param, nullptr, begin_threads);
    const int64_t chunk = ot.chunk_size();
    const int64_t n_trees = length / chunk;
    const int64_t eff_len = n_trees * chunk;
    if (eff_len_out) *eff_len_out = eff_len;
    std::vector<block> buf(eff_len);

    io->sync();
    ot.begin(eff_len);
    io->sync();
    auto start = clock_start();
    for (int64_t i = 0; i < n_trees; ++i)
        ot.next(buf.data() + i * chunk);
    long long us = time_from(start);
    ot.end();
    return us;
}

static double time_online_range_threads(NetIO* io, int party, int64_t length,
                                        bool malicious,
                                        const PrimalLPNParameter& param,
                                        int begin_threads, int online_threads,
                                        int64_t* eff_len_out) {
    SilentFerret ot(party, io, malicious, param, nullptr, begin_threads);
    const int64_t chunk = ot.chunk_size();
    const int64_t n_trees = length / chunk;
    const int64_t eff_len = n_trees * chunk;
    if (eff_len_out) *eff_len_out = eff_len;
    std::vector<block> buf(eff_len);

    io->sync();
    ot.begin(eff_len);
    io->sync();
    auto start = clock_start();
    ot.next_chunks_parallel(buf.data(), n_trees, online_threads);
    long long us = time_from(start);
    ot.end();
    return us;
}

// Silent online phase only: begin(n) is run before the timer, then output
// production is timed across the requested chunk-multiple length.
static void bench_online(NetIO* io, int party, int64_t length, bool malicious,
                         const char* tag, const PrimalLPNParameter& param,
                         int begin_threads, int online_threads) {
    const char* mode = malicious ? "mali" : "semi";
    int64_t eff_next = 0, eff_par = 0;
    double us_next = time_online_next(io, party, length, malicious, param,
                                      begin_threads, &eff_next);
    double us_par = time_online_range_threads(io, party, length, malicious,
                                              param, begin_threads,
                                              online_threads, &eff_par);
    if (eff_next <= 0 || eff_next != eff_par)
        error("bench_silentferret online: invalid effective length");
    cout << "SilentFerret " << tag << " " << mode << " online "
         << (party == ALICE ? "sender" : "receiver") << "\t"
         << "len=" << eff_next << "  "
         << "next=" << double(eff_next) / us_next << " MOTps  "
         << online_threads << "thr=" << double(eff_par) / us_par << " MOTps  "
         << "speedup=" << us_next / us_par << "x" << endl;
}

int main(int argc, char** argv) {
    int length_log, port, party;
#ifdef NDEBUG
    constexpr int default_length_log = 22;   // > b11 round budget → rollover
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
    const int begin_threads = 4;
    const int online_threads = (argc <= 3) ? 2 : std::max(1, atoi(argv[3]));

    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    cout << "# bench_silentferret: length=" << length
         << " begin_threads=" << begin_threads
         << " online_threads=" << online_threads << endl;

    bench_one(io.get(), party, length, /*malicious=*/false, "b11", tuning::ferret_b11, begin_threads);
    bench_one(io.get(), party, length, /*malicious=*/true,  "b11", tuning::ferret_b11, begin_threads);
    bench_one(io.get(), party, length, /*malicious=*/false, "b13", tuning::ferret_b13, begin_threads);
    bench_one(io.get(), party, length, /*malicious=*/true,  "b13", tuning::ferret_b13, begin_threads);

    bench_online(io.get(), party, length, /*malicious=*/false, "b11", tuning::ferret_b11, begin_threads, online_threads);
    bench_online(io.get(), party, length, /*malicious=*/true,  "b11", tuning::ferret_b11, begin_threads, online_threads);
    bench_online(io.get(), party, length, /*malicious=*/false, "b13", tuning::ferret_b13, begin_threads, online_threads);
    bench_online(io.get(), party, length, /*malicious=*/true,  "b13", tuning::ferret_b13, begin_threads, online_threads);

    return 0;
}
