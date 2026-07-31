// SilentFerret RCOT throughput: all wire traffic at begin(), wire-free
// next()/end(). Reports one-shot rcot() throughput (MOTps) and the per-COT
// wire bytes in each direction across the b11/b13 params in semi-honest and
// malicious modes. Also reports an end-to-end line (bench_e2e) that times
// begin() + parallel-extend + end() in a single window with BOTH begin_threads
// and online_threads engaged, so the offline (base OTs + begin wire traffic)
// cost is included -- the honest full-protocol, both-phases-threaded number,
// versus the serial-extend rcot() line above. Correctness lives in
// test/test_silentferret.cpp.
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
    length = snap_to_ferret_rounds(length, param);
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

// End-to-end multithreaded: begin() + parallel extend + end() timed as one
// window. begin_threads drives the begin() offline pool; online_threads drives
// the wire-free extend (next_chunks_parallel). Unlike bench_one (rcot(), whose
// extend loop is serial and ignores online_threads) this threads both phases,
// and unlike bench_online it keeps begin() -- hence the base OTs and all begin
// wire traffic -- inside the timer. Wire bytes are captured across the whole
// call, so send/recv B/COT reflect the full protocol.
static void bench_e2e(NetIO* io, int party, int64_t length, bool malicious,
                      const char* tag, const PrimalLPNParameter& param,
                      int begin_threads, int online_threads) {
    const char* mode = malicious ? "mali" : "semi";
    SilentFerret ot(party, io, malicious, param, nullptr, begin_threads);
    const int64_t chunk = ot.chunk_size();
    const int64_t n_trees = length / chunk;
    const int64_t eff_len = n_trees * chunk;
    expecting(n_trees > 0, "bench_silentferret e2e: length below one chunk");
    std::vector<block> buf(eff_len);  // vector ctor value-inits, faulting pages
    io->sync();
    uint64_t s0 = io->send_counter, r0 = io->recv_counter;
    auto start = clock_start();
    ot.begin(eff_len);
    ot.next_chunks_parallel(buf.data(), n_trees, online_threads);
    ot.end();
    long long us = time_from(start);
    uint64_t ds = io->send_counter - s0, dr = io->recv_counter - r0;
    cout << "SilentFerret " << tag << " " << mode << " e2e "
         << (party == ALICE ? "sender" : "receiver") << "\t"
         << "len=" << eff_len << "  "
         << "bt=" << begin_threads << " ot=" << online_threads << "  "
         << double(eff_len) / us << " MOTps  "
         << "send=" << double(ds) / eff_len << " B/COT  "
         << "recv=" << double(dr) / eff_len << " B/COT" << endl;
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
    // argv: <party> [length_log] [online_threads] [begin_threads].
    // begin_threads=1 disables the begin() expansion pool — use it when
    // comparing against the single-threaded protocols (README table).
    const int online_threads = (argc <= 3) ? 2 : std::max(1, atoi(argv[3]));
    const int begin_threads = (argc <= 4) ? 4 : std::max(1, atoi(argv[4]));

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

    bench_e2e(io.get(), party, length, /*malicious=*/false, "b11", tuning::ferret_b11, begin_threads, online_threads);
    bench_e2e(io.get(), party, length, /*malicious=*/true,  "b11", tuning::ferret_b11, begin_threads, online_threads);
    bench_e2e(io.get(), party, length, /*malicious=*/false, "b13", tuning::ferret_b13, begin_threads, online_threads);
    bench_e2e(io.get(), party, length, /*malicious=*/true,  "b13", tuning::ferret_b13, begin_threads, online_threads);

    return 0;
}
