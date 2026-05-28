// SilentFerret RCOT: all wire traffic at begin()/end(), wire-free next().
// Verifies RCOT correctness (one-shot + streaming) for semi-honest and
// malicious modes with a parallel begin()-time pool, and asserts that the
// next() loop moves zero bytes — the "silent consume" property.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>
using namespace std;

// One-shot RCOT correctness across a param/mode, driven via rcot().
static void bench_one(NetIO* io, int party, int64_t length, bool malicious,
                      const char* tag, const PrimalLPNParameter& param,
                      int n_threads) {
    const char* mode = malicious ? "mali" : "semi";
    SilentFerret* ot =
        new SilentFerret(party, io, malicious, param, nullptr, n_threads);
    uint64_t ds = 0, dr = 0;
    double us = test_rcot<SilentFerret>(ot, io, party, length, &ds, &dr);
    cout << "SilentFerret " << tag << " " << mode << " RCOT\t"
         << double(length) / us << " MOTps  "
         << "send=" << double(ds) / length << " B/COT  "
         << "recv=" << double(dr) / length << " B/COT" << endl;
    delete ot;
}

// Drive begin / next* / end within a single round (no rollover) and assert
// the next() loop moves zero bytes on either side — the silent property —
// then check RCOT correctness of the produced chunks.
static void verify_silent(NetIO* io, int party, bool malicious,
                          const PrimalLPNParameter& param, int n_threads) {
    SilentFerret ot(party, io, malicious, param, nullptr, n_threads);
    const int64_t chunk  = ot.chunk_size();
    const int64_t budget = param.t - param.refill_trees;   // trees pre-rollover
    const int64_t n_chunks = std::min<int64_t>(budget, 256);
    const int64_t eff = n_chunks * chunk;
    block* b = new block[eff];

    io->sync();
    ot.begin();                                  // all correction traffic here
    const uint64_t s0 = io->send_counter, r0 = io->recv_counter;
    for (int64_t i = 0; i < n_chunks; ++i)
        ot.next(b + i * chunk);                  // must be wire-free
    if (io->send_counter != s0 || io->recv_counter != r0)
        error("SilentFerret next() performed wire I/O (not silent)");
    ot.end();                                    // deferred check (mali only)

    verify_rcot(&ot, io, party, b, eff);
    cout << "  silent next() ok (" << n_chunks << " chunks, "
         << (malicious ? "mali" : "semi") << ")" << endl;
    delete[] b;
}

// Consumer-driven parallel consumption: produce the round's trees via one
// produce_range() call and via n_threads consumer-owned threads on disjoint
// ranges; assert the two outputs are byte-identical (order/thread-independent)
// and pass RCOT verification. No internal pool is used for consumption.
static void verify_parallel(NetIO* io, int party, bool malicious,
                            const PrimalLPNParameter& param, int n_threads) {
    SilentFerret ot(party, io, malicious, param, nullptr, n_threads);
    const int64_t chunk = ot.chunk_size();
    io->sync();
    ot.begin();
    const int64_t n = std::min<int64_t>(ot.round_capacity(), 256);
    const int64_t eff = n * chunk;
    std::vector<block> buf_single(eff), buf_par(eff);

    // (a) single call.
    ot.produce_range(buf_single.data(), 0, n);

    // (b) split across consumer-owned threads, disjoint [begin,cnt) ranges.
    const int T = std::max(1, n_threads);
    {
        std::vector<std::thread> ths;
        const int64_t per = (n + T - 1) / T;
        for (int t = 0; t < T; ++t) {
            const int64_t b = t * per;
            if (b >= n) break;
            const int64_t cnt = std::min<int64_t>(per, n - b);
            ths.emplace_back([&ot, &buf_par, chunk, b, cnt]() {
                ot.produce_range(buf_par.data() + b * chunk, b, cnt);
            });
        }
        for (auto& th : ths) th.join();
    }
    if (std::memcmp(buf_single.data(), buf_par.data(),
                    (size_t)eff * sizeof(block)) != 0)
        error("produce_range: threaded output != single-call output");

    ot.end();
    verify_rcot(&ot, io, party, buf_single.data(), eff);
    cout << "  produce_range ok (" << n << " trees, " << T << " threads, "
         << (malicious ? "mali" : "semi") << ")" << endl;
}

// Exercise next_n's drain + whole-chunk-direct + sub-chunk-tail paths with
// irregular increments that straddle chunk boundaries, and check the result
// against a produce_range reference over the same trees (both use the same
// deterministic index scheme, so they must be byte-identical).
static void verify_next_n(NetIO* io, int party, bool malicious,
                          const PrimalLPNParameter& param) {
    SilentFerret ot(party, io, malicious, param, nullptr, /*n_threads=*/1);
    const int64_t chunk = ot.chunk_size();
    io->sync();
    ot.begin();
    const int64_t n_trees = std::min<int64_t>(ot.round_capacity(), 64);
    const int64_t eff = n_trees * chunk;
    std::vector<block> buf_ref(eff), buf_inc(eff);

    ot.produce_range(buf_ref.data(), 0, n_trees);           // reference

    const int64_t steps[] = {1, chunk - 1, chunk, chunk + 3, 2 * chunk + 5};
    int64_t got = 0; int s = 0;
    while (got < eff) {
        int64_t step = std::min<int64_t>(steps[s++ % 5], eff - got);
        ot.next_n(buf_inc.data() + got, step);
        got += step;
    }
    if (std::memcmp(buf_ref.data(), buf_inc.data(),
                    (size_t)eff * sizeof(block)) != 0)
        error("next_n incremental output != produce_range output");

    ot.end();
    verify_rcot(&ot, io, party, buf_ref.data(), eff);
    cout << "  next_n ok (" << (malicious ? "mali" : "semi") << ")" << endl;
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
    cout << "# bench_silentferret_rcot: length=" << length
         << " threads=" << n_threads << endl;

    bench_one(io, party, length, /*malicious=*/false, "b11", tuning::ferret_b11, n_threads);
    bench_one(io, party, length, /*malicious=*/true,  "b11", tuning::ferret_b11, n_threads);
    bench_one(io, party, length, /*malicious=*/false, "b13", tuning::ferret_b13, n_threads);
    bench_one(io, party, length, /*malicious=*/true,  "b13", tuning::ferret_b13, n_threads);

    verify_silent(io, party, /*malicious=*/false, tuning::ferret_b11, n_threads);
    verify_silent(io, party, /*malicious=*/true,  tuning::ferret_b11, n_threads);
    verify_silent(io, party, /*malicious=*/false, tuning::ferret_b13, n_threads);
    verify_silent(io, party, /*malicious=*/true,  tuning::ferret_b13, n_threads);

    verify_parallel(io, party, /*malicious=*/false, tuning::ferret_b11, n_threads);
    verify_parallel(io, party, /*malicious=*/true,  tuning::ferret_b11, n_threads);
    verify_parallel(io, party, /*malicious=*/false, tuning::ferret_b13, n_threads);
    verify_parallel(io, party, /*malicious=*/true,  tuning::ferret_b13, n_threads);

    verify_next_n(io, party, /*malicious=*/false, tuning::ferret_b11);
    verify_next_n(io, party, /*malicious=*/true,  tuning::ferret_b11);
    verify_next_n(io, party, /*malicious=*/false, tuning::ferret_b13);
    verify_next_n(io, party, /*malicious=*/true,  tuning::ferret_b13);

    delete io;
    return 0;
}
