// SilentFerret RCOT correctness: all wire traffic at begin(), wire-free
// next()/end(). Verifies RCOT correctness (one-shot + streaming) for
// semi-honest and malicious modes with a parallel begin()-time pool, and
// asserts that the next()/end() path moves zero bytes after begin — the
// "silent consume" property. Throughput lives in bench/bench_silentferret.cpp.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>
using namespace std;

// Drive begin / next* / end within a single round (no rollover) and assert
// next()/end() move zero bytes on either side — the silent property after
// begin has prepared and malicious-checked the round — then check RCOT
// correctness of the produced chunks.
static void verify_silent(NetIO* io, int party, bool malicious,
                          const PrimalLPNParameter& param, int n_threads) {
    SilentFerret ot(party, io, malicious, param, nullptr, n_threads);
    const int64_t chunk  = ot.chunk_size();
    const int64_t budget = param.t - param.refill_trees;   // trees pre-rollover
    const int64_t n_chunks = std::min<int64_t>(budget, 256);
    const int64_t eff = n_chunks * chunk;
    block* b = new block[eff];

    io->sync();
    ot.begin();                                  // all wire traffic here
    const uint64_t s0 = io->send_counter, r0 = io->recv_counter;
    for (int64_t i = 0; i < n_chunks; ++i)
        ot.next(b + i * chunk);                  // must be wire-free
    if (io->send_counter != s0 || io->recv_counter != r0)
        error("SilentFerret next() performed wire I/O (not silent)");
    ot.end();                                    // local refill only
    if (io->send_counter != s0 || io->recv_counter != r0)
        error("SilentFerret end() performed wire I/O (not silent)");

    verify_rcot(&ot, io, party, b, eff);
    cout << "  silent next/end ok (" << n_chunks << " chunks, "
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

// Prepaid multi-round: begin(n_ots) ships every prepared round's traffic up
// front, then the whole prepared_capacity() is drawn with ZERO wire I/O
// across several round boundaries. n_ots is chosen to span K>=4 rounds with a
// partial last round. Asserts wire-free consume + RCOT correctness, and that
// a produce_range over round 0 matches the cursor output for the same trees.
static void verify_prepaid(NetIO* io, int party, bool malicious,
                           const PrimalLPNParameter& param, int n_threads) {
    SilentFerret ot(party, io, malicious, param, nullptr, n_threads);
    const int64_t chunk = ot.chunk_size();
    const int64_t cpr   = ot.cots_per_round();
    const int64_t n_ots = cpr * 3 + chunk * 5;      // 3 full rounds + a bit → K=4
    io->sync();
    ot.begin(n_ots);                                // all wire traffic here
    const int64_t cap = ot.prepared_capacity();
    const int64_t K   = cap / cpr;
    if (K < 4) error("verify_prepaid: expected K>=4 rounds");

    const uint64_t s0 = io->send_counter, r0 = io->recv_counter;
    std::vector<block> buf(cap);

    // Irregular steps that straddle chunk and round boundaries.
    const int64_t steps[] = {chunk, 3 * chunk + 1, chunk - 1, 7 * chunk, cpr + 3};
    int64_t got = 0; int s = 0;
    while (got < cap) {
        int64_t step = std::min<int64_t>(steps[s++ % 5], cap - got);
        ot.next_n(buf.data() + got, step);          // must be wire-free
        got += step;
    }
    if (io->send_counter != s0 || io->recv_counter != r0)
        error("verify_prepaid: prepaid consume performed wire I/O");
    ot.end();                                       // local roll only
    if (io->send_counter != s0 || io->recv_counter != r0)
        error("verify_prepaid: prepaid end performed wire I/O");

    verify_rcot(&ot, io, party, buf.data(), cap);
    cout << "  prepaid ok (K=" << K << " rounds, " << cap << " COTs, "
         << (malicious ? "mali" : "semi") << ")" << endl;
}

// Strongest equivalence test: at a WHOLE number of rounds, plain Ferret and the
// no-arg (K=1-per-round) SilentFerret move the EXACT same number of bytes in each
// direction. SilentFerret only *reschedules* Ferret's traffic — all corrections
// up front, wire-free consume — with one check per round either way. (Byte
// *values* differ: SilentFerret re-derives its cGGM seeds; the *counts* are
// protocol-determined and must match.) N must be a multiple of one round's user
// budget: SilentFerret prepares whole rounds, so a PARTIAL last round would make
// it ship the unused tail of that round's corrections (Ferret ships only what it
// consumes) — a known, bounded over-preparation, not a discrepancy in the core.
static void verify_comm_matches_ferret(NetIO* io, int party,
                                       const PrimalLPNParameter& param) {
    const int64_t chunk = int64_t{1} << param.tree_depth;
    const int64_t cpr   = (param.t - param.refill_trees) * chunk;
    const int64_t N     = cpr * 3;                    // exactly 3 rounds → 2 rollovers
    block* buf = new block[N];

    io->sync();
    uint64_t a = io->send_counter, b = io->recv_counter;
    { Ferret f(party, io, /*malicious=*/true, param); f.rcot(buf, N); }
    const uint64_t f_sent = io->send_counter - a, f_recv = io->recv_counter - b;

    io->sync();
    a = io->send_counter; b = io->recv_counter;
    { SilentFerret s(party, io, /*malicious=*/true, param); s.rcot(buf, N); }
    const uint64_t s_sent = io->send_counter - a, s_recv = io->recv_counter - b;

    if (f_sent != s_sent || f_recv != s_recv) {
        cerr << "Ferret sent/recv = " << f_sent << "/" << f_recv
             << "  SilentFerret = " << s_sent << "/" << s_recv << endl;
        error("Ferret vs SilentFerret communication differs (same N)");
    }
    cout << "  comm == Ferret (sent=" << f_sent << " recv=" << f_recv
         << " B, N=" << N << ")" << endl;
    delete[] buf;
}

// Even stronger: run SilentFerret as TWO prepaid batches of R rounds each
// (begin(R*cpr) / draw R*cpr / end, twice) vs plain Ferret over the same 2*R
// rounds. Corrections + bootstrap must be byte-for-byte identical; the ONLY
// difference is the malicious check — Ferret runs one per round (2*R total),
// the batched SilentFerret one per batch (2 total). So the saving is EXACTLY
// (2*R - 2) batched-away check round-trips (digest 32 B sender->recv, x' 16 B
// recv->sender). Also verifies the 2-batch chain produces valid RCOTs (abs-round
// / base continuity, no counter reuse across the two begin()s).
static void verify_comm_batched_vs_ferret(NetIO* io, int party,
                                          const PrimalLPNParameter& param) {
    const int64_t chunk = int64_t{1} << param.tree_depth;
    const int64_t cpr   = (param.t - param.refill_trees) * chunk;
    const int64_t R = 2, B = 2;                  // rounds/batch, num batches
    const int64_t N_batch = R * cpr;
    const int64_t N = B * N_batch;               // 2*R whole rounds
    block* buf = new block[N];

    io->sync();
    uint64_t a = io->send_counter, b = io->recv_counter;
    { Ferret f(party, io, /*malicious=*/true, param); f.rcot(buf, N); }
    const uint64_t f_sent = io->send_counter - a, f_recv = io->recv_counter - b;

    SilentFerret s(party, io, /*malicious=*/true, param, nullptr, 1);
    io->sync();
    a = io->send_counter; b = io->recv_counter;
    for (int64_t k = 0; k < B; ++k) {
        s.begin(N_batch);                          // K=R rounds, ONE batched check
        s.next_n(buf + k * N_batch, N_batch);      // wire-free across the batch
        s.end();
    }
    const uint64_t b_sent = io->send_counter - a, b_recv = io->recv_counter - b;

    const int64_t digest_b = 2 * (int64_t)sizeof(block);   // 32
    const int64_t xprime_b = kConsistCheckCotNum / 8;      // 16
    const int64_t saved    = (B * R) - B;                  // rounds - batches
    const bool ot_sender   = (party == ALICE);
    const int64_t exp_sent_save = saved * (ot_sender ? digest_b : xprime_b);
    const int64_t exp_recv_save = saved * (ot_sender ? xprime_b : digest_b);
    if ((int64_t)(f_sent - b_sent) != exp_sent_save ||
        (int64_t)(f_recv - b_recv) != exp_recv_save) {
        cerr << "Ferret " << f_sent << "/" << f_recv << "  batched " << b_sent
             << "/" << b_recv << "  expected save " << exp_sent_save << "/"
             << exp_recv_save << endl;
        error("batched comm != Ferret minus exactly the batched-away checks");
    }
    verify_rcot(&s, io, party, buf, N);    // 2-batch output is a valid RCOT
    cout << "  batched(" << B << "x" << R << " rounds) == Ferret - " << saved
         << " checks (Ferret " << f_sent << "/" << f_recv << " B, batched "
         << b_sent << "/" << b_recv << " B)" << endl;
    delete[] buf;
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    const int n_threads = 4;
    cout << "# test_silentferret: threads=" << n_threads << endl;

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

    // Multi-round consume is param-independent; exercise it on the smaller
    // params so the K>=4-round output buffer stays light (b13 rounds are ~15M
    // COTs each — too large to materialize several of here).
    verify_prepaid(io, party, /*malicious=*/false, tuning::ferret_b10, n_threads);
    verify_prepaid(io, party, /*malicious=*/true,  tuning::ferret_b10, n_threads);
    verify_prepaid(io, party, /*malicious=*/false, tuning::ferret_b11, n_threads);
    verify_prepaid(io, party, /*malicious=*/true,  tuning::ferret_b11, n_threads);

    // Differential: no-arg SilentFerret moves byte-for-byte the same as Ferret.
    verify_comm_matches_ferret(io, party, tuning::ferret_b10);
    verify_comm_matches_ferret(io, party, tuning::ferret_b11);

    // Batched (2 batches x 2 rounds) vs Ferret (4 rounds): identical corrections,
    // exactly (rounds - batches) fewer checks, and a valid 2-batch-chained RCOT.
    verify_comm_batched_vs_ferret(io, party, tuning::ferret_b10);
    verify_comm_batched_vs_ferret(io, party, tuning::ferret_b11);

    delete io;
    return 0;
}
