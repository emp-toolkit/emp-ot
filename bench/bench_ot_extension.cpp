// Cross-protocol OT-extension RCOT throughput bench. Reports MOT/s and
// B/RCOT for IKNP / SoftSpoken<k> / Ferret / SilentFerret. Two-party via
// `run` (loopback) or networked via EMP_PEER_IP (see bench/CMakeLists.txt).
//
// Each row drives a begin → next loop into a reusable chunk_size()-sized
// scratch buffer and discards the generated blocks. This keeps memory flat
// regardless of how many OTs the row runs. The requested length defaults to
// 2^25, then snaps to a whole number of b13 rounds (30,015,488 OTs at the
// Release default) so Ferret and SilentFerret cover the same round geometry
// and ship the same correction traffic. SilentFerret is the one
// exception to pure streaming: it prepays every round in begin(eff_len) (all
// correction traffic up front) and then draws wire-free -- its defining mode.
// Every row gets a fresh NetIO so its Fiat-Shamir state is independent. Each
// row also absorbs its base-OT bootstrap (set_delta hasn't fired and the
// streaming begin triggers it lazily) inside the timed window; this is
// intentional -- the reported B/RCOT includes the one-time bootstrap
// amortised over the bench length.
#include "bench/bench.h"
#include <type_traits>
#include <utility>
using namespace std;

template <typename T>
void run_row(T* ot, NetIO* io, int party, int64_t length, const char* row_name) {
    const int64_t chunk = ot->chunk_size();
    const int64_t n_chunks = length / chunk;
    const int64_t eff_len = n_chunks * chunk;

    BlockVec buf(chunk);
    pretouch_blocks(buf.data(), chunk);
    io->sync();
    uint64_t s0 = io->send_counter, r0 = io->recv_counter;
    auto start = clock_start();
    (void)party;  // both roles run the same begin/next/end loop
    // SilentFerret's defining mode: prepay every round up front (all the
    // correction traffic lands in begin()), then draw wire-free. The other
    // extensions stream round-by-round via the no-arg begin().
    if constexpr (std::is_same_v<T, SilentFerret>)
        ot->begin(eff_len);
    else
        ot->begin();
    for (int64_t i = 0; i < n_chunks; ++i)
        ot->next(buf.data());
    ot->end();
    io->flush();
    long long us = time_from(start);
    uint64_t ds = io->send_counter - s0;
    uint64_t dr = io->recv_counter - r0;

    cout << row_name << "\t"
         << double(eff_len) / us << " MOTps  "
         << "n=" << eff_len << "  "
         << "send=" << double(ds) / eff_len << " B/RCOT  "
         << "recv=" << double(dr) / eff_len << " B/RCOT" << endl;
}

template <typename T, typename... Args>
void run_fresh_row(NetIO* anchor, int party, int64_t length,
                   const char* row_name, Args&&... args) {
    auto io = anchor->make_sibling();
    T ot(party, io.get(), std::forward<Args>(args)...);
    run_row(&ot, io.get(), party, length, row_name);
}

template <int k>
void run_softspoken_k(NetIO* anchor, int party, int64_t length) {
    char name[32];
    snprintf(name, sizeof(name), "SoftSpoken<%d> semi", k);
    run_fresh_row<SoftSpoken<k>>(anchor, party, length, name,
                                 /*malicious=*/false);
    snprintf(name, sizeof(name), "SoftSpoken<%d> mali", k);
    run_fresh_row<SoftSpoken<k>>(anchor, party, length, name,
                                 /*malicious=*/true);
}

int main(int argc, char** argv) {
    int port, party;
    int64_t length;
#ifdef NDEBUG
    constexpr int default_length_log = 25;
#else
    constexpr int default_length_log = 12;
#endif
    constexpr auto ferret_param = tuning::ferret_b13;
    constexpr const char *ferret_param_name = "b13";
    if (argc <= 2) length = int64_t{1} << default_length_log;
    else           length = int64_t{1} << atoi(argv[2]);

    // SilentFerret prepays complete rounds in begin(length), whereas Ferret
    // streams one tree at a time. Use one shared whole-round length for every
    // row so the two implementations have identical output/correction
    // geometry. b13 is divisible by every current chunk size, so all rows
    // have equal n.
    length = snap_to_ferret_rounds(length, ferret_param);

    party = parse_party(argv);
    port = peer_port();
    // The unused primary connection keeps one listener alive. Every measured
    // row runs on a fresh sibling channel with independent transcript state.
    auto anchor = (party == ALICE) ? NetIO::listen(port, /*quiet=*/true)
                                   : NetIO::connect(peer_ip(), port,
                                                    /*quiet=*/true);
    // connect() may return before the listener's first accept() completes. If
    // the client opens a sibling immediately, the server can accept the two
    // connections in the opposite order and pair different sockets by role.
    // Complete one handshake on the primary before opening any siblings.
    anchor->sync();

    cout << "# bench_ot_extension: length=" << length
         << "  ferret_param=" << ferret_param_name
         << "  (RCOT throughput, streaming API)" << endl;

    // IKNP
    run_fresh_row<IKNP>(anchor.get(), party, length, "IKNP semi",
                        /*malicious=*/false);
    run_fresh_row<IKNP>(anchor.get(), party, length, "IKNP mali",
                        /*malicious=*/true);

    // SoftSpoken<k>, k ∈ {2, 4, 8}, semi + mali.
    run_softspoken_k<2>(anchor.get(), party, length);
    run_softspoken_k<4>(anchor.get(), party, length);
    run_softspoken_k<8>(anchor.get(), party, length);

    // Ferret (semi + mali).
    run_fresh_row<Ferret>(anchor.get(), party, length, "Ferret semi",
                          /*malicious=*/false, ferret_param);
    run_fresh_row<Ferret>(anchor.get(), party, length, "Ferret mali",
                          /*malicious=*/true, ferret_param);

    // SilentFerret (semi + mali). n_threads=1 so it is single-threaded like
    // every other row here (the begin() expansion pool stays disabled) -- an
    // apples-to-apples throughput comparison. Its LPN parameter matches
    // Ferret; it prepays all rounds in begin(), then draws wire-free.
    run_fresh_row<SilentFerret>(anchor.get(), party, length,
                                "SilentFerret semi",
                                /*malicious=*/false, ferret_param,
                                nullptr, /*n_threads=*/1);
    run_fresh_row<SilentFerret>(anchor.get(), party, length,
                                "SilentFerret mali",
                                /*malicious=*/true, ferret_param,
                                nullptr, /*n_threads=*/1);

    return 0;
}
