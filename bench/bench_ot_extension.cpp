// Cross-protocol OT-extension RCOT throughput bench. Reports MOT/s and
// B/RCOT for IKNP / SoftSpoken<k> / Ferret / SilentFerret. Two-party via
// `run` (loopback) or networked via EMP_PEER_IP (see bench/CMakeLists.txt).
//
// Each row drives a begin → next loop into a reusable chunk_size()-sized
// scratch buffer and discards the generated blocks. This keeps memory flat
// regardless of how many OTs the row runs, so the length default sits at 2^25
// (~33M OTs) without paying length × 16 B of heap. SilentFerret is the one
// exception to pure streaming: it prepays every round in begin(eff_len) (all
// correction traffic up front) and then draws wire-free -- its defining mode. The first row of each protocol absorbs the
// base-OT bootstrap (set_delta hasn't fired and the streaming begin
// triggers it lazily) inside the timed window; this is intentional —
// the reported B/RCOT for a protocol includes its one-time bootstrap
// amortised over the bench length.
#include "bench/bench.h"
#include <type_traits>
using namespace std;

template <typename T>
void run_row(T* ot, NetIO* io, int party, int64_t length, const char* row_name) {
    const int64_t chunk = ot->chunk_size();
    const int64_t n_chunks = length / chunk;
    const int64_t eff_len = n_chunks * chunk;

    BlockVec buf(chunk);
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
         << "send=" << double(ds) / eff_len << " B/RCOT  "
         << "recv=" << double(dr) / eff_len << " B/RCOT" << endl;
}

template <int k>
void run_softspoken_k(NetIO* io, int party, int64_t length) {
    char name[32];
    {
        SoftSpoken<k>* ot = new SoftSpoken<k>(party, io, /*malicious=*/false);
        snprintf(name, sizeof(name), "SoftSpoken<%d> semi", k);
        run_row(ot, io, party, length, name);
        delete ot;
    }
    {
        SoftSpoken<k>* ot = new SoftSpoken<k>(party, io, /*malicious=*/true);
        snprintf(name, sizeof(name), "SoftSpoken<%d> mali", k);
        run_row(ot, io, party, length, name);
        delete ot;
    }
}

int main(int argc, char** argv) {
    int port, party;
    int64_t length;
#ifdef NDEBUG
    constexpr int default_length_log = 25;
#else
    constexpr int default_length_log = 12;
#endif
    if (argc <= 2) length = int64_t{1} << default_length_log;
    else           length = int64_t{1} << atoi(argv[2]);

    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    cout << "# bench_ot_extension: length=" << length << "  (RCOT throughput, streaming API)" << endl;

    // IKNP
    {
        IKNP* iknp = new IKNP(party, io.get(), /*malicious=*/false);
        run_row(iknp, io.get(), party, length, "IKNP semi");
        delete iknp;
    }
    {
        IKNP* iknp = new IKNP(party, io.get(), /*malicious=*/true);
        run_row(iknp, io.get(), party, length, "IKNP mali");
        delete iknp;
    }

    // SoftSpoken<k>, k ∈ {2, 4, 8}, semi + mali.
    run_softspoken_k<2>(io.get(), party, length);
    run_softspoken_k<4>(io.get(), party, length);
    run_softspoken_k<8>(io.get(), party, length);

    // Ferret (semi + mali).
    {
        Ferret* ot = new Ferret(party, io.get(), /*malicious=*/false);
        run_row(ot, io.get(), party, length, "Ferret semi");
        delete ot;
    }
    {
        Ferret* ot = new Ferret(party, io.get(), /*malicious=*/true);
        run_row(ot, io.get(), party, length, "Ferret mali");
        delete ot;
    }

    // SilentFerret (semi + mali). n_threads=1 so it is single-threaded like
    // every other row here (the begin() expansion pool stays disabled) -- an
    // apples-to-apples throughput comparison. Default LPN param (ferret_b13)
    // matches Ferret; prepays all rounds in begin(), then draws wire-free.
    {
        SilentFerret* ot = new SilentFerret(party, io.get(), /*malicious=*/false,
                                            tuning::ferret_b13, nullptr, /*n_threads=*/1);
        run_row(ot, io.get(), party, length, "SilentFerret semi");
        delete ot;
    }
    {
        SilentFerret* ot = new SilentFerret(party, io.get(), /*malicious=*/true,
                                            tuning::ferret_b13, nullptr, /*n_threads=*/1);
        run_row(ot, io.get(), party, length, "SilentFerret mali");
        delete ot;
    }

    return 0;
}
