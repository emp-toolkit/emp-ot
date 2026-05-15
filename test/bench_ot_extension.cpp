// Cross-protocol OT-extension RCOT throughput bench. Reports MOT/s and
// B/RCOT for IKNP / SoftSpoken<k> / FerretCOT. Two-party via `run`.
//
// Streaming-only: each row drives rcot_*_begin → rcot_*_next loop into a
// reusable chunk_ots()-sized scratch buffer and discards the generated
// blocks. This keeps memory flat regardless of how many OTs the row
// runs, so the length default sits at 2^25 (~33M OTs) without paying
// length × 16 B of heap. The first row of each protocol absorbs the
// base-OT bootstrap (set_delta hasn't fired and the streaming begin
// triggers it lazily) inside the timed window; this is intentional —
// the reported B/RCOT for a protocol includes its one-time bootstrap
// amortised over the bench length.
#include "test/test.h"
using namespace std;

template <typename T>
void run_row(T* ot, NetIO* io, int party, int64_t length, const char* row_name) {
    const int64_t chunk = ot->chunk_ots();
    const int64_t n_chunks = length / chunk;
    const int64_t eff_len = n_chunks * chunk;

    BlockVec buf(chunk);
    io->sync();
    uint64_t s0 = io->bytes_sent, r0 = io->bytes_recv;
    auto start = clock_start();
    if (party == ALICE) {
        ot->rcot_send_begin();
        for (int64_t i = 0; i < n_chunks; ++i)
            ot->rcot_send_next(buf.data());
        ot->rcot_send_end();
    } else {
        ot->rcot_recv_begin();
        for (int64_t i = 0; i < n_chunks; ++i)
            ot->rcot_recv_next(buf.data());
        ot->rcot_recv_end();
    }
    io->flush();
    long long us = time_from(start);
    uint64_t ds = io->bytes_sent - s0;
    uint64_t dr = io->bytes_recv - r0;

    cout << row_name << "\t"
         << double(eff_len) / us << " MOTps  "
         << "send=" << double(ds) / eff_len << " B/RCOT  "
         << "recv=" << double(dr) / eff_len << " B/RCOT" << endl;
}

template <int k>
void run_softspoken_k(NetIO* io, int party, int64_t length) {
    char name[32];
    {
        SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(party, io, /*malicious=*/false);
        snprintf(name, sizeof(name), "SoftSpoken<%d> semi", k);
        run_row(ot, io, party, length, name);
        delete ot;
    }
    {
        SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(party, io, /*malicious=*/true);
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
    if (argc <= 3) length = int64_t{1} << default_length_log;
    else           length = int64_t{1} << atoi(argv[3]);

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    cout << "# bench_ot_extension: length=" << length << "  (RCOT throughput, streaming API)" << endl;

    // IKNP
    {
        IKNP* iknp = new IKNP(party, io, /*malicious=*/false);
        run_row(iknp, io, party, length, "IKNP semi");
        delete iknp;
    }
    {
        IKNP* iknp = new IKNP(party, io, /*malicious=*/true);
        run_row(iknp, io, party, length, "IKNP mali");
        delete iknp;
    }

    // SoftSpoken<k>, k ∈ {2, 4, 8}, semi + mali.
    run_softspoken_k<2>(io, party, length);
    run_softspoken_k<4>(io, party, length);
    run_softspoken_k<8>(io, party, length);

    // FerretCOT (semi + mali).
    {
        FerretCOT* ot = new FerretCOT(party, io, /*malicious=*/false);
        run_row(ot, io, party, length, "FerretCOT semi");
        delete ot;
    }
    {
        FerretCOT* ot = new FerretCOT(party, io, /*malicious=*/true);
        run_row(ot, io, party, length, "FerretCOT mali");
        delete ot;
    }

    delete io;
    return 0;
}
