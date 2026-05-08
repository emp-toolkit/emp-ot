// Cross-protocol OT-extension bench. Reports throughput + B/COT for
// IKNP / SoftSpoken / FerretCOT in one table, across all four flavors
// (RCOT → COT → ROT → OT). Two-party via the `run` script.
//
// Re-uses test_{rcot,cot,rot,ot} from test/test.h, so each row also
// asserts correctness — the bench's output is preceded by the helpers'
// "Tests passed.\t" markers (one per flavor call).
//
// Length default: (1 << 24) + 101 (~16M OTs). Smaller lengths
// (e.g. 2^20) leave constant base-OT setup bytes visible in the
// per-OT bandwidth column — at 16M OTs the protocol's asymptotic
// per-OT wire cost is what the table reports.
#include "test/test.h"
using namespace std;

#define BW_ROW(FLAVOR, FN) do {                                               \
    uint64_t ds = 0, dr = 0;                                                  \
    double us = FN(ot, io, party, length, &ds, &dr);                          \
    cout << FLAVOR << "\t" << row_name << "\t"                                \
         << double(length) / us << " MOTps  "                                 \
         << "send=" << double(ds) / length << " B/COT  "                      \
         << "recv=" << double(dr) / length << " B/COT" << endl;               \
} while (0)

// Streaming-API row: `length` gets rounded down to a multiple of
// chunk_ots() inside test_rcot_streaming, so MOTps must be computed
// over the effective length the test actually produced.
#define STR_ROW() do {                                                        \
    uint64_t ds = 0, dr = 0;                                                  \
    int64_t eff = 0;                                                          \
    double us = test_rcot_streaming<T>(ot, io, party, length, &eff, &ds, &dr);\
    cout << "STR " << "\t" << row_name << "\t"                                \
         << double(eff) / us << " MOTps  "                                    \
         << "send=" << double(ds) / eff << " B/COT  "                         \
         << "recv=" << double(dr) / eff << " B/COT" << endl;                  \
} while (0)

template <typename T>
void run_row(T* ot, NetIO* io, int party, int64_t length, const char* row_name) {
    // Warm up: trigger any deferred base-OT setup (IKNP / SoftSpoken
    // auto-run setup_send / setup_recv on the first rcot_send / rcot_recv
    // call). Without this, whichever row runs first eats the base-OT
    // bootstrap cost and looks 20-30% slower than the rest. Use length =
    // chunk_ots() so the OTExtension wrapper's leftover_ stays empty.
    {
        const int64_t warmup_len = ot->chunk_ots();
        BlockVec dummy(warmup_len);
        if (party == ALICE) ot->rcot_send(dummy.data(), warmup_len);
        else                ot->rcot_recv(dummy.data(), warmup_len);
        io->flush();
    }
    BW_ROW("RCOT", test_rcot<T>);
    STR_ROW();
    BW_ROW("COT ", test_cot<T>);
    BW_ROW("ROT ", test_rot<T>);
    BW_ROW("OT  ", test_ot<T>);
}

template <int k>
void run_softspoken_k(NetIO* io, int party, int64_t length) {
    char name[32];
    {
        SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(io);
        snprintf(name, sizeof(name), "SoftSpoken<%d> semi", k);
        run_row(ot, io, party, length, name);
        delete ot;
    }
    {
        SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(io);
        ot->set_malicious(true);
        snprintf(name, sizeof(name), "SoftSpoken<%d> mali", k);
        run_row(ot, io, party, length, name);
        delete ot;
    }
}

int main(int argc, char** argv) {
    int length, port, party;
#ifdef NDEBUG
    constexpr int default_length_log = 24;
#else
    constexpr int default_length_log = 12;
#endif
    if (argc <= 3) length = (1 << default_length_log) + 101;
    else           length = (1 << atoi(argv[3])) + 101;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    cout << "# bench_ot_extension: length=" << length << "  (3 protocols × 4 flavors)" << endl;

    // IKNP
    {
        IKNP* iknp = new IKNP(io, false);
        run_row(iknp, io, party, length, "IKNP semi");
        delete iknp;
    }
    {
        IKNP* iknp = new IKNP(io, true);
        run_row(iknp, io, party, length, "IKNP mali");
        delete iknp;
    }

    // SoftSpoken<k>, k ∈ {2, 4, 8}, semi + mali.
    run_softspoken_k<2>(io, party, length);
    run_softspoken_k<4>(io, party, length);
    run_softspoken_k<8>(io, party, length);

    // FerretCOT (semi + mali). FerretCOT's inherited send/recv,
    // send_cot/recv_cot, send_rot/recv_rot all dispatch through its
    // rcot_send/rcot_recv override, so the four-flavor matrix exercises
    // the same ferret extend pipeline at the bottom.
    {
        FerretCOT* ot = new FerretCOT(party, io, false);
        run_row(ot, io, party, length, "FerretCOT semi");
        delete ot;
    }
    {
        FerretCOT* ot = new FerretCOT(party, io, true);
        run_row(ot, io, party, length, "FerretCOT mali");
        delete ot;
    }

    delete io;
    return 0;
}
