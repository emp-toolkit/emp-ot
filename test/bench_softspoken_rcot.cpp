// SoftSpokenOT<k> RCOT-only bench, k ∈ {2, 4, 8}, semi + malicious.
// Two-party via `run`. Default length is sized for tighter RCOT-path
// timing.
#include "test/test.h"
using namespace std;

template <int k>
void run_k(NetIO* io, int party, int64_t length) {
    auto bench = [&](const char* mode_name, SoftSpokenOT<k>* ot) {
        uint64_t ds = 0, dr = 0;
        double us = test_rcot<SoftSpokenOT<k>>(ot, io, party, length, &ds, &dr);
        cout << "SoftSpoken<" << k << "> " << mode_name << " RCOT\t"
             << double(length) / us << " MOTps  "
             << "send=" << double(ds) / length << " B/COT  "
             << "recv=" << double(dr) / length << " B/COT" << endl;
    };
    {
        SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(party, io, /*malicious=*/false);
        bench("semi", ot);
        delete ot;
    }
    {
        SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(party, io, /*malicious=*/true);
        bench("mali", ot);
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

    cout << "# bench_softspoken_rcot: length=" << length << endl;
    run_k<2>(io, party, length);
    run_k<4>(io, party, length);
    run_k<8>(io, party, length);

    delete io;
    return 0;
}
