// FerretCOT RCOT-only bench: RCOT (test_rcot) + RCOT inplace
// (test_rcot_inplace, batch_size = ferret->ot_limit). Two-party via
// `run`. Both semi-honest and malicious modes.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

const static int threads = 1;

static void bench_one(IOChannel* ios[], NetIO* netio, int party,
                      int64_t length, bool malicious) {
    const char* mode_name = malicious ? "mali" : "semi";
    FerretCOT* ot = new FerretCOT(party, threads, ios, malicious, true, ferret_b13);

    {
        uint64_t ds = 0, dr = 0;
        double us = test_rcot<FerretCOT>(ot, netio, party, length, &ds, &dr);
        cout << "FerretCOT " << mode_name << " RCOT\t"
             << double(length) / us << " MOTps  "
             << "send=" << double(ds) / length << " B/COT  "
             << "recv=" << double(dr) / length << " B/COT" << endl;
    }
    {
        const uint64_t batch = ot->ot_limit;
        uint64_t ds = 0, dr = 0;
        double us = test_rcot_inplace<FerretCOT>(ot, netio, party, batch, &ds, &dr);
        cout << "FerretCOT " << mode_name << " RCOT inplace\t"
             << double(batch) / us << " MOTps  "
             << "send=" << double(ds) / batch << " B/COT  "
             << "recv=" << double(dr) / batch << " B/COT" << endl;
    }

    delete ot;
}

int main(int argc, char** argv) {
    int length_log, port, party;
#ifdef NDEBUG
    constexpr int default_length_log = 24;
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
    NetIO* ios[threads];
    for (int i = 0; i < threads; ++i)
        ios[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + 2 * i);
    IOChannel* iochans[threads];
    for (int i = 0; i < threads; ++i) iochans[i] = ios[i];

    cout << "# bench_ferret_rcot: length=" << length << endl;
    bench_one(iochans, ios[0], party, length, /*malicious=*/false);
    bench_one(iochans, ios[0], party, length, /*malicious=*/true);

    for (int i = 0; i < threads; ++i) delete ios[i];
    return 0;
}
