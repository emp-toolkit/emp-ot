#include "test/test.h"
using namespace std;

// Reports protocol-only wire (the test-harness verification round-trip
// that follows is excluded — see test.h for the snapshot points).
#define BW_RUN(NAME, EXPR)                                                  \
    do {                                                                    \
        uint64_t ds = 0, dr = 0;                                            \
        double t = (EXPR);                                                  \
        cout << "SoftSpoken<" << k << "> " << NAME << "\t"                  \
             << double(length) / t * 1e6 << " OTps  "                       \
             << "send=" << double(ds) / length << " B/COT  "                \
             << "recv=" << double(dr) / length << " B/COT" << endl;         \
    } while (0)

template <int k>
void test_softspoken_k(NetIO* io, int party, int length, bool malicious) {
    SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(io);
    if (malicious) ot->set_malicious(true);
    BW_RUN("OT  ", (test_ot<SoftSpokenOT<k>>(ot, io, party, length, &ds, &dr)));
    BW_RUN("COT ", (test_cot<SoftSpokenOT<k>>(ot, io, party, length, &ds, &dr)));
    BW_RUN("ROT ", (test_rot<SoftSpokenOT<k>>(ot, io, party, length, &ds, &dr)));
    BW_RUN("RCOT", (test_rcot<SoftSpokenOT<k>>(ot, io, party, length, &ds, &dr)));
    delete ot;
}

int main(int argc, char** argv) {
    int length, port, party;
    if (argc <= 3)
        length = (1 << 20) + 101;
    else
        length = (1 << atoi(argv[3])) + 101;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    cout << "=== semi-honest ===" << endl;
    test_softspoken_k<2>(io, party, length, /*malicious=*/false);
    test_softspoken_k<4>(io, party, length, /*malicious=*/false);
    test_softspoken_k<8>(io, party, length, /*malicious=*/false);

    cout << "=== malicious ===" << endl;
    test_softspoken_k<2>(io, party, length, /*malicious=*/true);
    test_softspoken_k<4>(io, party, length, /*malicious=*/true);
    test_softspoken_k<8>(io, party, length, /*malicious=*/true);

    delete io;
    return 0;
}
