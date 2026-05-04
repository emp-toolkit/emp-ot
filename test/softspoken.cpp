#include "test/test.h"
using namespace std;

#define BW_RUN(NAME, EXPR)                                                  \
    do {                                                                    \
        uint64_t s0 = io->bytes_sent, r0 = io->bytes_recv;                  \
        double t = (EXPR);                                                  \
        uint64_t ds = io->bytes_sent - s0, dr = io->bytes_recv - r0;        \
        cout << "SoftSpoken<" << k << "> " << NAME << "\t"                  \
             << double(length) / t * 1e6 << " OTps  "                       \
             << "send=" << double(ds) / length << " B/COT  "                \
             << "recv=" << double(dr) / length << " B/COT" << endl;         \
    } while (0)

template <int k>
void test_softspoken_k(NetIO* io, int party, int length) {
    SoftSpokenOT<k>* ot = new SoftSpokenOT<k>(io);
    BW_RUN("OT  ", (test_ot<SoftSpokenOT<k>>(ot, io, party, length)));
    BW_RUN("COT ", (test_cot<SoftSpokenOT<k>>(ot, io, party, length)));
    BW_RUN("ROT ", (test_rot<SoftSpokenOT<k>>(ot, io, party, length)));
    BW_RUN("RCOT", (test_rcot<SoftSpokenOT<k>>(ot, io, party, length)));
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

    test_softspoken_k<2>(io, party, length);
    test_softspoken_k<4>(io, party, length);
    test_softspoken_k<8>(io, party, length);

    delete io;
    return 0;
}
