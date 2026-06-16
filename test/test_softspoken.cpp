// SoftSpoken<k> RCOT-only correctness test, k ∈ {2, 4, 8}, semi + malicious.
// Two-party via `run` (loopback). Small fixed length so CI stays fast; the
// generated RCOT outputs are asserted via check_rcot.
#include "test/test.h"
using namespace std;

template <int k>
void run_k(NetIO* io, int party, int64_t length) {
    {
        SoftSpoken<k>* ot = new SoftSpoken<k>(party, io, /*malicious=*/false);
        check_rcot<SoftSpoken<k>>(ot, io, party, length);
        delete ot;
    }
    {
        SoftSpoken<k>* ot = new SoftSpoken<k>(party, io, /*malicious=*/true);
        check_rcot<SoftSpoken<k>>(ot, io, party, length);
        delete ot;
    }
}

int main(int argc, char** argv) {
    int length, port, party;
    length = (1 << 12) + 101;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    cout << "# test_softspoken: length=" << length << endl;
    run_k<2>(io, party, length);
    run_k<4>(io, party, length);
    run_k<8>(io, party, length);

    delete io;
    return 0;
}
