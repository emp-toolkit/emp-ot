// SoftSpoken<k> RCOT throughput bench, k ∈ {2, 4, 8}, semi + malicious.
// Reports MOT/s and B/COT per mode. Two-party via `run`. Default length is
// sized for tighter RCOT-path timing under a release build.
#include "bench/bench.h"
using namespace std;

template <int k>
void run_k(NetIO* io, int party, int64_t length) {
    auto bench = [&](const char* mode_name, SoftSpoken<k>* ot) {
        uint64_t ds = 0, dr = 0;
        double us = time_rcot<SoftSpoken<k>>(ot, io, party, length, &ds, &dr);
        cout << "SoftSpoken<" << k << "> " << mode_name << " RCOT\t"
             << double(length) / us << " MOTps  "
             << "send=" << double(ds) / length << " B/COT  "
             << "recv=" << double(dr) / length << " B/COT" << endl;
    };
    {
        SoftSpoken<k>* ot = new SoftSpoken<k>(party, io, /*malicious=*/false);
        bench("semi", ot);
        delete ot;
    }
    {
        SoftSpoken<k>* ot = new SoftSpoken<k>(party, io, /*malicious=*/true);
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
    if (argc <= 2) length = (1 << default_length_log) + 101;
    else           length = (1 << atoi(argv[2])) + 101;

    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    cout << "# bench_softspoken: length=" << length << endl;
    run_k<2>(io.get(), party, length);
    run_k<4>(io.get(), party, length);
    run_k<8>(io.get(), party, length);

    return 0;
}
