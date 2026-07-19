// SoftSpoken<k> RCOT throughput bench, k ∈ {2, 4, 8}, semi + malicious.
// Reports MOT/s and B/COT per mode. Two-party via `run`. Default length is
// sized for tighter RCOT-path timing under a release build.
#include "bench/bench.h"
using namespace std;

template <int k>
void run_k(NetIO* anchor, int party, int64_t length) {
    auto bench = [&](const char* mode_name, bool malicious) {
        // Fiat-Shamir state belongs to the IOChannel. A fresh connection per
        // row keeps a malicious run from enabling transcript hashing for the
        // semi-honest row that follows it.
        auto io = anchor->make_sibling();
        SoftSpoken<k> ot(party, io.get(), malicious);
        uint64_t ds = 0, dr = 0;
        double us = time_rcot<SoftSpoken<k>>(&ot, io.get(), party, length,
                                             &ds, &dr);
        cout << "SoftSpoken<" << k << "> " << mode_name << " RCOT\t"
             << double(length) / us << " MOTps  "
             << "send=" << double(ds) / length << " B/COT  "
             << "recv=" << double(dr) / length << " B/COT" << endl;
    };
    bench("semi", /*malicious=*/false);
    bench("mali", /*malicious=*/true);
}

int main(int argc, char** argv) {
    int port, party;
    int64_t length;
#ifdef NDEBUG
    constexpr int default_length_log = 24;
#else
    constexpr int default_length_log = 12;
#endif
    if (argc <= 2) length = (int64_t{1} << default_length_log) + 101;
    else           length = (int64_t{1} << atoi(argv[2])) + 101;

    party = parse_party(argv);
    port = peer_port();
    // Keep the listener alive while each benchmark row uses an independent
    // sibling channel. This avoids both shared transcript state and same-port
    // close/reconnect races between parties.
    auto anchor = (party == ALICE) ? NetIO::listen(port, /*quiet=*/true)
                                   : NetIO::connect(peer_ip(), port,
                                                    /*quiet=*/true);
    // Ensure the server has accepted the primary connection before the client
    // opens its first sibling; otherwise the accept queue can reverse them.
    anchor->sync();

    cout << "# bench_softspoken: length=" << length << endl;
    run_k<2>(anchor.get(), party, length);
    run_k<4>(anchor.get(), party, length);
    run_k<8>(anchor.get(), party, length);

    return 0;
}
