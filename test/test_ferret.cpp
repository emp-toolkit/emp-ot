// Ferret RCOT correctness test. Runs rcot() and asserts the receiver's
// outputs against the sender's via check_rcot, for each LPN parameter set
// {b11, b12, b13} × {semi, mali}, plus the common fourth-argument
// base-OT injection API with the default LPN parameter. Two-party via `run`.
//
// Correctness only: a small fixed length keeps CI fast regardless of
// NDEBUG. Throughput timing lives in bench/bench_ferret.cpp.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

static void test_one(NetIO* io, int party, int64_t length, bool malicious,
                     const char* tag, const PrimalLPNParameter& param) {
    const char* mode_name = malicious ? "mali" : "semi";
    Ferret* ot = new Ferret(party, io, malicious, nullptr, param);

    cout << "Ferret " << tag << " " << mode_name << " RCOT\t";
    check_rcot<Ferret>(ot, io, party, length);
    cout << endl;

    delete ot;
}

static void test_injected_base_ot(NetIO* io, int party, int64_t length) {
    Ferret ot(party, io, /*malicious=*/true, std::make_unique<CSW>(io));

    cout << "Ferret injected CSW b13 mali RCOT\t";
    check_rcot<Ferret>(&ot, io, party, length);
    cout << endl;
}

int main(int argc, char** argv) {
    int port, party;
    constexpr int length_log = 14;
    const int64_t length = 1LL << length_log;

    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    cout << "# test_ferret: length=" << length << endl;
    test_one(io.get(), party, length, /*malicious=*/false, "b11", tuning::ferret_b11);
    test_one(io.get(), party, length, /*malicious=*/true,  "b11", tuning::ferret_b11);
    test_one(io.get(), party, length, /*malicious=*/false, "b12", tuning::ferret_b12);
    test_one(io.get(), party, length, /*malicious=*/true,  "b12", tuning::ferret_b12);
    test_one(io.get(), party, length, /*malicious=*/false, "b13", tuning::ferret_b13);
    test_one(io.get(), party, length, /*malicious=*/true,  "b13", tuning::ferret_b13);
    test_injected_base_ot(io.get(), party, length);

    return 0;
}
