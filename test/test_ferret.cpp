// Ferret RCOT correctness test. Runs rcot() and asserts the receiver's
// outputs against the sender's via check_rcot, for each LPN parameter set
// {b11, b12, b13} × {semi, mali}. Two-party via `run`.
//
// Correctness only: a small fixed length keeps CI fast regardless of
// NDEBUG. Throughput timing lives in bench/bench_ferret.cpp.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

static void test_one(NetIO* io, int party, int64_t length, bool malicious,
                     const char* tag, const PrimalLPNParameter& param) {
    const char* mode_name = malicious ? "mali" : "semi";
    Ferret* ot = new Ferret(party, io, malicious, param);

    cout << "Ferret " << tag << " " << mode_name << " RCOT\t";
    check_rcot<Ferret>(ot, io, party, length);
    cout << endl;

    delete ot;
}

int main(int argc, char** argv) {
    int port, party;
    constexpr int length_log = 14;
    const int64_t length = 1LL << length_log;

    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    cout << "# test_ferret: length=" << length << endl;
    test_one(io, party, length, /*malicious=*/false, "b11", tuning::ferret_b11);
    test_one(io, party, length, /*malicious=*/true,  "b11", tuning::ferret_b11);
    test_one(io, party, length, /*malicious=*/false, "b12", tuning::ferret_b12);
    test_one(io, party, length, /*malicious=*/true,  "b12", tuning::ferret_b12);
    test_one(io, party, length, /*malicious=*/false, "b13", tuning::ferret_b13);
    test_one(io, party, length, /*malicious=*/true,  "b13", tuning::ferret_b13);

    delete io;
    return 0;
}
