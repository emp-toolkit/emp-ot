// Determinism check for set_choice_seed.
//
// For each RCOT backend (IKNP / SoftSpoken<8> / Ferret(b13)), runs the
// protocol twice end-to-end. Receiver seeds choice_prg with the SAME
// known block on both runs via set_choice_seed; everything else
// (Δ on the sender, base-OT keys, internal PRGs) is freshly random.
// After both runs, the receiver's LSBs (= choice bits) must be
// byte-identical across the two runs.
//
// Two-party via the `run` script.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace emp;
using namespace std;

static constexpr int64_t kN = 4096;   // RCOTs per run

static void compare_lsbs(const char* tag, const block* a, const block* b, int64_t n) {
    int64_t mismatches = 0;
    for (int64_t i = 0; i < n; ++i)
        if (getLSB(a[i]) != getLSB(b[i])) ++mismatches;
    if (mismatches == 0) {
        cout << "[OK]   " << tag << ": " << n << " choice bits identical across runs\n";
    } else {
        cout << "[FAIL] " << tag << ": " << mismatches << "/" << n << " choice bits differ\n";
        exit(1);
    }
}

template <typename MakeOT>
static void check_one(NetIO* io, int party, const char* tag,
                      const block& seed, MakeOT make_ot) {
    BlockVec buf1(kN), buf2(kN);

    {
        auto ot = make_ot();
        if (party == BOB) ot->set_choice_seed(seed);
        if (party == ALICE) ot->rcot_send(buf1.data(), kN);
        else                ot->rcot_recv(buf1.data(), kN);
    }
    io->flush();

    {
        auto ot = make_ot();
        if (party == BOB) ot->set_choice_seed(seed);
        if (party == ALICE) ot->rcot_send(buf2.data(), kN);
        else                ot->rcot_recv(buf2.data(), kN);
    }
    io->flush();

    if (party == BOB) compare_lsbs(tag, buf1.data(), buf2.data(), kN);
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

    // Fixed seed; we want this->set_choice_seed-driven determinism,
    // not test-mode determinism. The seed itself can be anything.
    block seed = makeBlock(0x1234567890abcdefULL, 0xfedcba0987654321ULL);

    check_one(io, party, "IKNP semi", seed, [&]{
        return std::make_unique<IKNP>(party, io, /*malicious=*/false);
    });
    check_one(io, party, "IKNP mali", seed, [&]{
        return std::make_unique<IKNP>(party, io, /*malicious=*/true);
    });

    check_one(io, party, "SoftSpoken<8> semi", seed, [&]{
        return std::make_unique<SoftSpokenOT<8>>(party, io, /*malicious=*/false);
    });
    check_one(io, party, "SoftSpoken<8> mali", seed, [&]{
        return std::make_unique<SoftSpokenOT<8>>(party, io, /*malicious=*/true);
    });

    check_one(io, party, "Ferret(b13) semi", seed, [&]{
        return std::make_unique<Ferret>(party, io, /*malicious=*/false);
    });
    check_one(io, party, "Ferret(b13) mali", seed, [&]{
        return std::make_unique<Ferret>(party, io, /*malicious=*/true);
    });

    delete io;
    return 0;
}
