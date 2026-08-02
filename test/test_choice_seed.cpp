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

// An outer multi-party protocol may deliberately share one receiver-choice
// pattern across peer COTs while assigning every pair a distinct transcript
// sid. An explicit public LPN-matrix root must preserve that pattern; the sid
// remains free to domain-separate the rest of each Ferret transcript.
static void check_ferret_distinct_sids(NetIO* io, int party, bool malicious,
                                       const block& choice_seed,
                                       const block& matrix_seed) {
    BlockVec buf1(kN), buf2(kN);
    const block sids[2] = {
        makeBlock(0x1011121314151617ULL, 0x18191a1b1c1d1e1fULL),
        makeBlock(0x2021222324252627ULL, 0x28292a2b2c2d2e2fULL)};
    BlockVec* outputs[2] = {&buf1, &buf2};
    for (int run = 0; run < 2; ++run) {
        Ferret ot(party, io, malicious);
        ot.set_sid(SessionID(sids[run]));
        ot.set_lpn_matrix_seed(matrix_seed);
        if (party == BOB) ot.set_choice_seed(choice_seed);
        ot.rcot(outputs[run]->data(), kN);
        io->flush();
    }
    if (party == BOB)
        compare_lsbs(malicious ? "Ferret distinct-sid mali"
                               : "Ferret distinct-sid semi",
                     buf1.data(), buf2.data(), kN);
}

template <typename MakeOT>
static void check_one(NetIO* io, int party, const char* tag,
                      const block& seed, MakeOT make_ot) {
    BlockVec buf1(kN), buf2(kN);

    {
        auto ot = make_ot();
        if (party == BOB) ot->set_choice_seed(seed);
        ot->rcot(buf1.data(), kN);
    }
    io->flush();

    {
        auto ot = make_ot();
        if (party == BOB) ot->set_choice_seed(seed);
        ot->rcot(buf2.data(), kN);
    }
    io->flush();

    if (party == BOB) compare_lsbs(tag, buf1.data(), buf2.data(), kN);
}

int main(int argc, char** argv) {
    int port, party;
    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    // Fixed seed; we want this->set_choice_seed-driven determinism,
    // not test-mode determinism. The seed itself can be anything.
    block seed = makeBlock(0x1234567890abcdefULL, 0xfedcba0987654321ULL);

    check_one(io.get(), party, "IKNP semi", seed, [&]{
        return std::make_unique<IKNP>(party, io.get(), /*malicious=*/false);
    });
    check_one(io.get(), party, "IKNP mali", seed, [&]{
        return std::make_unique<IKNP>(party, io.get(), /*malicious=*/true);
    });

    check_one(io.get(), party, "SoftSpoken<8> semi", seed, [&]{
        return std::make_unique<SoftSpoken<8>>(party, io.get(), /*malicious=*/false);
    });
    check_one(io.get(), party, "SoftSpoken<8> mali", seed, [&]{
        return std::make_unique<SoftSpoken<8>>(party, io.get(), /*malicious=*/true);
    });

    check_one(io.get(), party, "Ferret(b13) semi", seed, [&]{
        return std::make_unique<Ferret>(party, io.get(), /*malicious=*/false);
    });
    check_one(io.get(), party, "Ferret(b13) mali", seed, [&]{
        return std::make_unique<Ferret>(party, io.get(), /*malicious=*/true);
    });

    const block matrix_seed =
        makeBlock(0x3141592653589793ULL, 0x2384626433832795ULL);
    check_ferret_distinct_sids(io.get(), party, /*malicious=*/false, seed,
                              matrix_seed);
    check_ferret_distinct_sids(io.get(), party, /*malicious=*/true, seed,
                              matrix_seed);

    return 0;
}
