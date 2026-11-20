// SoftSpoken clone_lane correctness.
//
// Test A (assembled RCOT): a parent + L-1 lane clones extend DISJOINT contiguous
//   output ranges on L independent channels; the CONCATENATION must be one
//   coherent RCOT (per-lane COT relation Q^W = u*Delta, shared Delta). L in
//   {1,2,4}, k in {4,8}, semi + malicious (each lane runs its OWN subspace-VOLE
//   check at end() -- a mis-wired lane check or a broken correlation aborts).
// Test B (domain separation): two clones of one parent, and a clone of a clone,
//   over the SAME range must produce pairwise DIFFERENT outputs -- each lane
//   takes a fresh child of its parent's session id, and a lane whose id did not
//   reach its session keys would repeat another lane's COTs while staying
//   individually COT-valid, which Test A alone would miss.
//
// Two-party loopback via the `run` script. L channels are opened in the SAME
// order on both sides (sequential listen/connect), base port stepped per sub-test.
#include "test/test.h"
#include <vector>
#include <memory>
using namespace std;
using namespace emp;

static int g_port_base = 0;   // stepped per sub-test to avoid TIME_WAIT reuse

template <int k>
static void open_channels(int party, int L, vector<unique_ptr<NetIO>>& ch) {
    const int base = g_port_base;
    g_port_base += L + 2;
    for (int t = 0; t < L; ++t)
        ch.push_back(party == ALICE ? NetIO::listen(base + t)
                                    : NetIO::connect(peer_ip(), base + t));
}

// Test A: parent (lane 0) + L-1 clones over a contiguous partition of [0,total).
template <int k>
static void test_assembled(int party, int L, bool malicious, int64_t total) {
    vector<unique_ptr<NetIO>> ch;
    open_channels<k>(party, L, ch);
    // Partition is a pure function of (total, L) -- identical on both parties,
    // peer-independent (the cross-peer-consistency requirement, at 2 parties).
    auto lo = [&](int t){ return (total * (int64_t)t) / L; };
    auto hi = [&](int t){ return (total * (int64_t)(t + 1)) / L; };

    block* out = new block[total];

    // Parent on channel 0 = lane 0. Its first begin() bootstraps (base OT + PPRF
    // check); it draws range 0; after end() it is bootstrapped + out-of-session,
    // so it is cloneable and its one-time base-OT extraction check has fired.
    SoftSpoken<k> parent(party, ch[0].get(), malicious);
    parent.begin();
    parent.next_n(out + lo(0), hi(0) - lo(0));
    parent.end();

    // Lanes 1..L-1: clones on channels 1..L-1, cloned in the same order on both
    // parties, so each takes the same child of the parent's session id.
    vector<unique_ptr<SoftSpoken<k>>> lanes;
    for (int t = 1; t < L; ++t) {
        auto lane = parent.clone_lane(ch[t].get());
        lane->begin();
        lane->next_n(out + lo(t), hi(t) - lo(t));
        lane->end();
        lanes.push_back(std::move(lane));
    }

    // The assembled stream must be a valid RCOT: verify each element's COT
    // relation under the shared Delta, over channel 0.
    verify_rcot(&parent, ch[0].get(), party, out, total);
    cout << "[A k=" << k << " L=" << L << (malicious ? " mal" : " semi") << "] ";
    delete[] out;
}

// Test B: two clones of the parent and a clone of the first clone, SAME range
// -> all three outputs must differ pairwise.
template <int k>
static void test_domain_sep(int party, int64_t len) {
    vector<unique_ptr<NetIO>> ch;
    open_channels<k>(party, 4, ch);   // ch[0]=parent bootstrap, ch[1..3]=clones

    SoftSpoken<k> parent(party, ch[0].get(), /*malicious=*/true);
    parent.begin();
    { block* warm = new block[len]; parent.next_n(warm, len); delete[] warm; }
    parent.end();

    vector<block> out[3];
    for (auto& o : out) o.resize(len);
    auto l1 = parent.clone_lane(ch[1].get());
    l1->begin(); l1->next_n(out[0].data(), len); l1->end();
    auto l2 = parent.clone_lane(ch[2].get());
    l2->begin(); l2->next_n(out[1].data(), len); l2->end();
    auto l3 = l1->clone_lane(ch[3].get());
    l3->begin(); l3->next_n(out[2].data(), len); l3->end();

    // Each lane's session keys derive from its own id, so the keystreams over
    // the shared leaves differ. Identical outputs would be a silent COT reuse.
    for (int x = 0; x < 3; ++x)
        for (int y = x + 1; y < 3; ++y) {
            bool identical = true;
            for (int64_t i = 0; i < len; ++i)
                if (!cmpBlock(&out[x][i], &out[y][i], 1)) { identical = false; break; }
            expecting(!identical,
                      "clone_lane: two lanes produced IDENTICAL outputs (domain separation broken)");
        }
    cout << "[B k=" << k << " distinct] ";
}

int main(int argc, char** argv) {
    int party = parse_party(argv);
    g_port_base = peer_port();

    const int64_t total = (int64_t{1} << 12) + 101;   // spans several chunks + a tail
    for (bool mal : {false, true}) {
        test_assembled<4>(party, 1, mal, total);
        test_assembled<4>(party, 2, mal, total);
        test_assembled<4>(party, 4, mal, total);
        test_assembled<8>(party, 2, mal, total);
        test_assembled<8>(party, 4, mal, total);
    }
    test_domain_sep<4>(party, (int64_t{1} << 11) + 7);
    test_domain_sep<8>(party, (int64_t{1} << 11) + 7);

    if (party == ALICE) cout << "\nclone_lane: all tests passed." << endl;
    return 0;
}
