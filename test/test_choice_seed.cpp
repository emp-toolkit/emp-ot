// Seeded choices (Ferret::set_choice_seed), for Ferret and SilentFerret. The
// receiver runs three instances of each kind: two with one choice seed, and a
// third with another, all with one LPN seed. The sender runs them with
// independent Δs, as two different senders would. For each kind and mode:
//   - every instance's COTs are correct;
//   - the two instances with one seed give the same choice bit at every
//     position, over several rounds (Ferret) or prepaid batches
//     (SilentFerret), and the bits are balanced;
//   - the third instance agrees with them only by chance;
//   - their MACs differ at every position, so two senders who combine their
//     keys cannot cancel them out: K1 ⊕ K2 = b · (Δ1 ⊕ Δ2) would need M1 = M2;
//   - in malicious mode the masks of their last consistency check differ, so
//     the receiver's check reply, the mask's choice bits XOR a function of the
//     noise positions, is padded afresh in each instance.
// The sets are the shipped ferret_b9 (direct SoftSpoken bootstrap) and
// ferret_b11 (nested ferret_b9 bootstrap), plus two small custom sets with
// short rounds, one of each kind, so that several rounds stay cheap.
//
// Two-party via `run`.
#include "emp-ot/emp-ot.h"
#include "test/test.h"
#include <cstring>
#include <memory>
#include <string>
#include <vector>
using namespace emp;
using namespace std;

// 576 user COTs per round; M = 1,472 bootstraps directly from SoftSpoken.
static constexpr PrimalLPNParameter kShortDirect(64, 10, 5);
// 39,424 user COTs per round; M = 267,672 bootstraps through ferret_b9.
static constexpr PrimalLPNParameter kShortNested(600, 18, 9);

static constexpr block kSeedA = makeBlock(0x63686f6963652d61ULL, 0x2d73656564000001ULL);
static constexpr block kSeedB = makeBlock(0x63686f6963652d62ULL, 0x2d73656564000002ULL);
static constexpr block kLpnSeed = makeBlock(0x6c706e2d6d617472ULL, 0x69782d7365656400ULL);

// The masks of the instance's most recent consistency check: the first 128
// base COTs of the current round. Ferret: valid after end(). SilentFerret:
// right after begin(n_ots), before the cursor rolls to the next round.
// Test-only view of protected state.
template <class Base>
struct Probe : Base {
    using Base::Base;
    void copy_check_masks(block *out) const {
        memcpy(out, this->carry_curr_.data(), kConsistCheckCotNum * sizeof(block));
    }
};

struct Run {
    BlockVec out;            // the instance's COTs
    block delta;             // sender's Δ (zero on the receiver)
    block masks[kConsistCheckCotNum];
};

// One Ferret instance: `n` COTs through rcot(), across rounds when n exceeds a
// round.
static Run run_ferret(NetIO *io, int party, bool malicious,
                      const PrimalLPNParameter &param, const block &seed,
                      int64_t n) {
    Probe<Ferret> ot(party, io, malicious, nullptr, param);
    ot.set_choice_seed(party == BOB ? &seed : nullptr, kLpnSeed);
    Run r;
    r.out.resize(n);
    ot.rcot(r.out.data(), n);
    r.delta = (party == ALICE) ? ot.Delta : zero_block;
    ot.copy_check_masks(r.masks);
    return r;
}

// One SilentFerret instance: two prepaid batches, each spanning two rounds, so
// the second batch's check is masked afresh and its base comes from the first
// batch's refill trees.
static Run run_silent(NetIO *io, int party, bool malicious,
                      const PrimalLPNParameter &param, const block &seed,
                      int64_t n_per_batch) {
    Probe<SilentFerret> ot(party, io, malicious, param);
    ot.set_choice_seed(party == BOB ? &seed : nullptr, kLpnSeed);
    Run r;
    r.out.resize(2 * n_per_batch);
    for (int batch = 0; batch < 2; ++batch) {
        ot.begin(n_per_batch);
        if (batch == 1) ot.copy_check_masks(r.masks);
        ot.next_n(r.out.data() + batch * n_per_batch, n_per_batch);
        ot.end();
    }
    r.delta = (party == ALICE) ? ot.Delta : zero_block;
    return r;
}

// Receiver: M ⊕ LSB(M)·Δ must equal the sender's K at every position.
static void verify(NetIO *io, int party, const Run &r, const char *what) {
    const int64_t n = (int64_t)r.out.size();
    io->sync();
    if (party == ALICE) {
        io->send_block(&r.delta, 1);
        io->send_block(r.out.data(), n);
    } else {
        block delta;
        BlockVec k(n);
        io->recv_block(&delta, 1);
        io->recv_block(k.data(), n);
        const block ch[2] = {zero_block, delta};
        for (int64_t i = 0; i < n; ++i) {
            const block m = r.out[i] ^ ch[getLSB(r.out[i])];
            expecting(cmpBlock(&m, &k[i], 1), what);
        }
    }
    io->flush();
}

template <class RunOne>
static void check_kind(NetIO *io, int party, const string &tag, bool malicious,
                       RunOne run_one) {
    const string label = tag + (malicious ? " mali" : " semi");
    Run a = run_one(io, party, malicious, kSeedA);
    Run b = run_one(io, party, malicious, kSeedA);
    Run c = run_one(io, party, malicious, kSeedB);
    verify(io, party, a, (label + ": instance 1 COT failed").c_str());
    verify(io, party, b, (label + ": instance 2 COT failed").c_str());
    verify(io, party, c, (label + ": instance 3 COT failed").c_str());

    if (party == BOB) {
        const int64_t n = (int64_t)a.out.size();
        int64_t ones = 0, same_mac = 0, agree_c = 0;
        for (int64_t i = 0; i < n; ++i) {
            const bool ba = getLSB(a.out[i]), bb = getLSB(b.out[i]);
            expecting(ba == bb, (label + ": seeded choice bits differ").c_str());
            ones += ba;
            same_mac += cmpBlock(&a.out[i], &b.out[i], 1);
            agree_c += (ba == getLSB(c.out[i]));
        }
        expecting(4 * ones > n && 4 * ones < 3 * n,
                  (label + ": seeded choice bits are unbalanced").c_str());
        expecting(4 * agree_c < 3 * n,
                  (label + ": another seed gave the same choice bits").c_str());
        expecting(same_mac == 0,
                  (label + ": instances with one seed share a MAC").c_str());
        if (malicious) {
            int64_t same_mask_bit = 0;
            for (int i = 0; i < kConsistCheckCotNum; ++i)
                same_mask_bit += (getLSB(a.masks[i]) == getLSB(b.masks[i]));
            expecting(same_mask_bit < kConsistCheckCotNum,
                      (label + ": instances with one seed share a check mask").c_str());
        }
        cout << label << ": " << n << " COTs per instance, choice bits aligned, "
             << (malicious ? "MACs and check masks fresh" : "MACs fresh") << endl;
    }
}

int main(int argc, char **argv) {
    const int party = parse_party(argv);
    const int port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    for (bool mali : {false, true}) {
        // Ferret: three rounds of the short sets, part of one round of the
        // shipped ones.
        check_kind(io.get(), party, "Ferret(short direct)", mali,
            [](NetIO *x, int p, bool m, const block &s) {
                return run_ferret(x, p, m, kShortDirect, s,
                    3 * ((kShortDirect.t - kShortDirect.refill_trees) << kShortDirect.tree_depth) + 17);
            });
        check_kind(io.get(), party, "Ferret(short nested)", mali,
            [](NetIO *x, int p, bool m, const block &s) {
                return run_ferret(x, p, m, kShortNested, s,
                    3 * ((kShortNested.t - kShortNested.refill_trees) << kShortNested.tree_depth) + 17);
            });
        check_kind(io.get(), party, "Ferret(b9)", mali,
            [](NetIO *x, int p, bool m, const block &s) {
                return run_ferret(x, p, m, tuning::ferret_b9, s, 1 << 14);
            });
        check_kind(io.get(), party, "Ferret(b11)", mali,
            [](NetIO *x, int p, bool m, const block &s) {
                return run_ferret(x, p, m, tuning::ferret_b11, s, 1 << 14);
            });
        // SilentFerret: two batches of two rounds each.
        check_kind(io.get(), party, "SilentFerret(short direct)", mali,
            [](NetIO *x, int p, bool m, const block &s) {
                return run_silent(x, p, m, kShortDirect, s,
                    2 * ((kShortDirect.t - kShortDirect.refill_trees) << kShortDirect.tree_depth));
            });
        check_kind(io.get(), party, "SilentFerret(short nested)", mali,
            [](NetIO *x, int p, bool m, const block &s) {
                return run_silent(x, p, m, kShortNested, s,
                    2 * ((kShortNested.t - kShortNested.refill_trees) << kShortNested.tree_depth));
            });
    }
    return 0;
}
