// OTExtension::check() regression coverage.
//
// For each public RCOT extension backend:
//   * declare the session's total next_n() demand at begin();
//   * generate a partial next_n() chunk and certify it with check();
//   * consume only its already-certified tail and prove a repeated check is
//     wire-free (the tail survived the internal end/begin continuation);
//   * cross into a final production unit, check again, and verify the same
//     retained-tail property;
//   * validate every returned RCOT after the ordinary final end().
//
// The default-CSW cases are intentional: the first check also has to finish
// CSW's deferred extraction check, even though the public session stays open.
// SoftSpoken<8> additionally runs with BMM to cover a blocking, non-deferred
// base-OT path.

#include "emp-ot/emp-ot.h"
#include "test/test.h"

#include <cstdint>
#include <iostream>
#include <memory>

using namespace emp;

namespace {

struct IoCounts {
    uint64_t sent;
    uint64_t received;
    uint64_t flushes;
};

IoCounts counts(const NetIO& io) {
    return {io.send_counter, io.recv_counter, io.flushes_count};
}

bool operator==(const IoCounts& lhs, const IoCounts& rhs) {
    return lhs.sent == rhs.sent && lhs.received == rhs.received &&
           lhs.flushes == rhs.flushes;
}

void check_backend(const char* name, std::unique_ptr<OTExtension> ot,
                   NetIO* io, int party,
                   int64_t expected_counted_tail_bytes = -1) {
    const int64_t chunk = ot->chunk_size();
    expecting(chunk > 3, "test_extension_check: chunk unexpectedly small");
    constexpr int64_t final_demand = 129;
    BlockVec out(static_cast<size_t>(chunk + final_demand));

    // The declared total spans several next_n() calls and every check()
    // continuation below. Backends without a sized-tail override retain their
    // historical full-chunk refill; SoftSpoken can finish at 128-COT
    // granularity once only 129 declared outputs remain.
    ot->begin(chunk + final_demand);
    // No extension chunk exists yet. With CSW this must nevertheless finish
    // the deferred base extraction check; with blocking BMM it is a no-op.
    // Either way, the public session remains active for the first draw.
    ot->check();

    // Produce chunk A, expose A[0], retain A[1..], then certify all of A.
    ot->next_n(out.data(), 1);
    ot->check();

    // Drawing A[1] touches no backend state. check() must therefore be a
    // no-op: no generated chunk, no deferred base check, no flush.
    const IoCounts before_tail_a = counts(*io);
    ot->next_n(out.data() + 1, 1);
    ot->check();
    expecting(counts(*io) == before_tail_a,
              "OTExtension::check regenerated a certified tail");

    // Consume A[2..] and two outputs from the final production unit. At this
    // refill point exactly 129 declared outputs remain across all future
    // next_n() calls, even though this call itself needs only two of them.
    const IoCounts before_counted_tail = counts(*io);
    ot->next_n(out.data() + 2, chunk);
    const IoCounts after_counted_tail = counts(*io);
    if (expected_counted_tail_bytes >= 0) {
        const uint64_t expected =
            static_cast<uint64_t>(expected_counted_tail_bytes);
        const bool exact =
            party == ALICE
                ? after_counted_tail.received -
                              before_counted_tail.received == expected &&
                      after_counted_tail.sent == before_counted_tail.sent
                : after_counted_tail.sent - before_counted_tail.sent ==
                              expected &&
                      after_counted_tail.received == before_counted_tail.received;
        expecting(exact,
                  "counted SoftSpoken tail did not use its exact wire size");
    }
    ot->check();

    const IoCounts before_tail_b = counts(*io);
    ot->next_n(out.data() + chunk + 2, final_demand - 2);
    ot->check();
    expecting(counts(*io) == before_tail_b,
              "OTExtension::check did not retain the second certified tail");

    // Closing an idle continuation immediately after check must not pay an
    // empty sacrificial consistency exchange.
    const IoCounts before_end = counts(*io);
    ot->end();
    expecting(counts(*io) == before_end,
              "end emitted an empty post-check consistency exchange");
    verify_rcot(ot.get(), io, party, out.data(), chunk + final_demand);

    // Reopen after the optimized idle close. This is especially important for
    // Ferret: the close path must have restored the empty continuation's carry
    // swap so this begin() advances to the certified next-round base. Ordinary
    // begin() also drops the old caller-owned tail, as before check() existed.
    BlockVec reopened(3);
    ot->begin();
    ot->next_n(reopened.data(), static_cast<int64_t>(reopened.size()));
    ot->check();
    const IoCounts before_reopened_end = counts(*io);
    ot->end();
    expecting(counts(*io) == before_reopened_end,
              "reopened end emitted an empty post-check exchange");
    verify_rcot(ot.get(), io, party, reopened.data(),
                static_cast<int64_t>(reopened.size()));

    if (party == ALICE)
        std::cout << name << " check/tail: OK\n";
}

template <typename Make>
void with_sibling(int party, NetIO* anchor, const char* name, Make&& make,
                  int64_t expected_counted_tail_bytes = -1) {
    auto io = anchor->make_sibling();
    check_backend(name, make(io.get()), io.get(), party,
                  expected_counted_tail_bytes);
    io->flush();
}

}  // namespace

int main(int argc, char** argv) {
    const int party = parse_party(argv);
    const int port = peer_port();
    auto anchor = (party == ALICE)
                      ? NetIO::listen(port, /*quiet=*/true)
                      : NetIO::connect(peer_ip(), port, /*quiet=*/true);
    anchor->sync();

    with_sibling(party, anchor.get(), "IKNP", [&](IOChannel* io) {
        return std::unique_ptr<OTExtension>(
            new IKNP(party, io, /*malicious=*/true));
    });
    with_sibling(party, anchor.get(), "SoftSpoken<8>", [&](IOChannel* io) {
        return std::unique_ptr<OTExtension>(
            new SoftSpoken<8>(party, io, /*malicious=*/true));
    }, (SoftSpoken<8>::n - 1) * 2 * static_cast<int64_t>(sizeof(block)));
    with_sibling(party, anchor.get(), "SoftSpoken<8> + BMM",
                 [&](IOChannel* io) {
        return std::unique_ptr<OTExtension>(new SoftSpoken<8>(
            party, io, /*malicious=*/true, std::make_unique<BMM>(io)));
    }, (SoftSpoken<8>::n - 1) * 2 * static_cast<int64_t>(sizeof(block)));
    with_sibling(party, anchor.get(), "Ferret(b11)", [&](IOChannel* io) {
        return std::unique_ptr<OTExtension>(
            new Ferret(party, io, /*malicious=*/true, nullptr,
                       tuning::ferret_b11));
    });
    with_sibling(party, anchor.get(), "SilentFerret(b11)",
                 [&](IOChannel* io) {
        return std::unique_ptr<OTExtension>(
            new SilentFerret(party, io, /*malicious=*/true,
                             tuning::ferret_b11));
    });

    return 0;
}
