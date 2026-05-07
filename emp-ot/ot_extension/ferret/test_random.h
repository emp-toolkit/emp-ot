#ifndef EMP_FERRET_TEST_RANDOM_H__
#define EMP_FERRET_TEST_RANDOM_H__
#include "emp-tool/emp-tool.h"
#include <atomic>
#include <cstdint>

// Test-only deterministic-PRG hook for ferret. When the counter is
// non-zero, the two ferret-internal PRG sites in the rcot path
// (SPCOT_Sender ctor's `seed`, LpnF2::seed_gen's per-extend seed)
// derive their seed from the counter instead of OS randomness,
// which lets a tracing test produce byte-identical wire output
// across runs. Default is zero, meaning production behavior
// (OS-random) is unchanged. Setup-phase randomness (Delta sampling,
// IKNP, OTCO) is not covered — tests that need byte-exact
// reproducibility snapshot the post-setup state via assemble_state
// and replay rcot from there.

namespace emp { namespace ferret_test {

inline std::atomic<uint64_t>& test_seed_counter() {
    static std::atomic<uint64_t> c{0};
    return c;
}

// Returns true and writes a fresh deterministic seed to *out if
// the test mode is enabled. Returns false otherwise; caller falls
// back to its normal randomness.
inline bool maybe_test_seed(block* out) {
    auto& c = test_seed_counter();
    uint64_t v = c.load(std::memory_order_relaxed);
    if (v == 0) return false;
    *out = makeBlock(0xC0DEDEA1ULL, c.fetch_add(1, std::memory_order_relaxed));
    return true;
}

}}  // namespace emp::ferret_test
#endif
