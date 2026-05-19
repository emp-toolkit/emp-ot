#ifndef EMP_OT_SVOLE_EXTENSION_H__
#define EMP_OT_SVOLE_EXTENSION_H__

#include "emp-tool/emp-tool.h"
#include <cassert>
#include <cstring>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <memory>

// Shared sVOLE infrastructure:
//   - AuthValue<F, K>: the val/mac carrier struct, val-first across
//     all Policies so consumers casting to packed 128-bit ints see
//     val in low 64.
//   - SVoleExtension<AuthValueT>: streaming-contract base class for
//     sVOLE extensions, parallel to OTExtension. Both F2kVOLE and
//     FpVOLE subclass this.
//       - chunk_extends() elements per _next
//       - lifecycle: _begin -> loop _next* -> _end (session tripwire)
//       - one-shot extend(out, num) drains a per-instance leftover
//         so non-chunk-multiple requests don't pay a fresh chunk per
//         call
//       - lazy bootstrap on first do_extend_begin, gated by setup_done
//     Subclass owns Δ / choice randomness plumbing and implements the
//     three do_* virtuals; the public _begin/_next/_end here enforce
//     session lifecycle before delegating.

namespace emp {

// Carrier for one sVOLE pair. Used everywhere — Mpsvole leaves,
// pre_curr_/_next_, vole_buf_, the API output, and the LPN element
// type. K is the value type; F is the mac type. ALICE (sender) holds
// val=0 throughout; BOB (receiver) holds val at sparse positions
// (after MPFSS) and dense vals (after LPN).
//
// Field order is val-first so that a Policy whose F and K both fit
// in 64 bits (e.g. MersennePolicy61) sees AuthValue alias a packed
// 128-bit int with val in the low 64 — natural reading order and
// SIMD-friendly for `_mm_add_epi64`.
template <typename F_, typename K_>
struct AuthValue {
  using F = F_;
  using K = K_;
  K val;
  F mac;
};

template <typename AuthValueT>
class SVoleExtension {
public:
    int  party = 0;
    bool malicious = false;
    bool setup_done = false;

    virtual int64_t chunk_extends() const = 0;

    void extend_begin() {
        assert(!in_session_ && "extend_begin: previous session not ended");
        do_extend_begin();
        in_session_ = true;
    }
    void extend_next(AuthValueT *out) {
        assert(in_session_ && "extend_next: call extend_begin first");
        do_extend_next(out);
    }
    void extend_end() {
        assert(in_session_ && "extend_end: no active session");
        do_extend_end();
        in_session_ = false;
    }

    void extend(AuthValueT *data, int64_t num) {
        const int64_t chunk = chunk_extends();
        int64_t produced = drain_leftover(data, num);
        if (produced == num) return;

        extend_begin();
        while (produced + chunk <= num) {
            extend_next(data + produced);
            produced += chunk;
        }
        if (produced < num) {
            if ((int64_t)leftover_.size() < chunk) leftover_.resize(chunk);
            extend_next(leftover_.data());
            int64_t take = num - produced;
            std::memcpy(data + produced, leftover_.data(),
                        take * sizeof(AuthValueT));
            leftover_pos_   = take;
            leftover_count_ = chunk - take;
        }
        extend_end();
    }

    virtual ~SVoleExtension() {
        assert(!in_session_ && "~SVoleExtension: missing extend_end");
    }

protected:
    SVoleExtension(int party_, bool malicious_)
        : party(party_), malicious(malicious_) {}

    virtual void do_extend_begin() = 0;
    virtual void do_extend_next(AuthValueT *out) = 0;
    virtual void do_extend_end() = 0;

private:
    bool in_session_ = false;
    std::vector<AuthValueT> leftover_;
    int64_t leftover_pos_   = 0;
    int64_t leftover_count_ = 0;

    int64_t drain_leftover(AuthValueT *out, int64_t take_max) {
        if (leftover_count_ == 0) return 0;
        int64_t take = std::min<int64_t>(take_max, leftover_count_);
        std::memcpy(out, leftover_.data() + leftover_pos_,
                    take * sizeof(AuthValueT));
        leftover_pos_   += take;
        leftover_count_ -= take;
        return take;
    }
};

} // namespace emp
#endif
