#ifndef EMP_OT_STREAMING_EXTENSION_H__
#define EMP_OT_STREAMING_EXTENSION_H__

#include "emp-tool/emp-tool.h"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

// Single-role streaming-extension base. Both RCOT extensions and
// sVOLE extensions specialize this with their per-leaf carrier:
//
//   OTExtension : public StreamingExtension<block>            (RCOT)
//                 + rcot_begin/next/end (single-role lifecycle aliases)
//                 + send_rcot / recv_rcot (dual-role one-shot from RandomCOT)
//                 + Δ / base_ot / choice_prg
//   Svole<AuthValue, IO> : public StreamingExtension<AuthValue> (sVOLE)
//
// Lifecycle: begin → loop next* → end. One-shot wrapper run(data, num)
// drains a per-instance leftover buffer so non-chunk-multiple requests
// don't pay a fresh chunk per call. Lazy setup is gated by the
// `setup_done` flag (subclass flips it inside its first do_begin).
//
// Each instance is single-role at runtime (`party` is fixed at
// construction). OTExtension exposes the lifecycle as the
// role-agnostic rcot_begin/next/end, plus the dual-role one-shot
// send_rcot/recv_rcot inherited from RandomCOT.

namespace emp {

template <typename Element>
class StreamingExtension {
public:
    int  party = 0;
    bool malicious = false;
    bool setup_done = false;

    virtual int64_t chunk_size() const = 0;

    void begin() {
        assert(!in_session_ && "begin: previous session not ended");
        do_begin();
        in_session_ = true;
    }
    void next(Element *out) {
        assert(in_session_ && "next: call begin first");
        do_next(out);
    }
    void end() {
        assert(in_session_ && "end: no active session");
        do_end();
        in_session_ = false;
    }

    // One-shot: produce `num` outputs into `data`, draining a
    // per-instance leftover buffer first so a partial tail from a
    // previous call is consumed before extending again.
    void run(Element *data, int64_t num) {
        const int64_t chunk = chunk_size();
        int64_t produced = drain_leftover(data, num);
        if (produced == num) return;

        begin();
        while (produced + chunk <= num) {
            next(data + produced);
            produced += chunk;
        }
        if (produced < num) {
            if ((int64_t)leftover_.size() < chunk) leftover_.resize(chunk);
            next(leftover_.data());
            int64_t take = num - produced;
            std::memcpy(data + produced, leftover_.data(),
                        take * sizeof(Element));
            leftover_pos_   = take;
            leftover_count_ = chunk - take;
        }
        end();
    }

    virtual ~StreamingExtension() {
        // Always-on (not just debug): a missed end() leaves the wire
        // transcript / FS state desynchronized — silently OK in NDEBUG
        // would hide the bug at runtime in production.
        if (in_session_)
            error("~StreamingExtension: destructed without calling end()");
    }

protected:
    StreamingExtension(int party_, bool malicious_)
        : party(party_), malicious(malicious_) {}

    virtual void do_begin() = 0;
    virtual void do_next(Element *out) = 0;
    virtual void do_end() = 0;

private:
    bool in_session_ = false;
    std::vector<Element> leftover_;
    int64_t leftover_pos_   = 0;
    int64_t leftover_count_ = 0;

    int64_t drain_leftover(Element *out, int64_t take_max) {
        if (leftover_count_ == 0) return 0;
        int64_t take = std::min<int64_t>(take_max, leftover_count_);
        std::memcpy(out, leftover_.data() + leftover_pos_,
                    take * sizeof(Element));
        leftover_pos_   += take;
        leftover_count_ -= take;
        return take;
    }
};

}  // namespace emp
#endif  // EMP_OT_STREAMING_EXTENSION_H__
