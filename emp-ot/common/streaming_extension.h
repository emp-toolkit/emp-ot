#ifndef EMP_OT_STREAMING_EXTENSION_H__
#define EMP_OT_STREAMING_EXTENSION_H__

#include "emp-tool/emp-tool.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

// Single-role streaming-extension base. Both RCOT extensions and
// sVOLE extensions specialize this with their per-leaf carrier:
//
//   OTExtension : public StreamingExtension<block>            (RCOT)
//                 + rcot(data, num) from RandomCOT
//                 + Δ / base_ot / choice_prg
//   Svole<AuthValue> : public StreamingExtension<AuthValue> (sVOLE)
//
// Lifecycle: begin → loop next* → end. Two convenience draws sit on top
// of the begin/next/end primitives:
//   - run(data, num)   — one-shot: opens and closes a session per call,
//     draining a per-instance leftover buffer so non-chunk-multiple
//     requests don't pay a fresh chunk per call.
//   - next_n(dst, n)   — buffered draw *within* a caller-owned session
//     (begin once, draw incrementally, end once). Keeps the round-end
//     work amortized over the whole session instead of per call, which
//     matters for callers that consume a few elements at a time.
// Lazy setup is gated by the `setup_done` flag (subclass flips it inside
// its first begin).
//
// Each instance is single-role at runtime (`party` is fixed at
// construction). begin/next/end are virtual — subclasses override them
// directly. Session-tripwire enforcement (no double-begin, no end
// without begin, no destruction in-session) is provided by protected
// helpers (enter_session_ / expect_in_session_ / exit_session_) that
// the subclass calls from its overrides.

namespace emp {

template <typename Element>
class StreamingExtension {
public:
    int  party = 0;
    bool malicious = false;
    bool setup_done = false;

    // Per-chunk extend (next()) traffic direction: does the ALICE-role party
    // (party == ALICE) send during next(), or receive? Callers that interleave
    // a streaming extension with a fixed-direction protocol on the same socket
    // read this to place the send-dominant role on the send channel and avoid
    // flipping a socket's direction mid-stream. Subclasses redefine it from
    // their own next() body; the default (false = ALICE recv-dominant) matches
    // IKNP / SoftSpoken. (begin()/end() bookends may differ but run before/after
    // the streaming loop, so only the per-chunk direction matters here.)
    static constexpr bool kSenderSendsOnExtend = false;

    virtual int64_t chunk_size() const = 0;

    // Streaming lifecycle. Each subclass overrides these with its
    // bootstrap / per-chunk / round-end body. The override is
    // expected to call enter_session_() at the top of begin(),
    // expect_in_session_() before work and exit_session_() at the end of
    // end(), and expect_in_session_() inside next() — the protected helpers
    // below enforce the tripwire without the NVI dispatcher layer.
    virtual void begin() = 0;
    virtual void next(Element *out) = 0;
    virtual void end() = 0;

    // One-shot: produce `num` outputs into `data`, draining a
    // per-instance leftover buffer first so a partial tail from a
    // previous call is consumed before extending again. Non-virtual;
    // works for any subclass via the begin/next/end virtuals.
    void run(Element *data, int64_t num) {
        expecting(!in_session_,
                  "StreamingExtension::run: active streaming session");
        expecting(num >= 0, "StreamingExtension::run: negative element count");
        expecting(num <= max_element_count_(),
                  "StreamingExtension::run: element byte count overflow");
        expecting(num == 0 || data != nullptr,
                  "StreamingExtension::run: null output for nonzero count");
        if (num == 0) return;

        const int64_t chunk = chunk_size();
        validate_chunk_size_(chunk);
        int64_t produced = drain_leftover(data, num);
        if (produced == num) return;

        begin();
        while (chunk <= num - produced) {
            next(data + produced);
            produced += chunk;
        }
        if (produced < num) {
            if (leftover_.size() < static_cast<size_t>(chunk))
                leftover_.resize(static_cast<size_t>(chunk));
            next(leftover_.data());
            int64_t take = num - produced;
            std::memcpy(data + produced, leftover_.data(),
                        static_cast<size_t>(take) * sizeof(Element));
            leftover_pos_   = take;
            leftover_count_ = chunk - take;
        }
        end();
    }

    // Buffered multi-element draw within an open session: produce `n`
    // elements into `dst`. Lets a caller consume the stream incrementally
    // (even one element at a time) while the round-end work (refill trees +
    // malicious check) amortizes over the whole session — unlike run(),
    // which opens/closes a session per call. The caller owns the session:
    // begin() once (e.g. in its constructor), draw via next_n(dst, n),
    // end() once (e.g. in its destructor). enter_session_ resets the buffer,
    // so a fresh begin() never serves a stale tail. (Distinct name, not
    // `next`, so it isn't hidden by the subclass's single-element next().)
    //
    // Whole chunks are produced *straight into* `dst` (next() writes
    // chunk_size() elements with no intermediate copy); only a prior partial
    // tail and a trailing sub-chunk remainder ever pass through leftover_, so
    // the per-call copy is bounded by one chunk regardless of n (vs copying
    // all n through the buffer). Mirrors run() minus the begin()/end().
    void next_n(Element *dst, int64_t n) {
        expecting(n >= 0,
                  "StreamingExtension::next_n: negative element count");
        expecting(n <= max_element_count_(),
                  "StreamingExtension::next_n: element byte count overflow");
        expecting(n == 0 || dst != nullptr,
                  "StreamingExtension::next_n: null output for nonzero count");
        expecting(in_session_,
                  "StreamingExtension::next_n: call begin first");
        if (n == 0) return;

        const int64_t chunk = chunk_size();
        validate_chunk_size_(chunk);
        // 1. Consume any partial tail left by a previous call (stream order
        //    requires these elements come first).
        int64_t got = drain_leftover(dst, n);
        // 2. Fill whole chunks directly in the caller's buffer — no copy.
        while (chunk <= n - got) {
            next(dst + got);
            got += chunk;
        }
        // 3. Sub-chunk remainder: produce one chunk into leftover_, copy the
        //    needed prefix, and keep the rest for the next call.
        if (got < n) {
            if (leftover_.size() < static_cast<size_t>(chunk))
                leftover_.resize(static_cast<size_t>(chunk));
            next(leftover_.data());
            int64_t take = n - got;
            std::memcpy(dst + got, leftover_.data(),
                        static_cast<size_t>(take) * sizeof(Element));
            leftover_pos_   = take;
            leftover_count_ = chunk - take;
        }
    }

    virtual ~StreamingExtension() {
        // Always-on (not just debug): a missed end() leaves the wire
        // transcript / FS state desynchronized — silently OK in NDEBUG
        // would hide the bug at runtime in production.
        expecting(!in_session_,
                  "~StreamingExtension: destructed without calling end()");
    }

protected:
    StreamingExtension(int party_, bool malicious_)
        : party(party_), malicious(malicious_) {}

    // Session tripwire helpers. Subclass overrides call these from
    // their begin/end/next — the base
    // can't manage the flag automatically without an NVI layer.
    void enter_session_() {
        expecting(!in_session_, "begin: previous session not ended");
        in_session_ = true;
        // Drop any leftover from a prior session so next_n() / run() never
        // serve a stale chunk tail across a begin().
        leftover_count_ = 0;
    }
    void exit_session_() {
        expecting(in_session_, "end: no active session");
        in_session_ = false;
    }
    void expect_in_session_() const {
        expecting(in_session_,
                  "StreamingExtension: no active session; call begin first");
    }

private:
    bool in_session_ = false;
    std::vector<Element> leftover_;
    int64_t leftover_pos_   = 0;
    int64_t leftover_count_ = 0;

    static constexpr int64_t max_element_count_() {
        return std::numeric_limits<int64_t>::max() /
               static_cast<int64_t>(sizeof(Element));
    }

    static void validate_chunk_size_(int64_t chunk) {
        expecting(chunk > 0,
                  "StreamingExtension: chunk size must be positive");
        expecting(chunk <= max_element_count_(),
                  "StreamingExtension: chunk byte count overflow");
    }

    int64_t drain_leftover(Element *out, int64_t take_max) {
        if (leftover_count_ == 0) return 0;
        int64_t take = std::min<int64_t>(take_max, leftover_count_);
        std::memcpy(out, leftover_.data() + leftover_pos_,
                    static_cast<size_t>(take) * sizeof(Element));
        leftover_pos_   += take;
        leftover_count_ -= take;
        return take;
    }
};

}  // namespace emp
#endif  // EMP_OT_STREAMING_EXTENSION_H__
