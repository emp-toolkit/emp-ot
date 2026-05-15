#ifndef EMP_OT_EXTENSION_H__
#define EMP_OT_EXTENSION_H__

#include <cassert>
#include <cstring>
#include <algorithm>
#include "emp-ot/ot.h"

namespace emp {

// Common base class for OT extensions (IKNP / SoftSpokenOT / FerretCOT).
//
// Defines the streaming RCOT contract — chunk_ots() blocks per
// _next, lifecycle is _begin -> loop _next* -> _end — and provides
// the one-shot rcot_send / rcot_recv wrappers shared across all
// three backends.
//
// Subclasses override the protected do_* virtuals; the public
// _begin/_next/_end are concrete and enforce the session lifecycle
// (assert + flag flip) before delegating, so each backend gets the
// same in_*_session_ tripwire for free.
class OTExtension : public RandomCOT {
public:
    // Per-_next chunk size in OTs. Subclasses pick a value that's
    // natural for their pipeline (one cGGM tree's leaves for ferret;
    // the max-batch unit for IKNP / SoftSpoken). Constant per
    // instance after setup.
    virtual int64_t chunk_ots() const = 0;

    // Streaming primitives. Each _next writes exactly chunk_ots()
    // blocks. Lifecycle: _begin -> loop _next* -> _end. Sessions
    // can be re-started.
    void rcot_send_begin() {
        assert(!in_send_session_ && "rcot_send_begin: previous session not ended");
        do_rcot_send_begin();
        in_send_session_ = true;
    }
    void rcot_send_next(block* out) {
        assert(in_send_session_ && "rcot_send_next: call rcot_send_begin first");
        do_rcot_send_next(out);
    }
    void rcot_send_end() {
        assert(in_send_session_ && "rcot_send_end: no active session");
        do_rcot_send_end();
        in_send_session_ = false;
    }
    void rcot_recv_begin() {
        assert(!in_recv_session_ && "rcot_recv_begin: previous session not ended");
        do_rcot_recv_begin();
        in_recv_session_ = true;
    }
    void rcot_recv_next(block* out) {
        assert(in_recv_session_ && "rcot_recv_next: call rcot_recv_begin first");
        do_rcot_recv_next(out);
    }
    void rcot_recv_end() {
        assert(in_recv_session_ && "rcot_recv_end: no active session");
        do_rcot_recv_end();
        in_recv_session_ = false;
    }

    // RandomCOT one-shot, implemented once here in terms of the
    // streaming primitives + a per-instance leftover buffer. The
    // leftover holds the unused suffix of one chunk when num isn't
    // a multiple of chunk_ots(); subsequent calls drain it before
    // producing more chunks, so repeated tiny rcot_send calls don't
    // pay a fresh chunk per call.
    //
    // Setup is triggered through the streaming begin path: each
    // subclass's do_rcot_*_begin runs setup() on first entry when
    // its setup_done flag is still false. Callers may also invoke
    // setup() explicitly (e.g. to inject an external Δ) before the
    // first rcot_* call; the second setup() call is a no-op.
    void rcot_send(block* data, int64_t num) final override {
        rcot_run(data, num, /*sender=*/true);
    }
    void rcot_recv(block* data, int64_t num) final override {
        rcot_run(data, num, /*sender=*/false);
    }

    ~OTExtension() override {
        assert(!in_send_session_ && "~OTExtension: missing rcot_send_end");
        assert(!in_recv_session_ && "~OTExtension: missing rcot_recv_end");
    }

protected:
    // Subclass implementation hooks. Called from the public concrete
    // _begin/_next/_end above after the lifecycle asserts have
    // passed. do_*_begin must trigger setup() on its own first-call
    // path (each subclass keeps its own setup-done flag under a
    // different name).
    virtual void do_rcot_send_begin() = 0;
    virtual void do_rcot_send_next(block* out) = 0;
    virtual void do_rcot_send_end() = 0;
    virtual void do_rcot_recv_begin() = 0;
    virtual void do_rcot_recv_next(block* out) = 0;
    virtual void do_rcot_recv_end() = 0;

private:
    bool in_send_session_ = false;
    bool in_recv_session_ = false;

    // One leftover buffer per instance; role is fixed at construction
    // so send and recv never share a single instance.
    BlockVec leftover_;
    int      leftover_pos_   = 0;
    int      leftover_count_ = 0;

    // Drain up to `take_max` blocks of leftover into `out`.
    int64_t drain_leftover(block* out, int64_t take_max) {
        if (leftover_count_ == 0) return 0;
        int64_t take = std::min<int64_t>(take_max, leftover_count_);
        memcpy(out, leftover_.data() + leftover_pos_, take * sizeof(block));
        leftover_pos_   += (int)take;
        leftover_count_ -= (int)take;
        return take;
    }

    // Shared body for both rcot_send and rcot_recv. `sender` picks
    // which streaming primitives to call; the loop / leftover logic
    // is the same.
    void rcot_run(block* data, int64_t num, bool sender) {
        const int64_t chunk = chunk_ots();
        int64_t produced = drain_leftover(data, num);
        if (produced == num) return;

        if (sender) rcot_send_begin(); else rcot_recv_begin();
        while (produced + chunk <= num) {
            if (sender) rcot_send_next(data + produced);
            else        rcot_recv_next(data + produced);
            produced += chunk;
        }
        if (produced < num) {
            // Partial tail: produce one more chunk into leftover_,
            // copy the user-requested prefix to data, save the
            // suffix for the next call.
            if (leftover_.empty()) leftover_.resize(chunk);
            if (sender) rcot_send_next(leftover_.data());
            else        rcot_recv_next(leftover_.data());
            int64_t take = num - produced;
            memcpy(data + produced, leftover_.data(), take * sizeof(block));
            leftover_pos_   = (int)take;
            leftover_count_ = (int)(chunk - take);
        }
        if (sender) rcot_send_end(); else rcot_recv_end();
    }
};

}  // namespace emp
#endif  // EMP_OT_EXTENSION_H__
