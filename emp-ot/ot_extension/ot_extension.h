#ifndef EMP_OT_EXTENSION_H__
#define EMP_OT_EXTENSION_H__

#include <cassert>
#include <cstring>
#include <algorithm>
#include <memory>
#include "emp-ot/ot.h"
#include "emp-ot/base_ot/pvw.h"

namespace emp {

// Common base class for OT extensions (IKNP / SoftSpokenOT / Ferret).
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
//
// Role / config plumbing — `party`, `malicious`, `setup_done`, the
// owned `base_ot`, and the sender-side random Δ with LSB pinned to
// 1 — also live here so subclasses don't redeclare them.
class OTExtension : public RandomCOT {
public:
    // Role; locked at construction. is_ot_sender() (ALICE) iff this
    // instance produces sender-side RCOT outputs. The OT-sender role
    // also serves as the IOChannel FS send_first side and owns Δ.
    int  party = 0;
    bool malicious = false;
    // Subclass do_rcot_*_begin trips this on first call; set_delta and
    // any pre-bootstrap configuration assert !setup_done.
    bool setup_done = false;
    // Owned base OT for the subclass's bootstrap. Default is OTPVW
    // (DDH messy-mode PVW '08, malicious-secure); override by passing
    // a different concrete OT into the subclass ctor.
    std::unique_ptr<OT> base_ot;
    // Sender-side bool[128] mirror of this->Delta. Maintained in sync
    // by the base ctor and set_delta — subclasses that need per-bit
    // access during bootstrap (IKNP per-row XOR, SoftSpoken α-slice
    // extraction) read this directly instead of redoing bits_to_bools.
    // Zero-valued on the receiver (Δ is sender-only).
    bool delta_bool[128] = {};

    // Receiver-side choice PRG. Every RCOT backend's choice bits are
    // PRG-derived; this is the source of that derivation. IKNP pulls
    // the bit-packed r vector from here; SoftSpoken pulls per-sub-VOLE
    // roots; Ferret pulls a sub-seed to forward to the inner extension
    // at bootstrap time. Default-initialized with a fresh random seed;
    // outer protocols call set_choice_seed pre-bootstrap to take
    // control. Unused on the sender.
    PRG choice_prg;

    bool is_ot_sender() const { return party == ALICE; }

    // Replace the ctor-sampled Δ with one supplied by an outer protocol.
    // Sender-only; must fire before the streaming bootstrap consumes Δ
    // (i.e. before the first rcot_*_begin call). bits[0] must be true
    // (the COT LSB convention shared by all three extensions).
    //
    // Subclasses that need to propagate Δ into auxiliary state (e.g.
    // Ferret's mpcot_sender) override and call this base first.
    virtual void set_delta(const bool* bits) {
        assert(is_ot_sender() && "set_delta: receiver has no \xCE\x94");
        assert(!setup_done && "set_delta: bootstrap already fired");
        assert(bits[0] && "set_delta: bits[0] must be true (LSB invariant)");
        memcpy(this->delta_bool, bits, sizeof(this->delta_bool));
        this->Delta = bool_to_block(this->delta_bool);
    }

    // Reseed the receiver-side choice PRG. Receiver-only; must fire
    // before the streaming bootstrap consumes the PRG (i.e. before
    // the first rcot_*_begin call). Subclasses that nest another
    // OTExtension at bootstrap (Ferret -> SoftSpoken / nested Ferret)
    // pull a sub-seed from choice_prg and forward it via the inner's
    // set_choice_seed in their bootstrap path; no override of the
    // setter itself is needed since the PRG lives on the base.
    virtual void set_choice_seed(const block& seed) {
        assert(!is_ot_sender() && "set_choice_seed: sender has no choice bits");
        assert(!setup_done && "set_choice_seed: bootstrap already fired");
        choice_prg.reseed(&seed);
    }

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
    // Setup runs lazily on the first do_rcot_*_begin (gated by
    // setup_done). Callers that need to inject Δ before bootstrap
    // call set_delta on the sender side; do_rcot_send_begin will
    // observe the injected Delta on its first run.
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
    // Shared ctor used by every concrete extension. Owns the base_ot
    // default (OTPVW), the malicious-secure cross-check, and the
    // sender-side random Δ with LSB pinned to 1. Subclasses pass in
    // their `(party, io, malicious)` and a base_ot if they want a
    // non-default one; everything else is handled here.
    OTExtension(int party_, IOChannel* io_, bool malicious_,
                std::unique_ptr<OT> base_ot_ = nullptr)
        : party(party_), malicious(malicious_),
          base_ot(base_ot_ ? std::move(base_ot_)
                           : std::unique_ptr<OT>(new OTPVW(io_))) {
        this->io = io_;
        if (malicious && !base_ot->is_malicious_secure())
            error("OT extension malicious mode requires a malicious-secure base OT");
        if (is_ot_sender()) {
            // Random Δ with bit 0 = 1 (LSB-encoded choice convention
            // shared across IKNP / SoftSpoken / Ferret). Reusing
            // set_delta keeps the (Delta, delta_bool) mirror logic in
            // one place.
            bool bits[128];
            this->prg.random_bool(bits, 128);
            bits[0] = true;
            set_delta(bits);
        } else {
            this->Delta = zero_block;
            // choice_prg is default-init with a fresh random seed (PRG
            // ctor pulls urandom). Caller can override pre-bootstrap
            // via set_choice_seed.
        }
    }

    // Subclass implementation hooks. Called from the public concrete
    // _begin/_next/_end above after the lifecycle asserts have
    // passed. do_*_begin must trigger first-call setup itself (gated
    // by the inherited `setup_done` flag).
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
    int64_t  leftover_pos_   = 0;
    int64_t  leftover_count_ = 0;

    // Drain up to `take_max` blocks of leftover into `out`.
    int64_t drain_leftover(block* out, int64_t take_max) {
        if (leftover_count_ == 0) return 0;
        int64_t take = std::min<int64_t>(take_max, leftover_count_);
        memcpy(out, leftover_.data() + leftover_pos_, take * sizeof(block));
        leftover_pos_   += take;
        leftover_count_ -= take;
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
            leftover_pos_   = take;
            leftover_count_ = chunk - take;
        }
        if (sender) rcot_send_end(); else rcot_recv_end();
    }
};

}  // namespace emp
#endif  // EMP_OT_EXTENSION_H__
