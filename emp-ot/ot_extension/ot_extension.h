#ifndef EMP_OT_EXTENSION_H__
#define EMP_OT_EXTENSION_H__

#include <cassert>
#include <cstring>
#include <algorithm>
#include <memory>
#include "emp-ot/ot.h"
#include "emp-ot/common/streaming_extension.h"

namespace emp {

// Common base class for OT extensions (IKNP / SoftSpokenOT / Ferret).
// Conceptually `OTExtension` is just `StreamingExtension<block>` with
// three additions:
//   - dual-role public API: rcot_send_* / rcot_recv_* (party-asserting
//     wrappers around the inherited single-role begin/next/end).
//   - Δ / delta_bool / choice_prg / base_ot — OT-specific plumbing.
//   - chunk_ots() as an alias for chunk_size().
//
// Each instance is single-role at runtime (`party` is fixed at
// construction); the dual-role API is just two API surfaces over the
// same single-role lifecycle. Subclasses (IKNP, SoftSpoken, Ferret)
// override the three streaming virtuals do_begin / do_next / do_end
// and dispatch by party internally.
class OTExtension : public RandomCOT, public StreamingExtension<block> {
public:
    // Subclass do_begin trips this on first call; set_delta and any
    // pre-bootstrap configuration assert !setup_done. (Inherited from
    // StreamingExtension.)

    // Owned base OT for the subclass's bootstrap. Allocated by the
    // subclass ctor (see IKNPBaseOT / SoftSpokenBaseOT / FerretBaseOT
    // typedefs); each subclass picks its own default and can be
    // overridden by passing a concrete OT into the subclass ctor.
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

    // Per-_next chunk size in OTs. Subclasses override the inherited
    // chunk_size() (one cGGM tree's leaves for Ferret; the max-batch
    // unit for IKNP / SoftSpoken). chunk_ots() is a non-virtual alias
    // for external callers that pre-date the unified streaming name.
    int64_t chunk_ots() const { return chunk_size(); }

    // -------- Dual-role public API --------
    // Each is a thin party-asserting alias for the inherited
    // single-role begin/next/end/run. Subclasses don't see these —
    // they implement do_begin/do_next/do_end and dispatch on party.
    void rcot_send_begin()        { assert(is_ot_sender());  begin(); }
    void rcot_send_next(block* o) { assert(is_ot_sender());  next(o); }
    void rcot_send_end()          { assert(is_ot_sender());  end(); }
    void rcot_recv_begin()        { assert(!is_ot_sender()); begin(); }
    void rcot_recv_next(block* o) { assert(!is_ot_sender()); next(o); }
    void rcot_recv_end()          { assert(!is_ot_sender()); end(); }

    // RandomCOT one-shot. Lifecycle: lazy setup_done flip happens
    // inside the subclass's first do_begin.
    void rcot_send(block* data, int64_t num) final override {
        assert(is_ot_sender());
        run(data, num);
    }
    void rcot_recv(block* data, int64_t num) final override {
        assert(!is_ot_sender());
        run(data, num);
    }

protected:
    // Shared ctor used by every concrete extension. Stores the base_ot
    // (subclasses always pass non-null — their per-extension typedef
    // picks the default), runs the malicious-secure cross-check, and
    // samples the sender-side random Δ with LSB pinned to 1.
    OTExtension(int party_, IOChannel* io_, bool malicious_,
                std::unique_ptr<OT> base_ot_)
        : StreamingExtension<block>(party_, malicious_),
          base_ot(std::move(base_ot_)) {
        assert(base_ot && "OTExtension: subclass must provide a non-null base_ot");
        this->io = io_;
        if (malicious_ && !base_ot->is_malicious_secure())
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

    // Default StreamingExtension hook implementations: party-dispatch
    // to the per-role virtuals below. Subclasses that fit the dual-role
    // split (IKNP, SoftSpoken) override the six per-role methods and
    // inherit these dispatchers. Subclasses with a unified body (e.g.
    // Ferret, which routes through TreeExtensionBase::engine_*) can
    // override do_begin / do_next / do_end directly and ignore the
    // per-role hooks.
    void do_begin() override {
        if (is_ot_sender()) do_rcot_send_begin();
        else                do_rcot_recv_begin();
    }
    void do_next(block* out) override {
        if (is_ot_sender()) do_rcot_send_next(out);
        else                do_rcot_recv_next(out);
    }
    void do_end() override {
        if (is_ot_sender()) do_rcot_send_end();
        else                do_rcot_recv_end();
    }

    // Per-role hooks. Default empty (so subclasses that override
    // do_begin/do_next/do_end directly don't need to provide them).
    // Subclasses using the default dispatch above must override these
    // with their per-role bodies.
    virtual void do_rcot_send_begin()        {}
    virtual void do_rcot_send_next(block*)   {}
    virtual void do_rcot_send_end()          {}
    virtual void do_rcot_recv_begin()        {}
    virtual void do_rcot_recv_next(block*)   {}
    virtual void do_rcot_recv_end()          {}
};

}  // namespace emp
#endif  // EMP_OT_EXTENSION_H__
