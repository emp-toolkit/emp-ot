#ifndef EMP_OT_EXTENSION_H__
#define EMP_OT_EXTENSION_H__

#include <cassert>
#include <cstring>
#include <algorithm>
#include <memory>
#include "emp-ot/ot.h"
#include "emp-ot/common/streaming_extension.h"

namespace emp {

// Common base class for OT extensions (IKNP / SoftSpoken / Ferret).
// Conceptually `OTExtension` is `StreamingExtension<block>` with two
// additions:
//   - rcot(data, num) — the polymorphic one-shot entry from RandomCOT.
//     Implemented here by forwarding to StreamingExtension::run (the
//     leftover-buffer drainer). Concrete subclasses don't override
//     this — they implement begin / next / end and let rcot delegate.
//   - Δ / delta_bool / choice_prg / base_ot — OT-specific plumbing.
//
// Concrete subclasses (IKNP, SoftSpoken, Ferret) override the three
// streaming virtuals begin / next / end directly:
//   - IKNP / SoftSpoken: party-dispatch inline to private send/recv
//     helpers (their bodies diverge per role).
//   - Ferret: one unified body per stage (party-dispatches inside the
//     private per-tree helpers).
class OTExtension : public RandomCOT, public StreamingExtension<block> {
public:
    // Subclass begin/next/end trip this on first call via
    // enter_session_; set_delta and any pre-bootstrap configuration
    // assert !setup_done. (Inherited from StreamingExtension.)

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
    // (i.e. before the first begin() call). bits[0] must be true
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
    // the first begin() call). Subclasses that nest another
    // OTExtension at bootstrap (Ferret -> SoftSpoken / nested Ferret)
    // pull a sub-seed from choice_prg and forward it via the inner's
    // set_choice_seed in their bootstrap path; the PRG lives on the
    // base and no subclass needs to override the setter.
    void set_choice_seed(const block& seed) {
        assert(!is_ot_sender() && "set_choice_seed: sender has no choice bits");
        assert(!setup_done && "set_choice_seed: bootstrap already fired");
        choice_prg.reseed(&seed);
    }

    // Set this extension's session id and forward a derived child sid to the
    // owned base OT, so the base OT's RO transcript is session-separated.
    // Pre-bootstrap, like the setters above. (Subclasses that nest another
    // extension at bootstrap — Ferret — additionally derive a child sid for
    // that nested instance in their bootstrap path.)
    void set_sid(SessionID s) override {
        assert(!setup_done && "set_sid: bootstrap already fired");
        sid = s;
        base_ot->set_sid(sid.derive());
    }

    // Streaming surface: begin / next / end / run / chunk_size are
    // inherited verbatim from StreamingExtension<block>. Each instance
    // is single-role at runtime (`party` is fixed at construction), so
    // the role is implicit. Subclasses override the inherited
    // chunk_size() — one cGGM tree's leaves for Ferret, the max-batch
    // unit for IKNP / SoftSpoken.

    // RandomCOT polymorphic entry. Single-method (role-implicit),
    // forwards to the inherited leftover-buffer one-shot run().
    void rcot(block* data, int64_t num) final override {
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
};

}  // namespace emp
#endif  // EMP_OT_EXTENSION_H__
