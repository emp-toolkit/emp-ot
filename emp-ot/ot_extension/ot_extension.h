#ifndef EMP_OT_EXTENSION_H__
#define EMP_OT_EXTENSION_H__

#include <cstring>
#include <algorithm>
#include <memory>
#include "emp-ot/ot.h"
#include "emp-ot/base_ot/csw.h"
#include "emp-ot/common/streaming_extension.h"

namespace emp {

// Common base class for OT extensions (IKNP / SoftSpoken / Ferret).
// Conceptually `OTExtension` is `StreamingExtension<block>` with three
// additions:
//   - rcot(data, num) — the polymorphic one-shot entry from RandomCOT.
//     Implemented here by forwarding to StreamingExtension::run (the
//     leftover-buffer drainer). Concrete subclasses don't override
//     this — they implement begin / next / end and let rcot delegate.
//   - check() — certify newly generated chunks without closing the caller's
//     session or dropping an already-certified next_n() tail.
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
    // expect !setup_done. (Inherited from StreamingExtension.)

    // Owned base OT for the subclass's bootstrap. Allocated by the
    // subclass ctor (see IKNPBaseOT / SoftSpokenBaseOT / FerretBaseOT
    // typedefs); each subclass picks its own default and can be
    // overridden by passing a concrete OT into the subclass ctor.
    std::unique_ptr<OT> base_ot;
    // Non-null iff base_ot is CSW (the only base OT exposing the messy-core +
    // deferred extraction-check split). Set once in the ctor. When set, the
    // subclass bootstrap calls *_core in begin() (buffering the base round-2
    // bytes) and the deferred *_check at the tail of the first end() or
    // mid-session check(), overlapping the base OT's last two flows with the
    // extension's first message (3-round result). nullptr → blocking path
    // (base_ot->send/recv).
    CSW* csw_base_ = nullptr;
    // One-shot: set true when the bootstrap runs *_core, cleared when end()
    // (possibly through check()) runs the deferred *_check. Keyed off this (not
    // setup_done / malicious) so the base check runs exactly once at the first
    // certification boundary.
    bool base_check_pending_ = false;
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
        expecting(is_ot_sender(), "set_delta: receiver has no \xCE\x94");
        expecting(!setup_done, "set_delta: bootstrap already fired");
        expecting(bits != nullptr, "set_delta: null bit buffer");
        expecting(bits[0], "set_delta: bits[0] must be true (LSB invariant)");
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
        expecting(!is_ot_sender(),
                  "set_choice_seed: sender has no choice bits");
        expecting(!setup_done,
                  "set_choice_seed: bootstrap already fired");
        choice_prg.reseed(&seed);
    }

    // Set this extension's session id and forward a derived child sid to the
    // owned base OT, so the base OT's RO transcript is session-separated.
    // Pre-bootstrap, like the setters above. (Subclasses that nest another
    // extension at bootstrap — Ferret — additionally derive a child sid for
    // that nested instance in their bootstrap path.)
    void set_sid(SessionID s) override {
        expecting(!setup_done, "set_sid: bootstrap already fired");
        sid = s;
        base_ot->set_sid(sid.derive());
    }

    // Streaming surface: ordinary begin / next / end / run / chunk_size come
    // from StreamingExtension<block>. Each instance is single-role at runtime
    // (`party` is fixed at construction), so the role is implicit. Subclasses
    // override the inherited chunk_size() — one cGGM tree's leaves for Ferret,
    // the max-batch unit for IKNP / SoftSpoken.

    // Counted streaming begin: `n_ots` is an upper bound across this
    // session's next_n() calls. It enables a backend to shrink its final
    // production unit. Both peers must pass the same count because a sized
    // unit changes wire length. Ordinary begin() remains unchanged.
    //
    // Virtual to preserve SilentFerret's existing stronger begin(n_ots)
    // prepayment semantics.
    using StreamingExtension<block>::begin;
    virtual void begin(int64_t n_ots) { begin_counted_(n_ots); }

    // Certify every backend chunk generated since begin() / the preceding
    // successful check(), while keeping the caller-owned streaming session
    // active. A partial next_n() tail was generated and folded as part of its
    // whole backend chunk, so it is already certified and remains buffered for
    // subsequent draws. If the caller has consumed only such a certified tail,
    // check() is a no-op. The first check still runs when a CSW bootstrap left
    // its deferred base-OT extraction check pending.
    //
    // The default implementation deliberately composes the concrete virtual
    // end()/begin() lifecycle. This gives every OTExtension backend its exact
    // existing round-final check/restart semantics without adding a new pure
    // hook, while StreamingExtension preserves the buffered cursor across that
    // internal boundary. Ordinary public end(); begin(); continues to discard
    // a prior caller-owned tail.
    virtual void check() {
        expect_in_session_();
        if (unchecked_chunk_ || base_check_pending_)
            restart_session_preserving_leftover_();
        // Even an empty check establishes that this logical continuation has
        // no provisional material. Concrete end() implementations may close
        // this idle post-check continuation without an empty sacrificial
        // exchange; Ferret additionally restores its pre-begin buffer swap.
        checked_continuation_idle_ = true;
    }

    // RandomCOT polymorphic entry. Single-method (role-implicit),
    // forwards to the inherited leftover-buffer one-shot run().
    void rcot(block* data, int64_t num) final override {
        run(data, num);
    }

protected:
    // Concrete next() overrides mark once after successfully producing one
    // backend chunk; concrete end() overrides clear only after every check and
    // deferred base-OT check succeeds. This is per chunk (thousands of COTs),
    // never per COT or per downstream gate.
    void mark_chunk_unchecked_() {
        unchecked_chunk_ = true;
        checked_continuation_idle_ = false;
    }
    void mark_chunks_checked_() {
        unchecked_chunk_ = false;
        checked_continuation_idle_ = false;
    }
    bool can_close_checked_continuation_() const {
        return checked_continuation_idle_ && !unchecked_chunk_ &&
               !base_check_pending_;
    }
    void mark_checked_continuation_closed_() {
        checked_continuation_idle_ = false;
    }

    // Tag for the clone-lane ctor below (disambiguates from the normal ctor).
    struct CloneInit {};

    // Clone-lane base ctor: build a lane that SHARES an already-bootstrapped
    // parent's checked material but runs an INDEPENDENT extension on `io_`.
    // Allocates NO base OT and samples NO Δ — the subclass clone ctor copies the
    // parent's leaves/alphas/Δ and flips setup_done. Constructing a FRESH object
    // (never copy-constructing a clone) is precisely what leaves every mutable
    // streaming/COT field at its clean in-class default — StreamingExtension's
    // in_session_/leftover_, COT's mitccrh/prg — so concurrent lanes share no
    // mutable state and touch disjoint scratch. base_ot / csw_base_ /
    // base_check_pending_ default to null/null/false, so the deferred base-OT
    // extraction check is the PARENT's sole responsibility, run once on its io.
    // choice_prg is bootstrap-only (dead after setup_done), so its value is
    // irrelevant on a clone. See SoftSpoken::clone_lane.
    OTExtension(CloneInit, int party_, IOChannel* io_, bool malicious_)
        : StreamingExtension<block>(party_, malicious_) {
        this->io = io_;
    }

    // Shared ctor used by every concrete extension. Stores the base_ot
    // (subclasses always pass non-null — their per-extension typedef
    // picks the default), runs the malicious-secure cross-check, and
    // samples the sender-side random Δ with LSB pinned to 1.
    OTExtension(int party_, IOChannel* io_, bool malicious_,
                std::unique_ptr<OT> base_ot_)
        : StreamingExtension<block>(party_, malicious_),
          base_ot(std::move(base_ot_)) {
        expecting(base_ot != nullptr,
                  "OTExtension: subclass must provide a non-null base_ot");
        this->io = io_;
        expecting(!malicious_ || base_ot->is_malicious_secure(),
                  "OT extension malicious mode requires a malicious-secure base OT");
        // Detect a CSW base OT for the deferred-check overlap (CSW is the only
        // OT setting this trait, so the static_cast is sound — no RTTI needed).
        if (base_ot->supports_deferred_check())
            csw_base_ = static_cast<CSW*>(base_ot.get());
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

private:
    bool unchecked_chunk_ = false;
    bool checked_continuation_idle_ = false;
};

}  // namespace emp
#endif  // EMP_OT_EXTENSION_H__
