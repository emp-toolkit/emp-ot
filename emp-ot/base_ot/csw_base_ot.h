#ifndef EMP_OT_CSW_BASE_OT_H__
#define EMP_OT_CSW_BASE_OT_H__

#include <cstdint>
#include <emp-tool/emp-tool.h>   // block
#include "emp-ot/ot.h"

namespace emp {

// A "CSW-like" base OT: one that realizes F_SF-rOT as a messy *core* (delivers
// the receiver its chosen pad while the other pad stays pseudorandom) followed
// by the shared challenge–prove–response *extraction check* (the observable-RO
// step that lets the simulator read off the receiver's choice bit). CSW (DH
// pads) and PVWKyber (Kyber pads) are the two instances; both feed their pads
// into sfrot_check_send / sfrot_check_recv.
//
// Splitting the two phases lets an OT extension overlap the base OT's last two
// flows with its own first message — the paper's round-preserving result. The
// extension calls *_core in its bootstrap (which buffers the core round-2 bytes
// WITHOUT flushing, so they bundle with the extension's first message) and
// defers *_check to the very end of its session, after its own consistency
// check. Then every receiver→sender message rides one network round and the
// check's response (otans') is the single closing flow → 3 rounds. See the
// deferred-check wiring in iknp.cpp / softspoken.cpp.
//
// supports_deferred_check() returns true so an extension can detect a CSW-like
// base through the OT* it already holds (mirrors is_malicious_secure()); a base
// OT that does not derive from CSWBaseOT returns false and gets the blocking
// path.
class CSWBaseOT : public OT {
public:
    bool supports_deferred_check() const override { return true; }

    // Deliver the OT outputs and stash the per-instance pads internally. Does
    // NOT run the extraction check and does NOT flush, so the base round-2
    // bytes stay buffered to bundle with the caller's next messages.
    virtual void send_core(const block* data0, const block* data1, int64_t length) = 0;
    virtual void recv_core(block* data, const bool* b, int64_t length) = 0;

    // Run the deferred extraction check over the stashed pads. The check's
    // final recv flushes the bundled buffer, so call this only after the caller
    // has emitted all of its own outbound messages.
    virtual void send_check() = 0;   // base-sender half:   sends (chi,proof), recvs+verifies otans'
    virtual void recv_check() = 0;   // base-receiver half: recvs (chi,proof), verifies, sends otans'

    // Complete OT for standalone callers = core + check back-to-back, wire-
    // identical to a monolithic implementation.
    void send(const block* data0, const block* data1, int64_t length) override {
        send_core(data0, data1, length);
        send_check();
    }
    void recv(block* data, const bool* b, int64_t length) override {
        recv_core(data, b, length);
        recv_check();
    }
};

}  // namespace emp

#endif  // EMP_OT_CSW_BASE_OT_H__
