#ifndef EMP_OT_SFROT_CHECK_H__
#define EMP_OT_SFROT_CHECK_H__

#include <emp-tool/emp-tool.h>   // RO, block, cmpBlock, error, IOChannel
#include <vector>

// Shared challenge–prove–response check for F_SF-rOT base OTs.
//
// This is the observable-RO extraction step that turns a "messy" two-message
// base OT (one that delivers the receiver a single random pad p_{i,b} while
// keeping the other pad pseudorandom) into a simulation-extractable one: it
// forces an accepting receiver to query the random oracle on its selected pad,
// so a simulator that observes RO queries reads off the choice bit b_i
// (Property P1 of Def. F_SF-rOT) and the proof Π folds a malformed challenge
// into the tolerated selective-failure attack.
//
// The check is base-OT-agnostic: it touches only the finished `block` pads via
// the emp-tool RO, never the underlying DH / lattice objects. Both CSW (DH
// pads) and PVWKyber (Kyber pads) feed their already-domain-separated pads in.
// The check owns its own RO domains, so the source of the pads is irrelevant.
//
// Wire (3rd flow of a 3-round base OT):
//   sender → receiver : chi[0..n) , proof          (caller sends the core
//                                                    bytes first, then these)
//   receiver → sender : otans'
// Both sides abort via error() on verification failure.

namespace emp {

inline constexpr char kSFRotCheckDomShort[] = "emp-ot:sf-rot-check:h3";
inline constexpr char kSFRotCheckDomAgg[]   = "emp-ot:sf-rot-check:agg";

// H3(sid, x): one block in, one block out.
inline block sfrot_check_h3(block sid, const block& x) {
    return RO(kSFRotCheckDomShort, sid).absorb(x).squeeze_block();
}

// Sender half. p0[i], p1[i] are the two per-instance pads (already core
// domain-separated). Sends (chi, proof), then receives otans' and aborts on
// mismatch. The caller must have already sent its core round-2 payload.
inline void sfrot_check_send(IOChannel* io, block sid,
                             const block* p0, const block* p1, int64_t n) {
    std::vector<block> h0((size_t)n);
    std::vector<block> chi((size_t)n);
    for (int64_t i = 0; i < n; ++i) {
        h0[i]  = sfrot_check_h3(sid, p0[i]);
        chi[i] = h0[i] ^ sfrot_check_h3(sid, p1[i]);
    }
    // Single bulk-absorbed field — must match the receiver's absorb exactly.
    block otans = RO(kSFRotCheckDomAgg, sid)
                      .absorb(h0.data(), (size_t)n * sizeof(block))
                      .squeeze_block();
    block proof = sfrot_check_h3(sid, otans);

    io->send_block(chi.data(), n);
    io->send_block(&proof, 1);

    block otans_prime;
    io->recv_block(&otans_prime, 1);
    if (!cmpBlock(&otans, &otans_prime, 1))
        error("sfrot_check_send: otans verification failed (receiver misbehavior)");
}

// Receiver half. p_b[i] is the CHOSEN pad only (the unchosen / messy branch is
// never needed — this is what keeps the messy-mode hiding intact). b[i] is the
// choice bit. Receives (chi, proof), verifies the proof against the recomputed
// otans', aborts on mismatch, then sends otans'.
inline void sfrot_check_recv(IOChannel* io, block sid,
                             const block* p_b, const bool* b, int64_t n) {
    std::vector<block> chi((size_t)n);
    block proof;
    io->recv_block(chi.data(), n);
    io->recv_block(&proof, 1);

    std::vector<block> otresp((size_t)n);
    for (int64_t i = 0; i < n; ++i) {
        block h = sfrot_check_h3(sid, p_b[i]);
        otresp[i] = b[i] ? (h ^ chi[i]) : h;        // canonicalize to p_{i,0}
    }
    block otans_prime = RO(kSFRotCheckDomAgg, sid)
                            .absorb(otresp.data(), (size_t)n * sizeof(block))
                            .squeeze_block();
    block proof_check = sfrot_check_h3(sid, otans_prime);
    if (!cmpBlock(&proof, &proof_check, 1))
        error("sfrot_check_recv: proof verification failed (sender misbehavior or selective-failure attack)");

    io->send_block(&otans_prime, 1);
}

}  // namespace emp

#endif  // EMP_OT_SFROT_CHECK_H__
