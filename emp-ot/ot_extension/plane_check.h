#ifndef EMP_OT_PLANE_CHECK_H__
#define EMP_OT_PLANE_CHECK_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/ot.h"
#include <cstdint>
#include <cstring>

namespace emp {

// Malicious-mode consistency check of IKNP and SoftSpoken: the subspace-VOLE
// consistency check of SoftSpokenOT (Roy '22, eprint 2022/192, Fig. 9). Two
// changes: the hash R comes from the transcript (Fiat–Shamir) instead of from
// the sender, and the receiver sends a collision-resistant digest of its folded
// planes instead of the planes, which the sender recomputes on its side. IKNP
// is the k = 1 case: every bit position is its own sub-VOLE.
//
// Both extensions build each chunk as 128 bit-planes before transposing them
// into COT rows: plane p holds bit p of every COT in the chunk, as bs blocks of
// 128 COTs. Honest planes satisfy
//     W_p = V_p ⊕ Δ_p·U   for every p,
// with W_p the sender's plane, V_p the receiver's, U the receiver's choice bits
// (its plane 0) and Δ_p bit p of Δ. A correction that breaks the relation in
// one sub-VOLE breaks it in that sub-VOLE's planes only.
//
// After each chunk's corrections are on the transcript, both parties draw one
// challenge χ_i per 128-COT block (fs_challenge). That defines the linear hash
// R(x) = Σ_i χ_i·x_i in GF(2^128) over the chunk's blocks, ε-almost-universal
// with ε = 2^-128, and R is applied to every plane separately:
//     receiver   Ũ = R(V_0) = R(U),   Ṽ_p = R(V_p)
//     sender     E_p = R(W_p) ⊕ Δ_p·Ũ
// each summed over the chunks since the last check. The receiver sends Ũ and a
// 256-bit digest of (Ṽ_0, …, Ṽ_127); the sender accepts iff it equals the
// digest of (E_0, …, E_127). The planes are compared one by one, never
// combined, so a receiver that leaves a sub-VOLE inconsistent passes only by
// guessing that sub-VOLE's bits of Δ.
//
// The caller extends one more chunk right before each check and discards its
// COTs. Its random choice bits, under a nonzero χ, make Ũ uniform, and Ṽ is
// determined by Ũ and the sender's view.
class PlaneCheck {
public:
    static constexpr int kPlanes = 128;

    void reset() {
        std::memset(lo_, 0, sizeof(lo_));
        std::memset(hi_, 0, sizeof(hi_));
    }

    // Folds one chunk, plane p at planes[p·bs, (p+1)·bs). Both parties call it
    // right after the chunk's corrections reach the transcript, so they draw
    // the same challenges.
    void fold(IOChannel* io, block sid, const block* planes, int64_t bs) {
        if (chi_.size() < static_cast<size_t>(bs))
            chi_.resize(static_cast<size_t>(bs));
        block seed = fs_challenge(io, sid);
        PRG chi_prg(&seed);
        chi_prg.random_block(chi_.data(), bs);
        block lo_hi[2];
        for (int p = 0; p < kPlanes; ++p) {
            vector_inn_prdt_sum_no_red(lo_hi, chi_.data(), planes + p * bs, bs);
            lo_[p] = lo_[p] ^ lo_hi[0];
            hi_[p] = hi_[p] ^ lo_hi[1];
        }
    }

    // Receiver: sends Ũ and the digest of Ṽ.
    void send(IOChannel* io, block sid) const {
        block v[kPlanes];
        for (int p = 0; p < kPlanes; ++p) v[p] = reduce(lo_[p], hi_[p]);
        block msg[3];
        msg[0] = v[0];
        digest_(msg + 1, sid, v);
        io->send_block(msg, 3);
    }

    // Sender: receives Ũ and the receiver's digest. True iff it equals the
    // digest of E. delta_bool[p] is bit p of Δ.
    bool verify(IOChannel* io, block sid, const bool* delta_bool) const {
        block msg[3];
        io->recv_block(msg, 3);
        block e[kPlanes];
        for (int p = 0; p < kPlanes; ++p) {
            const uint64_t m = 0 - static_cast<uint64_t>(delta_bool[p]);
            e[p] = reduce(lo_[p], hi_[p]) ^ (msg[0] & makeBlock(m, m));
        }
        block d[2];
        digest_(d, sid, e);
        return cmpBlock(d, msg + 1, 2);
    }

private:
    static void digest_(block* out, block sid, const block* planes) {
        RO("emp-ot:plane-check", sid)
            .absorb(planes, static_cast<int64_t>(kPlanes * sizeof(block)))
            .squeeze_digest(out);
    }

    // Per plane, Σ χ_i·x_i before reduction: low and high 128 bits.
    block lo_[kPlanes] = {};
    block hi_[kPlanes] = {};
    BlockVec chi_;   // the current chunk's challenges
};

}  // namespace emp
#endif
