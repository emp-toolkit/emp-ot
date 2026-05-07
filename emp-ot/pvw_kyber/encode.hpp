#ifndef EMP_OT_PVW_KYBER_ENCODE_HPP__
#define EMP_OT_PVW_KYBER_ENCODE_HPP__

// Encode/Decode wrappers around Kyber's poly_frommsg / poly_tomsg.
// PVW's "Encode" maps a 256-bit message to an R_q element by placing
// each bit at coefficient position i ∈ [0, 256) with value
//   bit_i × ⌊(q+1)/2⌋ = bit_i × 1665   (for q = 3329).
// "Decode" rounds each coefficient to the nearest of {0, 1665} (boundary
// at q/4 and 3q/4) and packs the result back into 32 bytes.
//
// Both Kyber primitives are constant-time (poly_frommsg uses
// cmov_int16; poly_tomsg uses bit-mask arithmetic).

#include "emp-ot/pvw_kyber/params.hpp"
#include <cstdint>

namespace emp { namespace pvw_kyber {

// 32 B → poly. Bit 0 of msg[0] lands at coeffs[0]; bit 7 of msg[31] at
// coeffs[255]. Bit value 0 → 0, bit value 1 → ⌊(q+1)/2⌋.
inline void encode_msg(poly *r, const uint8_t msg[32]) {
    poly_frommsg(r, msg);
}

// poly → 32 B (inverse of encode_msg, with the rounding described above).
// Caller must reduce the poly to the canonical [0, q) representative
// before calling (poly_tomsg is undefined on un-reduced inputs).
inline void decode_msg(uint8_t msg[32], const poly *r) {
    poly_tomsg(msg, r);
}

}}  // namespace emp::pvw_kyber

#endif  // EMP_OT_PVW_KYBER_ENCODE_HPP__
