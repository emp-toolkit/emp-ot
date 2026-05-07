#ifndef EMP_OT_PVW_KYBER_PARAMS_HPP__
#define EMP_OT_PVW_KYBER_PARAMS_HPP__

// Internal header — only included by emp-ot/base_ot/pvw_kyber/*.cpp / *.hpp.
// Pulls in Kyber's reference C headers under the ML-KEM-512 parameter
// set (KYBER_K = 2) and re-exposes the constants we need as constexpr
// values. KYBER_K is set here, before the Kyber header includes, so it
// matches the value compiled into the lifted .c sources (CMakeLists
// scopes -DKYBER_K=2 to those translation units).
//
// NOTE: this header MUST NOT be transitively included from the public
// emp-ot/base_ot/pvw_kyber.h, because that would leak the KYBER_K macro
// into every emp-ot consumer. Keep Kyber linkage entirely behind the
// pvw_kyber.cpp boundary.

#define KYBER_K 2

extern "C" {
#include "emp-ot/base_ot/pvw_kyber/kyber/params.h"
#include "emp-ot/base_ot/pvw_kyber/kyber/poly.h"
#include "emp-ot/base_ot/pvw_kyber/kyber/polyvec.h"
#include "emp-ot/base_ot/pvw_kyber/kyber/cbd.h"
#include "emp-ot/base_ot/pvw_kyber/symmetric.h"  /* keccak_state, prf, kyber_shake128_*, etc. */
}

namespace emp { namespace pvw_kyber {

// ML-KEM-512 parameter mirror. static_asserts here would fire if the
// lifted Kyber sources were ever rebuilt under a different KYBER_K.
constexpr int kN          = KYBER_N;          // 256: ring degree
constexpr int kK          = KYBER_K;          // 2:   module rank
constexpr int kQ          = KYBER_Q;          // 3329
constexpr int kEta1       = KYBER_ETA1;       // 3
constexpr int kEta2       = KYBER_ETA2;       // 2
constexpr int kSymBytes   = KYBER_SYMBYTES;   // 32: seed / hash size
constexpr int kPolyBytes  = KYBER_POLYBYTES;  // 384: serialized R_q
constexpr int kPolyVecBytes = KYBER_POLYVECBYTES;  // 768: serialized R_q^k

// Kyber's IND-CPA-style ciphertext compression (du=10 for u, dv=4 for v
// at K=2). Used for the (u_β, v_β) ciphertext pair on the wire — the
// receiver's t (LWE public key) stays uncompressed.
constexpr int kPolyCompBytes    = KYBER_POLYCOMPRESSEDBYTES;     // 128
constexpr int kPolyVecCompBytes = KYBER_POLYVECCOMPRESSEDBYTES;  //  640

static_assert(kN == 256 && kK == 2 && kQ == 3329, "ML-KEM-512 parameters expected");
static_assert(kSymBytes == 32, "Kyber sym-bytes != 32");

}}  // namespace emp::pvw_kyber

#endif  // EMP_OT_PVW_KYBER_PARAMS_HPP__
