#ifndef EMP_SOFTSPOKEN_SFVOLE_DISPATCH_H__
#define EMP_SOFTSPOKEN_SFVOLE_DISPATCH_H__

// Platform-specific routing for the SoftSpoken sfvole inner loop.
//
// `sfvole_*_try_optimized` returns true if the request was handled by a
// platform-specialized kernel; the caller should `return` immediately.
// Returns false if no specialization applies — the caller is responsible
// for the portable leaf-major fallback (the aes_ctr_fold kernel inlined
// in softspoken_ot.h).
//
// k=8 routes to the cross-platform butterfly kernel
// (sfvole_butterfly.h). k=2 / k=4 fall through to leaf-major.

#include <emp-tool/emp-tool.h>
#include "emp-ot/softspoken/sfvole_butterfly.h"
#include <cstdint>

namespace emp { namespace softspoken {

template <int k>
EMP_AES_TARGET_ATTR
inline bool sfvole_sender_try_optimized(const block leaves[1 << k],
                                         uint64_t session,
                                         int64_t b0, int64_t bs,
                                         block* u_bits_chunk,
                                         block* v_planes_chunk) {
    if constexpr (k == 8) {
        sfvole_sender_butterfly<k>(leaves, session, b0, bs,
                                    u_bits_chunk, v_planes_chunk);
        return true;
    }
    (void)leaves; (void)session; (void)b0; (void)bs;
    (void)u_bits_chunk; (void)v_planes_chunk;
    return false;
}

template <int k>
EMP_AES_TARGET_ATTR
inline bool sfvole_receiver_try_optimized(int alpha,
                                           const block leaves[1 << k],
                                           uint64_t session,
                                           int64_t b0, int64_t bs,
                                           block* w_planes_chunk) {
    if constexpr (k == 8) {
        sfvole_receiver_butterfly<k>(alpha, leaves, session, b0, bs,
                                      w_planes_chunk);
        return true;
    }
    (void)alpha; (void)leaves; (void)session; (void)b0; (void)bs;
    (void)w_planes_chunk;
    return false;
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_DISPATCH_H__
