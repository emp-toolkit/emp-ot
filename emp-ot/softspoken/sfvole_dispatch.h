#ifndef EMP_SOFTSPOKEN_SFVOLE_DISPATCH_H__
#define EMP_SOFTSPOKEN_SFVOLE_DISPATCH_H__

// Platform-specific routing for the SoftSpoken sfvole inner loop. Owns
// every `#if defined(__aarch64__) / EMP_AES_HAS_VAES512 / vendor check`
// gate in one place so that softspoken_ot.h's compute_chunk reads as
// plain code.
//
// `sfvole_*_try_optimized` returns true if the request was handled by a
// platform-specialized kernel; the caller should `return` immediately.
// Returns false if no specialization applies — the caller is responsible
// for the portable leaf-major fallback (aes_ctr_fold).
//
// Specializations currently active:
//   - Apple M (NEON), k=8: recursive butterfly halve (sfvole_butterfly.h).
//     +50% kernel-level vs leaf-major; M-series is AES-throughput-bound,
//     so the win comes from eliminating fold per-target memory RMW.
//   - Intel x86 + VAES-512 (Sapphire Rapids+, Granite Rapids), k=8:
//     View B reg-resident lane-packed accumulator + mask-gated XOR
//     (sfvole_view_b.h). +46% kernel @ bs=1024, +19-37% e2e SoftSpoken<8>
//     RCOT. Gated runtime to GenuineIntel via sfvole_view_b_is_supported()
//     because AMD Zen 5 regressed (-7-12% e2e) under the same kernel.
//
// All other (k, arch) combinations fall through to leaf-major.

#include <emp-tool/emp-tool.h>
#include "emp-ot/softspoken/sfvole_butterfly.h"
#include "emp-ot/softspoken/sfvole_view_b.h"
#include <cstdint>

namespace emp { namespace softspoken {

template <int k>
EMP_AES_TARGET_ATTR
inline bool sfvole_sender_try_optimized(const block leaves[1 << k],
                                         uint64_t session,
                                         int64_t b0, int64_t bs,
                                         block* u_bits_chunk,
                                         block* v_planes_chunk) {
#if defined(__aarch64__)
    if constexpr (k == 8) {
        sfvole_sender_butterfly<k>(leaves, session, b0, bs,
                                    u_bits_chunk, v_planes_chunk);
        return true;
    }
#endif
#if EMP_AES_HAS_VAES512
    if constexpr (k == 8) {
        if (sfvole_view_b_is_supported()) {
            sfvole_sender_view_b<k>(leaves, session, b0, bs,
                                     u_bits_chunk, v_planes_chunk);
            return true;
        }
    }
#endif
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
#if defined(__aarch64__)
    if constexpr (k == 8) {
        sfvole_receiver_butterfly<k>(alpha, leaves, session, b0, bs,
                                      w_planes_chunk);
        return true;
    }
#endif
#if EMP_AES_HAS_VAES512
    if constexpr (k == 8) {
        if (sfvole_view_b_is_supported()) {
            sfvole_receiver_view_b<k>(alpha, leaves, session, b0, bs,
                                       w_planes_chunk);
            return true;
        }
    }
#endif
    (void)alpha; (void)leaves; (void)session; (void)b0; (void)bs;
    (void)w_planes_chunk;
    return false;
}

}}  // namespace emp::softspoken

#endif  // EMP_SOFTSPOKEN_SFVOLE_DISPATCH_H__
