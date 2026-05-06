#ifndef EMP_SOFTSPOKEN_SFVOLE_VIEW_B_H__
#define EMP_SOFTSPOKEN_SFVOLE_VIEW_B_H__

// View B sfvole kernel for AVX-512 + VAES-512 (Sapphire Rapids+, Zen 5).
// Replaces the leaf-major aes_ctr_fold<N_TARGETS> per-target memory-RMW
// with a tile-resident, lane-packed accumulator and a mask-gated XOR.
// Targets the per-target vmovdqu64 + vpxorq fold traffic that `perf`
// shows accounts for ~30-37% of the existing kernel on Intel c8i /
// AMD c8a — see `/Users/wangxiao/.claude/plans/if-i-implement-libc-agile-cosmos.md`.
//
// Algorithm (sender, k=8): for each j-tile of T=4 contiguous chunk
// positions, hold acc_lo, acc_hi ∈ zmm where:
//   acc_lo[t] lane d ∈ [0,3] = v_d at j+t  (one zmm per t)
//   acc_hi[t] lane d ∈ [0,3] = v_{4+d} at j+t
//   u_acc      lane t ∈ [0,3] = u   at j+t  (single zmm covers T j's)
// For each leaf x, generate r_x[j..j+T) via VAES-512 (1 zmm at T=4),
// look up the per-leaf __mmask16 from a 16-entry nibble table, broadcast
// each r_x[j+t] across all 4 lanes, and apply a mask-gated XOR. After
// Q=256 leaves, flush 8 plane stores per t. No memory traffic in the
// leaf inner loop — that traffic is what dominates the existing
// aes_ctr_fold path on Intel/AMD.
//
// Receiver: drop u_acc; permute key list (keys[y] = leaves[α ⊕ y]);
// mask is derived from bits of y itself (since after substitution
// w_b = ⊕_{y : bit_b(y)=1} r_{α⊕y}).
//
// Gated on EMP_AES_HAS_VAES512 (defined in emp-tool/crypto/aes.h).

#include <emp-tool/emp-tool.h>
#include <cstdint>

#if EMP_AES_HAS_VAES512
#include <cpuid.h>

namespace emp { namespace softspoken {

// Vendor gate. AWS bench (`if-i-implement-libc-agile-cosmos.md` round-2):
// View B wins on Intel Sapphire Rapids+ (e2e SoftSpoken<8> RCOT +19-37%
// across modes/directions) but regresses on AMD Zen 5 (kernel -18-32%
// at bs=1024/128, e2e -7-12%). Zen 5's existing aes_ctr_fold VAES-512
// 4-block path keeps up with the per-target memory RMW pattern better
// than expected. Gate dispatch on Intel only; AMD falls through to
// aes_ctr_fold. One-shot CPUID lookup cached at first call.
inline bool sfvole_view_b_is_supported() {
    static const bool cached = [] {
        unsigned eax, ebx, ecx, edx;
        if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) return false;
        // "GenuineIntel" = ebx="Genu" (0x756e6547),
        //                  edx="ineI" (0x49656e69),
        //                  ecx="ntel" (0x6c65746e).
        return ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e;
    }();
    return cached;
}

namespace view_b_detail {

// 16-entry nibble→mask table. The lane-packed accumulator has 4 lanes
// of 4 dwords each; lane d should XOR iff bit_d(nibble) = 1, i.e. bits
// (4d..4d+3) of the mask are set together.
constexpr __mmask16 build_mask_for_nibble(int nibble) {
    __mmask16 m = 0;
    for (int b = 0; b < 4; ++b)
        if ((nibble >> b) & 1) m = (__mmask16)(m | ((__mmask16)0xF << (b * 4)));
    return m;
}
inline constexpr __mmask16 kMaskTab[16] = {
    build_mask_for_nibble(0),  build_mask_for_nibble(1),
    build_mask_for_nibble(2),  build_mask_for_nibble(3),
    build_mask_for_nibble(4),  build_mask_for_nibble(5),
    build_mask_for_nibble(6),  build_mask_for_nibble(7),
    build_mask_for_nibble(8),  build_mask_for_nibble(9),
    build_mask_for_nibble(10), build_mask_for_nibble(11),
    build_mask_for_nibble(12), build_mask_for_nibble(13),
    build_mask_for_nibble(14), build_mask_for_nibble(15),
};

// Generate 4 AES-CTR blocks at counters (b0..b0+3) using VAES-512.
// Counter format = makeBlock(0, b0+j): low-64 = ctr, high-64 = 0.
// Lane t of the returned zmm = AES_kk(makeBlock(0, b0+t)).
EMP_AES_TARGET_ATTR
inline __m512i aes_4blocks(int64_t b0, const AES_KEY* kk) {
    __m512i pt = _mm512_set_epi64(0, b0 + 3, 0, b0 + 2,
                                  0, b0 + 1, 0, b0 + 0);
    __m512i rk = _mm512_broadcast_i32x4(kk->rd_key[0]);
    pt = _mm512_xor_si512(pt, rk);
    #pragma GCC unroll 9
    for (int r = 1; r < 10; ++r) {
        rk = _mm512_broadcast_i32x4(kk->rd_key[r]);
        pt = _mm512_aesenc_epi128(pt, rk);
    }
    rk = _mm512_broadcast_i32x4(kk->rd_key[10]);
    return _mm512_aesenclast_epi128(pt, rk);
}

}  // namespace view_b_detail

// Sender. T=4: one VAES-512 zmm covers all four j-positions per leaf.
// Caller-provided u_chunk[bs] and v_planes_chunk[k * bs] (plane-major:
// v_planes_chunk[d * bs + j] = v_d[j]).
template <int k, int T = 4>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_view_b(const block leaves[1 << k],
                                  uint64_t session,
                                  int64_t b0, int64_t bs,
                                  block* u_chunk,
                                  block* v_planes_chunk) {
    static_assert(k == 8, "sfvole_sender_view_b: implemented for k=8 only");
    static_assert(T == 4, "sfvole_sender_view_b: T=4 (single VAES-512 zmm per tile)");
    constexpr int Q = 1 << k;

    // Hoist all Q AES key expansions once per chunk. ~44 KB stack at
    // k=8 — same footprint as the NEON butterfly path.
    alignas(16) AES_KEY keys[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int x = 0; x < Q; ++x)
        AES_set_encrypt_key(leaves[x] ^ session_xor, &keys[x]);

    // Tile body and flush are factored as lambdas: the main loop and the
    // (possibly partial) tail share the accumulate logic; only the flush
    // varies in how many j-positions get stored. This matters because
    // SoftSpokenOT calls compute_chunk with bs as small as 1 (malicious
    // sacrificial chunk in rcot_recv_end → rcot_recv_next(scratch, 128)).
    auto tile_accumulate = [&](int64_t t0, __m512i acc_lo[T],
                               __m512i acc_hi[T], __m512i& u_acc) {
        for (int t = 0; t < T; ++t) {
            acc_lo[t] = _mm512_setzero_si512();
            acc_hi[t] = _mm512_setzero_si512();
        }
        u_acc = _mm512_setzero_si512();

        for (int x = 0; x < Q; ++x) {
            __m512i r_zmm = view_b_detail::aes_4blocks(b0 + t0, &keys[x]);
            const __mmask16 m_lo = view_b_detail::kMaskTab[x & 0xF];
            const __mmask16 m_hi = view_b_detail::kMaskTab[(x >> 4) & 0xF];

            __m512i b0z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0x00);
            __m512i b1z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0x55);
            __m512i b2z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0xAA);
            __m512i b3z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0xFF);

            acc_lo[0] = _mm512_mask_xor_epi32(acc_lo[0], m_lo, acc_lo[0], b0z);
            acc_lo[1] = _mm512_mask_xor_epi32(acc_lo[1], m_lo, acc_lo[1], b1z);
            acc_lo[2] = _mm512_mask_xor_epi32(acc_lo[2], m_lo, acc_lo[2], b2z);
            acc_lo[3] = _mm512_mask_xor_epi32(acc_lo[3], m_lo, acc_lo[3], b3z);
            acc_hi[0] = _mm512_mask_xor_epi32(acc_hi[0], m_hi, acc_hi[0], b0z);
            acc_hi[1] = _mm512_mask_xor_epi32(acc_hi[1], m_hi, acc_hi[1], b1z);
            acc_hi[2] = _mm512_mask_xor_epi32(acc_hi[2], m_hi, acc_hi[2], b2z);
            acc_hi[3] = _mm512_mask_xor_epi32(acc_hi[3], m_hi, acc_hi[3], b3z);

            u_acc = _mm512_xor_si512(u_acc, r_zmm);
        }
    };

    auto flush = [&](int64_t t0, int n_valid,
                     const __m512i acc_lo[T], const __m512i acc_hi[T],
                     __m512i u_acc) {
        for (int t = 0; t < n_valid; ++t) {
            _mm_storeu_si128((__m128i*)&v_planes_chunk[0 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 0));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[1 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 1));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[2 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 2));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[3 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 3));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[4 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 0));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[5 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 1));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[6 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 2));
            _mm_storeu_si128((__m128i*)&v_planes_chunk[7 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 3));
        }
        if (n_valid == T) {
            _mm512_storeu_si512((__m512i*)&u_chunk[t0], u_acc);
        } else {
            // _mm512_extracti32x4_epi32 requires a 2-bit immediate,
            // so dispatch on n_valid with literal indices (T=4).
            __m128i u0 = _mm512_extracti32x4_epi32(u_acc, 0);
            _mm_storeu_si128((__m128i*)&u_chunk[t0 + 0], u0);
            if (n_valid > 1) {
                __m128i u1 = _mm512_extracti32x4_epi32(u_acc, 1);
                _mm_storeu_si128((__m128i*)&u_chunk[t0 + 1], u1);
            }
            if (n_valid > 2) {
                __m128i u2 = _mm512_extracti32x4_epi32(u_acc, 2);
                _mm_storeu_si128((__m128i*)&u_chunk[t0 + 2], u2);
            }
        }
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) {
        __m512i acc_lo[T];
        __m512i acc_hi[T];
        __m512i u_acc;
        tile_accumulate(t0, acc_lo, acc_hi, u_acc);
        flush(t0, T, acc_lo, acc_hi, u_acc);
    }
    if (bs > bs_full) {
        __m512i acc_lo[T];
        __m512i acc_hi[T];
        __m512i u_acc;
        tile_accumulate(bs_full, acc_lo, acc_hi, u_acc);
        flush(bs_full, (int)(bs - bs_full), acc_lo, acc_hi, u_acc);
    }
}

// Receiver. Substitution y = α ⊕ x: w_b = ⊕_{y : bit_b(y)=1} r_{α⊕y}.
// y=0 → r_α (uses leaves[α], pinned to zero_block by pprf_eval_receiver
// — its bogus AES output is harmlessly absorbed since bit_b(0)=0 ∀ b).
template <int k, int T = 4>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_view_b(int alpha,
                                    const block leaves[1 << k],
                                    uint64_t session,
                                    int64_t b0, int64_t bs,
                                    block* w_planes_chunk) {
    static_assert(k == 8, "sfvole_receiver_view_b: implemented for k=8 only");
    static_assert(T == 4, "sfvole_receiver_view_b: T=4");
    constexpr int Q = 1 << k;

    // α-permuted key expansion: keys[y] = expand(leaves[α ⊕ y]).
    alignas(16) AES_KEY keys[Q];
    const block session_xor = makeBlock(0LL, (int64_t)session);
    for (int y = 0; y < Q; ++y)
        AES_set_encrypt_key(leaves[alpha ^ y] ^ session_xor, &keys[y]);

    auto tile_accumulate = [&](int64_t t0, __m512i acc_lo[T],
                               __m512i acc_hi[T]) {
        for (int t = 0; t < T; ++t) {
            acc_lo[t] = _mm512_setzero_si512();
            acc_hi[t] = _mm512_setzero_si512();
        }
        for (int y = 0; y < Q; ++y) {
            __m512i r_zmm = view_b_detail::aes_4blocks(b0 + t0, &keys[y]);
            const __mmask16 m_lo = view_b_detail::kMaskTab[y & 0xF];
            const __mmask16 m_hi = view_b_detail::kMaskTab[(y >> 4) & 0xF];

            __m512i b0z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0x00);
            __m512i b1z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0x55);
            __m512i b2z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0xAA);
            __m512i b3z = _mm512_shuffle_i32x4(r_zmm, r_zmm, 0xFF);

            acc_lo[0] = _mm512_mask_xor_epi32(acc_lo[0], m_lo, acc_lo[0], b0z);
            acc_lo[1] = _mm512_mask_xor_epi32(acc_lo[1], m_lo, acc_lo[1], b1z);
            acc_lo[2] = _mm512_mask_xor_epi32(acc_lo[2], m_lo, acc_lo[2], b2z);
            acc_lo[3] = _mm512_mask_xor_epi32(acc_lo[3], m_lo, acc_lo[3], b3z);
            acc_hi[0] = _mm512_mask_xor_epi32(acc_hi[0], m_hi, acc_hi[0], b0z);
            acc_hi[1] = _mm512_mask_xor_epi32(acc_hi[1], m_hi, acc_hi[1], b1z);
            acc_hi[2] = _mm512_mask_xor_epi32(acc_hi[2], m_hi, acc_hi[2], b2z);
            acc_hi[3] = _mm512_mask_xor_epi32(acc_hi[3], m_hi, acc_hi[3], b3z);
        }
    };

    auto flush = [&](int64_t t0, int n_valid,
                     const __m512i acc_lo[T], const __m512i acc_hi[T]) {
        for (int t = 0; t < n_valid; ++t) {
            _mm_storeu_si128((__m128i*)&w_planes_chunk[0 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 0));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[1 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 1));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[2 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 2));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[3 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_lo[t], 3));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[4 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 0));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[5 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 1));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[6 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 2));
            _mm_storeu_si128((__m128i*)&w_planes_chunk[7 * bs + t0 + t],
                             _mm512_extracti32x4_epi32(acc_hi[t], 3));
        }
    };

    const int64_t bs_full = (bs / T) * T;
    for (int64_t t0 = 0; t0 < bs_full; t0 += T) {
        __m512i acc_lo[T];
        __m512i acc_hi[T];
        tile_accumulate(t0, acc_lo, acc_hi);
        flush(t0, T, acc_lo, acc_hi);
    }
    if (bs > bs_full) {
        __m512i acc_lo[T];
        __m512i acc_hi[T];
        tile_accumulate(bs_full, acc_lo, acc_hi);
        flush(bs_full, (int)(bs - bs_full), acc_lo, acc_hi);
    }
}

}}  // namespace emp::softspoken

#endif  // EMP_AES_HAS_VAES512

#endif  // EMP_SOFTSPOKEN_SFVOLE_VIEW_B_H__
