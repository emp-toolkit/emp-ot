#ifndef EMP_SOFTSPOKEN_OT_H__
#define EMP_SOFTSPOKEN_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/cot.h"
#include "emp-ot/base_ot/pvw.h"
#include "emp-ot/cggm.h"
#include "emp-ot/softspoken/sfvole_butterfly.h"
#include <cstdint>
#include <cstring>
#include <memory>

namespace emp { namespace softspoken {

// =====================================================================
// Fused AES-CTR + multi-target XOR-fold kernel (leaf-major fallback for
// k=2 / k=4). Inner loop:
//   for j in [0, n_blocks):
//     ct = AES_K(makeBlock(0, base_ctr + j) ⊕ tweak)
//     for t in [0, N_TARGETS): tgts[t][j] ^= ct
// keeping `ct` in SIMD registers from AES last-round through the
// multi-target XOR-store — no intermediate r_x[bs] scratch is ever
// materialized in memory.
//
// `key` is a session-shared fixed AES schedule (caller hoists out of
// the per-leaf loop). `tweak` is the per-leaf input that distinguishes
// leaves and session — typically `leaves[x] ⊕ session_xor`. AES_K is
// modeled as a random permutation, mirroring PRP / CCRH in emp-tool.
// The multi-target shape (N_TARGETS up to 1+k = 9 at k=8) is specific
// to small-field VOLE.

#ifdef __x86_64__

// Tile-loop kernel: encrypt n_tiles tiles of L::N blocks each from
// (counter ⊕ tweak) under fixed key, folding each cipher block into
// tgts[j][off..] (XOR-store) for j in [0, N_TARGETS). Same shape as
// emp::detail::aes_tiles_src but with a runtime n_tiles and a fold-XOR
// sink instead of a store sink.
template <class L, int N_TARGETS>
EMP_AES_TARGET_ATTR
static inline void aes_ctr_fold_tiles(block* const tgts[N_TARGETS],
                                      int n_tiles, int64_t base_off,
                                      int64_t b0, const AES_KEY* kk,
                                      block tweak) {
    if (n_tiles == 0) return;
    typename L::vec_t rk[11];
    for (int r = 0; r < 11; ++r) rk[r] = L::broadcast(kk->rd_key[r]);
    const typename L::vec_t tw = L::broadcast(tweak);
    for (int t = 0; t < n_tiles; ++t) {
        auto x = L::ctr_xor_tweak(b0, t, tw);
        x = L::xorv(x, rk[0]);
        for (int r = 1; r < 10; ++r) x = L::aesenc(x, rk[r]);
        x = L::aesenclast(x, rk[10]);
        const size_t off = (size_t)base_off + (size_t)t * L::N;
        for (int j = 0; j < N_TARGETS; ++j)
            L::store(tgts[j] + off, L::xorv(L::load(tgts[j] + off), x));
    }
}

// Public entry point. Per-call tile schedule mirrors ParaEnc<1, N>:
// VAES512 4-tiles → VAES256 2-tiles → AES-NI 1-tiles. Lane traits and
// ctr_xor_tweak come from emp-tool/crypto/aes.h.
template <int N_TARGETS>
EMP_AES_TARGET_ATTR
inline void aes_ctr_fold(block* const tgts[N_TARGETS], int n_blocks,
                         int64_t base_ctr, const AES_KEY* key, block tweak) {
    int64_t ctr = base_ctr;
    int64_t off = 0;

#if EMP_AES_HAS_VAES512
    {
        const int n4 = n_blocks / 4;
        if (n4 > 0) {
            aes_ctr_fold_tiles<emp::detail::Lane512, N_TARGETS>(
                tgts, n4, off, ctr, key, tweak);
            const int b = n4 * 4;
            off += b; ctr += b; n_blocks -= b;
        }
    }
#endif
#if EMP_AES_HAS_VAES256
    {
        const int n2 = n_blocks / 2;
        if (n2 > 0) {
            aes_ctr_fold_tiles<emp::detail::Lane256, N_TARGETS>(
                tgts, n2, off, ctr, key, tweak);
            const int b = n2 * 2;
            off += b; ctr += b; n_blocks -= b;
        }
    }
#endif
    if (n_blocks > 0) {
        aes_ctr_fold_tiles<emp::detail::Lane128, N_TARGETS>(
            tgts, n_blocks, off, ctr, key, tweak);
    }
}

#elif __aarch64__

// NEON path: hold T=4 plaintexts in registers across the round loop,
// then fold into N_TARGETS destinations. Tail (n_blocks % 4) handled
// per-block.
template <int N_TARGETS>
inline void aes_ctr_fold(block* const tgts_in[N_TARGETS], int n_blocks,
                         int64_t base_ctr, const AES_KEY* key, block tweak) {
    constexpr int T = 4;
    const int n_full = n_blocks / T;
    const int tail   = n_blocks - n_full * T;
    const uint8x16_t tw = vreinterpretq_u8_m128i(tweak);

    for (int t = 0; t < n_full; ++t) {
        const int64_t base = base_ctr + (int64_t)t * T;
        uint8x16_t pt[T];
        for (int j = 0; j < T; ++j) {
            uint64_t lo = (uint64_t)(base + j);
            const uint8x16_t ctr =
                vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
            pt[j] = veorq_u8(ctr, tw);
        }
        for (unsigned int r = 0; r < 9; ++r) {
            uint8x16_t K = vreinterpretq_u8_m128i(key->rd_key[r]);
            for (int j = 0; j < T; ++j) pt[j] = vaesmcq_u8(vaeseq_u8(pt[j], K));
        }
        {
            uint8x16_t K  = vreinterpretq_u8_m128i(key->rd_key[9]);
            uint8x16_t K2 = vreinterpretq_u8_m128i(key->rd_key[10]);
            for (int j = 0; j < T; ++j) pt[j] = veorq_u8(vaeseq_u8(pt[j], K), K2);
        }
        for (int n = 0; n < N_TARGETS; ++n) {
            uint8_t* dst = (uint8_t*)(tgts_in[n] + (size_t)t * T);
            for (int j = 0; j < T; ++j) {
                uint8x16_t cur = vld1q_u8(dst + j * 16);
                cur = veorq_u8(cur, pt[j]);
                vst1q_u8(dst + j * 16, cur);
            }
        }
    }
    for (int t = 0; t < tail; ++t) {
        const int64_t off = (int64_t)n_full * T + t;
        uint64_t lo = (uint64_t)(base_ctr + off);
        const uint8x16_t ctr =
            vreinterpretq_u8_u64(vsetq_lane_u64(lo, vdupq_n_u64(0), 0));
        uint8x16_t pt = veorq_u8(ctr, tw);
        for (unsigned int r = 0; r < 9; ++r) {
            uint8x16_t K = vreinterpretq_u8_m128i(key->rd_key[r]);
            pt = vaesmcq_u8(vaeseq_u8(pt, K));
        }
        uint8x16_t K  = vreinterpretq_u8_m128i(key->rd_key[9]);
        uint8x16_t K2 = vreinterpretq_u8_m128i(key->rd_key[10]);
        pt = veorq_u8(vaeseq_u8(pt, K), K2);
        for (int n = 0; n < N_TARGETS; ++n) {
            uint8_t* dst = (uint8_t*)(tgts_in[n] + off);
            uint8x16_t cur = vld1q_u8(dst);
            cur = veorq_u8(cur, pt);
            vst1q_u8(dst, cur);
        }
    }
}

#endif

// Dispatch on runtime target count `n` into the compile-time-N
// aes_ctr_fold<N> instantiation. n ∈ [1, 1+k]; cases past 1+k are
// discarded via `if constexpr` so unused instantiations aren't emitted
// for low-k builds. SoftSpoken's k ∈ {2, 4, 8} ⇒ N_MAX ∈ {3, 5, 9}.
template <int k>
EMP_AES_TARGET_ATTR
inline void dispatch_ctr_fold(block** tgts, int n, int n_blocks,
                              int64_t base_ctr, const AES_KEY* key,
                              block tweak) {
    constexpr int N_MAX = 1 + k;
    switch (n) {
        case 1: aes_ctr_fold<1>(tgts, n_blocks, base_ctr, key, tweak); return;
        case 2: aes_ctr_fold<2>(tgts, n_blocks, base_ctr, key, tweak); return;
        case 3: if constexpr (N_MAX >= 3) { aes_ctr_fold<3>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 4: if constexpr (N_MAX >= 4) { aes_ctr_fold<4>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 5: if constexpr (N_MAX >= 5) { aes_ctr_fold<5>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 6: if constexpr (N_MAX >= 6) { aes_ctr_fold<6>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 7: if constexpr (N_MAX >= 7) { aes_ctr_fold<7>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 8: if constexpr (N_MAX >= 8) { aes_ctr_fold<8>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
        case 9: if constexpr (N_MAX >= 9) { aes_ctr_fold<9>(tgts, n_blocks, base_ctr, key, tweak); return; } break;
    }
}



// =====================================================================
// Conv: F_2-linear bit packing between F_{2^k}^n and F_{2^128}.
// Bit (i*k + b) of the 128-bit output = bit b of the i-th F_{2^k} input.
// Constrained to k ∈ {1, 2, 4, 8} so n*k = 128 exactly; the bulk
// direction (Conv across many OTs at once) is then exactly a
// 128 × (bpr*128) sse_trans of the contiguous plane buffer — call
// sse_trans directly at the use site (see softspoken_ot.cpp).
//
// `unpack<k>` is the inverse direction, used by setup_send to split
// Δ into n alpha_i bytes — a single-block scalar op, no transpose
// involved.

template <int k>
constexpr int n_subvoles() {
    static_assert(k >= 1 && k <= 8 && (128 % k) == 0,
                  "softspoken: k must be in {1, 2, 4, 8} so n*k == 128");
    return 128 / k;
}

// Decompose a 128-bit block into n F_{2^k} elements (low k bits of
// each output byte hold the value). Used once per session in
// setup_send to split Δ into per-sub-VOLE alpha_i.
template <int k>
inline void unpack(block in, uint8_t* out_n) {
    constexpr int n = n_subvoles<k>();
    uint8_t bytes[16];
    std::memcpy(bytes, &in, 16);
    for (int i = 0; i < n; ++i) {
        uint8_t v = 0;
        for (int b = 0; b < k; ++b) {
            const int bitpos = i * k + b;
            v |= ((bytes[bitpos >> 3] >> (bitpos & 7)) & 1u) << b;
        }
        out_n[i] = v;
    }
}

// =====================================================================
// PPRF: thin wrappers around the shared cGGM tree (emp-ot/cggm.h),
// reused as a punctured PRF here because softspoken never reveals Δ to
// the receiver (no per-COT correction byte, no global-Δ base-COT
// layer). With per-tree fresh Δ, the receiver's view of leaves[α]
// stays pseudorandom even though XOR(leaves) = Δ holds.

// Sender: sample fresh Δ and root from `rng`, build the depth-k cGGM
// tree. K0[h] is the level-(h+1) left-side XOR-sum; K1[h] = K0[h] ⊕ Δ
// via leveled correlation. The (K0, K1) pair is shipped via base
// 1-of-2 OTs by the caller.
template <int k>
inline void pprf_build_sender(PRG& rng,
                              block leaves[1 << k],
                              block K0[k],
                              block K1[k]) {
    block Delta, root;
    rng.random_block(&Delta, 1);
    rng.random_block(&root, 1);
    cggm::build_sender(k, Delta, root, leaves, K0);
    for (int h = 0; h < k; ++h) K1[h] = K0[h] ^ Delta;
}

// Receiver: alpha in [0, 2^k) is the punctured leaf index, MSB-first.
// On return, leaves[x] is correct for every x != alpha; leaves[alpha]
// = zero_block.
template <int k>
inline void pprf_eval_receiver(int alpha,
                               const block K_recv[k],
                               block leaves[1 << k]) {
    cggm::eval_receiver(k, alpha, K_recv, leaves);
}

// =====================================================================
// Sub-space VOLE inner loop (chunked).
//
// Chunked variants take a counter offset b0 and chunk length bs (in
// bpr-blocks). Chunk c reads PRG output blocks [b0, b0+bs). Output is
// bit-identical to a single PRG.random_block over the same range —
// chunking + setting the counter to b0 reproduces the slice.
//
// PRG semantics: PRG_x(j) = AES_K(j ⊕ leaves[x] ⊕ session_xor) where
// K is a session-shared fixed AES key (built from emp-tool's `fix_key`
// constant). Treats AES_K as a random permutation, mirroring the
// PRP / CCRH / MITCCRH model already in emp-tool. The leaf is folded
// into the AES plaintext as a tweak rather than the AES key, so round
// keys persist across all Q × bs encryptions in a chunk and the key
// schedule is one-shot per kernel call instead of per-leaf.
//
// Inner loop uses the fused AES-CTR + multi-target XOR-fold kernel
// (defined above): each leaf's r_x[bs] is generated and consumed
// inside the AES tile loop (in SIMD registers, never materialized to
// memory).

// Maximum chunk size (in bpr-blocks) the chunked sfvole helpers will
// be called with. Sets stack-resident scratch sizing in
// softspoken_ot.cpp (u_canonical / u_temp). The fused kernel itself
// no longer needs a per-leaf scratch buffer.
constexpr int kMaxChunkBlocks = 1024;

// Per-k chunk size (in bpr-blocks). Larger chunks amortize per-chunk
// overhead better but eventually hit cache pressure; per-leaf compute
// grows as 2^k, so larger k tolerates a larger chunk before the cliff.
//   k=2 → 128:  little compute per leaf — small chunk avoids L1
//               pressure on small-cache parts.
//   k=4 → 1024: heavier compute per leaf supports a larger
//               amortization window.
//   k=8 → 1024: Q=256 leaves means lots of fold work per chunk;
//               amortization wins up to the L2 cliff.
template <int k>
constexpr int chunk_blocks_for() {
    if constexpr (k <= 2)      return 128;
    else if constexpr (k <= 4) return 1024;
    else                       return 1024;
}

// Sender-side chunked sfvole: under a session-shared fixed AES key,
// folds AES_K(j ⊕ leaves[x] ⊕ session_xor) directly into u_bits and
// the selected v_planes (no r_x materialization, no per-leaf key
// schedule). k=8 routes to the cross-platform butterfly kernel
// (sfvole_butterfly.h); k=2 / k=4 take the leaf-major path below.
template <int k>
EMP_AES_TARGET_ATTR
inline void sfvole_sender_compute_chunk(const block leaves[1 << k],
                                        uint64_t session,
                                        int64_t b0,
                                        int64_t bs,
                                        block* u_bits_chunk,
                                        block* v_planes_chunk) {
    if constexpr (k == 8) {
        sfvole_sender_butterfly<k>(leaves, session, b0, bs,
                                    u_bits_chunk, v_planes_chunk);
        return;
    }

    constexpr int Q = 1 << k;

    std::memset(u_bits_chunk,   0, sizeof(block) * bs);
    std::memset(v_planes_chunk, 0, sizeof(block) * k * bs);

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);
    const block session_xor = makeBlock(0LL, static_cast<int64_t>(session));

    for (int x = 0; x < Q; ++x) {
        // PRG_x(j) = AES_K(j ⊕ leaves[x] ⊕ session_xor). Fixed-key AES
        // as random permutation, leaf folded into the plaintext tweak.
        const block tweak = leaves[x] ^ session_xor;

        // Build the leaf's fold target list: u always, v_planes[b] for
        // each set bit b of x. n ∈ [1, 1+k].
        block* tgts[1 + k];
        int n = 0;
        tgts[n++] = u_bits_chunk;
        for (int b = 0; b < k; ++b)
            if ((x >> b) & 1) tgts[n++] = v_planes_chunk + (size_t)b * bs;

        dispatch_ctr_fold<k>(tgts, n, static_cast<int>(bs), b0, &fixed_K, tweak);
    }
}

// Receiver-side chunked sfvole. Skips x = alpha; folds AES_seed(b0..b0+bs)
// into w_planes[b] for each set bit b of (alpha XOR x). k=8 routes to
// the cross-platform butterfly kernel (sfvole_butterfly.h); k=2 / k=4
// take the leaf-major path below.
template <int k>
EMP_AES_TARGET_ATTR
inline void sfvole_receiver_compute_chunk(int alpha,
                                          const block leaves[1 << k],
                                          uint64_t session,
                                          int64_t b0,
                                          int64_t bs,
                                          block* w_planes_chunk) {
    if constexpr (k == 8) {
        sfvole_receiver_butterfly<k>(alpha, leaves, session, b0, bs,
                                      w_planes_chunk);
        return;
    }

    constexpr int Q = 1 << k;

    std::memset(w_planes_chunk, 0, sizeof(block) * k * bs);

    AES_KEY fixed_K;
    AES_set_encrypt_key(_mm_loadu_si128((const __m128i*)fix_key), &fixed_K);
    const block session_xor = makeBlock(0LL, static_cast<int64_t>(session));

    for (int x = 0; x < Q; ++x) {
        if (x == alpha) continue;
        const block tweak = leaves[x] ^ session_xor;

        // For x ≠ alpha, coeff ≠ 0, so n ≥ 1. Max n = k.
        const int coeff = alpha ^ x;
        block* tgts[k > 0 ? k : 1];
        int n = 0;
        for (int b = 0; b < k; ++b)
            if ((coeff >> b) & 1) tgts[n++] = w_planes_chunk + (size_t)b * bs;

        dispatch_ctr_fold<k>(tgts, n, static_cast<int>(bs), b0, &fixed_K, tweak);
    }
}

// Apply d_i (bs blocks) to receiver's w_planes_i: for each set bit b
// of alpha_i, XOR d_i into plane b. Sub-space VOLE derandomization
// step on the OT-sender side.
template <int k>
inline void apply_derand_to_w_planes(int alpha_i,
                                     const block* d_i,
                                     int64_t bs,
                                     block* w_planes) {
    for (int b = 0; b < k; ++b) {
        if ((alpha_i >> b) & 1) {
            block* dst = w_planes + b * bs;
            for (int64_t j = 0; j < bs; ++j)
                dst[j] = dst[j] ^ d_i[j];
        }
    }
}

// Bulk Conv = sse_trans(out, planes, 128, bpr*128). Inlined at the
// (few) call sites in softspoken_ot.cpp / bench_conv. The plane
// buffer's plane-major layout (plane p at offset p*bpr blocks) is
// already the row-major byte layout sse_trans expects; n_subvoles<k>'s
// static_assert above guarantees n*k == 128.

}}  // namespace emp::softspoken

namespace emp {

/*
 * SoftSpoken OT Extension — RandomCOT subclass, semi-honest by
 * default; call `set_malicious(true)` before setup to enable the two
 * malicious-security checks.
 * [REF] L. Roy, "SoftSpokenOT: Quieter OT Extension from Small-Field
 *       Silent VOLE in the Minicrypt Model" — Crypto '22.
 *       https://eprint.iacr.org/2022/192
 *
 * The protocol is natively a RandomCOT: after sfvole_*_compute,
 * u_canonical[j] is the receiver's intrinsic random choice bit and
 * Conv(V[j]) ⊕ Conv(W[j]) = u_canonical[j] · Δ at the full-block
 * level. rcot_send / rcot_recv expose this directly with the
 * LSB-of-output choice convention (LSB(K)=0, LSB(M)=u_canonical[j]).
 * send_cot / recv_cot are inherited from RandomCOT, which adds the
 * standard 1-bit-per-COT chosen-message correction wrapper.
 *
 * Templated on k, the F_{2^k} sub-field size used inside the small-
 * field VOLE. Larger k = less bandwidth (~kappa/k bytes per COT) but
 * more compute (~2^k / k AES blocks per COT). Pre-instantiated for
 * k in {2, 4, 8} in softspoken_ot.cpp.
 *
 * Streaming. rcot_send / rcot_recv chunk the OT-output axis: each
 * begin → loop _next → end runs one session, with a small per-chunk
 * plane scratch (member-resident BlockVec, sized n*k*kChunkBlocks).
 * The per-leaf AES key is re-expanded from its 16 B seed at the start
 * of every chunk — see softspoken::sfvole_*_compute_chunk above.
 *
 * Δ has LSB=1 (forced by setup_send no-arg, required of callers
 * passing setup_send(delta_in)). Required for the LSB-encoded choice
 * convention to round-trip the COT relation correctly.
 *
 * Malicious mode (off by default). Two checks compose to upgrade from
 * the semi-honest baseline to malicious-secure (Roy '22 Fig.
 * `protpprfconsistency` and Fig. `protvoleconsistency`):
 *
 *   (1) PPRF check, run once at end of setup_send / setup_recv. The
 *       PPRF-sender (= COT-receiver / setup_recv side) ships per-level
 *       K^0/K^1 blocks via base OT and could lie there to corrupt the
 *       PPRF-receiver's (= COT-sender / setup_send side) leaves at
 *       indices y ≠ alpha_i. To bind, the PPRF-sender sends per-sub-
 *       VOLE (s' := SHA256(leaves), t' := XOR-of-leaves); the
 *       PPRF-receiver reconstructs leaves[alpha_i] = t' XOR
 *       XOR_{y≠alpha_i} leaves[y], hashes the full vector, and aborts
 *       on mismatch. Bounds the per-sub-VOLE selective-abort leakage
 *       to affinesub(F_2^k) (Roy Prop. `pprfcheckattack`).
 *
 *   (2) Subspace VOLE check, run once per begin/next…/end session. A
 *       Fiat-Shamir transcript over the d_bufs bytes of every chunk
 *       seeds a per-chunk chi; both sides chi-fold packed F_{2^128}
 *       elements over the post-Conv outputs (sender accumulates
 *       check_q := Σ chi_i · Q_i, receiver check_t := Σ chi_i · T_i,
 *       check_x := Σ chi_i · R_i where R_i = u_canonical[i]). One
 *       128-OT sacrificial chunk runs in *_end before the (check_x,
 *       check_t) exchange and the check_q ?= check_t ⊕ check_x · Δ
 *       compare. Catches any deviation by the VOLE-sender (= COT-
 *       receiver) in the d_bufs syndrome. Same chi-fold shape as IKNP
 *       — see emp-ot/iknp.{h,cpp}.
 */
template <int k>
class SoftSpokenOT : public RandomCOT {
    static_assert(k >= 1 && k <= 8, "SoftSpokenOT supports k in [1, 8]");
public:
    static constexpr int n = softspoken::n_subvoles<k>();
    static constexpr int Q = 1 << k;

    // User-supplied base OT, owned by SoftSpokenOT. Defaults to OTPVW
    // (DDH messy-mode PVW '08 — malicious-secure). Pass a different
    // one (e.g., OTCSW or OTPVWKyber) via the second ctor arg.
    explicit SoftSpokenOT(IOChannel* io_, std::unique_ptr<OT> base_ot = nullptr);
    ~SoftSpokenOT() override = default;

    // RandomCOT virtual contract. send_cot / recv_cot inherit from
    // RandomCOT and run the standard 1-bit-per-COT chosen-message
    // correction wrapper on top.
    //
    // rcot_send / rcot_recv are thin wrappers around the streaming
    // API below: each runs one _begin → loop _next → _end session,
    // with internal chunk size kChunkBlocks * 128 OTs.
    void rcot_send(block* data, int64_t length) override;
    void rcot_recv(block* data, int64_t length) override;

    // Streaming API — IKNP-shape. After _begin(), call _next() any
    // number of times with chunk_len a multiple of 128 and ≤
    // kChunkBlocks * 128, then _end() to flush. Setup must already be
    // done (one-shot wrappers above auto-run setup; the streaming
    // entry points assert it).
    static constexpr int kChunkBlocks = softspoken::chunk_blocks_for<k>();
    static constexpr int kChunkOTs    = kChunkBlocks * 128;

    void rcot_send_begin();
    void rcot_send_next(block* out, int64_t chunk_len);
    void rcot_send_end();

    void rcot_recv_begin();
    void rcot_recv_next(block* out, int64_t chunk_len);
    void rcot_recv_end();

    // Externally-provided Δ (must have LSB=1). The decomposition
    // unpack<k>(Δ, ...) into alphas_ works for any Δ ∈ F_{2^128};
    // setup proceeds identically. Used by ferret to share its global
    // Δ with the bootstrap base-OT generator.
    void setup_send(block delta_in);

    // Receiver-role setup. Exposed so ferret can drive the bootstrap
    // explicitly (rcot_send/rcot_recv auto-run the matching setup on
    // first call, but ferret wants to synchronize role selection with
    // its own party flag).
    void setup_recv();

    // Enable malicious-mode checks. Must be called BEFORE setup_send /
    // setup_recv so the PPRF check runs at the tail of setup. Once
    // setup is done, the flag also gates the per-session subspace
    // VOLE check in rcot_*_begin/next/end. Asserts that the base OT
    // is itself malicious-secure (a semi-honest base would invalidate
    // the malicious-mode security claim).
    void set_malicious(bool on = true) {
        if (on && !base_ot_->is_malicious_secure())
            error("SoftSpokenOT::set_malicious(true) requires a malicious-secure base OT");
        malicious_ = on;
    }

private:
    std::unique_ptr<OT> base_ot_;
    bool setup_done_ = false;
    uint64_t session_ = 0;

    // COT-Sender (= VOLE-Receiver / PPRF-Receiver) state.
    int alphas_[n] = {0};
    std::unique_ptr<block[]> leaves_recv_;  // n * Q blocks; punctured at alphas_[i]

    // COT-Receiver (= VOLE-Sender / PPRF-Sender) state.
    std::unique_ptr<block[]> leaves_send_;  // n * Q blocks; full GGM tree

    // Streaming session state. Each begin/next.../end runs one
    // SoftSpoken session with a fresh session_id; cur_*_b0 tracks the
    // PRG counter offset (in bpr-blocks) consumed by previous _next
    // calls in this session.
    bool send_session_active_ = false;
    bool recv_session_active_ = false;
    uint64_t cur_send_session_ = 0;
    uint64_t cur_recv_session_ = 0;
    int64_t cur_send_b0_ = 0;
    int64_t cur_recv_b0_ = 0;

    // Per-chunk scratch (allocated at the first _next call; reused
    // across chunks within and across sessions). Heap-resident so we
    // can grow B past the comfortable stack limit without changing
    // call sites.
    BlockVec planes_chunk_;   // n * k * kChunkBlocks blocks
    BlockVec d_bufs_chunk_;   // (n - 1) * kChunkBlocks blocks

    // ===== Malicious-mode state =====
    bool malicious_ = false;
    // Fiat-Shamir transcript over the d_bufs bytes of every chunk in
    // the current session (reset at *_begin). Snapshots (reset_after=
    // false) seed the per-chunk chi PRG identically on both sides.
    Hash transcript_;
    // Packs 128 consecutive post-Conv outputs into one F_{2^128}
    // element via (1, X, …, X^127); see iknp.cpp::combine_*.
    GaloisFieldPacking packer_;
    // Running chi-fold accumulators, reset at *_begin. Sender uses
    // check_q_; receiver uses check_t_ (folds T_i) and check_x_
    // (folds R_i = u_canonical[i]). The end-of-session compare is
    // check_q_ ?= check_t_ ⊕ check_x_ · Δ.
    block check_q_  = zero_block;
    block check_t_  = zero_block;
    block check_x_  = zero_block;

    void setup_send();
    // Resize the per-chunk scratch buffers to their full kChunkBlocks
    // capacity on first call; cheap no-op afterwards. Called at the
    // top of rcot_send_next / rcot_recv_next.
    void ensure_chunk_scratch_();
    // PPRF consistency check. _send runs on the PPRF-sender (=
    // setup_recv side); _recv on the PPRF-receiver (= setup_send
    // side). Implements Fig. `protpprfconsistency` directly on the
    // cGGM leaves (no separate PRG'_0 — leaves are already PRF
    // outputs and SHA-256 absorbs the full λ-bit input).
    void pprf_check_send();
    void pprf_check_recv();
    // Per-chunk subspace VOLE chi-fold. Both take the chunk's post-
    // Conv `out` (bs * 128 OTs) and accumulate into the matching
    // running check. Chi seed is a snapshot of transcript_ taken
    // after this chunk's d_bufs were absorbed. Mirrors IKNP::combine_*.
    void combine_send_chunk(block* out, int64_t bs);
    void combine_recv_chunk(block* out, const block* u_canonical, int64_t bs);
};

extern template class SoftSpokenOT<2>;
extern template class SoftSpokenOT<4>;
extern template class SoftSpokenOT<8>;

} // namespace emp
#endif
