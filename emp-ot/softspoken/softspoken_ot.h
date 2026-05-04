#ifndef EMP_SOFTSPOKEN_OT_H__
#define EMP_SOFTSPOKEN_OT_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/cot.h"
#include "emp-ot/co.h"
#include "emp-ot/cggm.h"
#include <cstdint>
#include <cstring>
#include <memory>

namespace emp { namespace softspoken {

// =====================================================================
// Conv: F_2-linear bit packing between F_{2^k}^n and F_{2^128}.
// Bit (i*k + b) of the 128-bit output = bit b of the i-th F_{2^k} input.
// We pick n = ceil(128/k); for k in {1,2,4,8} every bit is used,
// otherwise the top n*k - 128 bits of the last input element are
// unused (silently discarded by pack, set to zero by unpack).

template <int k>
constexpr int n_subvoles() {
    static_assert(k >= 1 && k <= 8, "softspoken: k in [1,8]");
    return (128 + k - 1) / k;
}

template <int k>
inline block pack(const uint8_t* in_n) {
    constexpr int n = n_subvoles<k>();
    constexpr uint64_t mask = (1ull << k) - 1ull;
    uint64_t lo = 0, hi = 0;
    for (int i = 0; i < n; ++i) {
        const uint64_t v = static_cast<uint64_t>(in_n[i]) & mask;
        const int bitpos = i * k;
        if (bitpos + k <= 64) {
            lo |= v << bitpos;
        } else if (bitpos >= 64) {
            if (bitpos - 64 < 64) hi |= v << (bitpos - 64);
        } else {
            const int low_bits = 64 - bitpos;
            lo |= (v & ((1ull << low_bits) - 1ull)) << bitpos;
            hi |= v >> low_bits;
        }
    }
    return makeBlock(hi, lo);
}

template <int k>
inline void unpack(block in, uint8_t* out_n) {
    constexpr int n = n_subvoles<k>();
    uint8_t bytes[16];
    std::memcpy(bytes, &in, 16);
    for (int i = 0; i < n; ++i) {
        uint8_t v = 0;
        for (int b = 0; b < k; ++b) {
            const int bitpos = i * k + b;
            if (bitpos >= 128) break;
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
// bit-identical to a single PRG.random_block(buf, b0+bs) covering the
// same range — emp::PRG is plain CTR (output[j] = AES_seed(makeBlock(0,j))),
// so re-keying per chunk + setting the counter to b0 reproduces the
// slice. We pay one AES_set_encrypt_key per leaf per chunk (~30
// cycles) instead of persisting Q PRG objects (~800 KB at k=8);
// amortized over bs * ~10 cycles of encrypt+fold, the overhead is
// ~3/bs.

// Maximum chunk size (in bpr-blocks) the chunked sfvole helpers will
// be called with. The plane-scratch working set is held in a member
// BlockVec on SoftSpokenOT; this constant only sizes the small
// stack-resident r_x / u_canonical / u_temp arrays.
constexpr int kMaxChunkBlocks = 1024;

// Per-k chunk size (in bpr-blocks). Picked from a wide A/B sweep
// across Apple M / Sapphire Rapids+ / Zen 5c at length=2^19 (ferret
// regime) and 2^24 (standalone). Curves are unimodal; these are the
// joint optima at length=2^19.
//   k=2 → 128: re-key cost is already ≤5% at bs=128; bigger just adds
//              cache pressure on small-L1 parts.
//   k=4 → 1024: heavy compute per leaf, larger amortization window
//              wins. Apple M flat across 256–1024.
//   k=8 → 1024: Q=256 means each leaf produces a lot of fold work;
//              amortization keeps winning until L2 cliff.
template <int k>
constexpr int chunk_blocks_for() {
    if constexpr (k <= 2)      return 128;
    else if constexpr (k <= 4) return 1024;
    else                       return 1024;
}

// Sender-side chunked sfvole: re-keys each leaf's AES from its 16 B
// seed, encrypts B blocks of CTR starting at b0, folds into u_bits and
// v_planes.
template <int k>
inline void sfvole_sender_compute_chunk(const block leaves[1 << k],
                                        uint64_t session,
                                        int64_t b0,
                                        int64_t bs,
                                        block* u_bits_chunk,
                                        block* v_planes_chunk) {
    constexpr int Q = 1 << k;

    std::memset(u_bits_chunk,   0, sizeof(block) * bs);
    std::memset(v_planes_chunk, 0, sizeof(block) * k * bs);

    alignas(16) block r_x[kMaxChunkBlocks];
    AES_KEY aes_local;
    const block session_xor = makeBlock(0LL, static_cast<int64_t>(session));

    for (int x = 0; x < Q; ++x) {
        // Matches PRG(seed=leaves[x], id=session).random_block at
        // counter offset b0: emp::PRG seeds via XOR with (0,id) and
        // emits AES_seed(counter) in CTR mode.
        const block seed = leaves[x] ^ session_xor;
        AES_set_encrypt_key(seed, &aes_local);
        for (int64_t b = 0; b < bs; ++b)
            r_x[b] = makeBlock(0LL, b0 + b);
        ParaEnc(r_x, &aes_local, 1, static_cast<int>(bs));

        // u ^= r_x
        for (int64_t b = 0; b < bs; ++b)
            u_bits_chunk[b] = u_bits_chunk[b] ^ r_x[b];

        // For each set bit b of x, plane b ^= r_x.
        for (int b = 0; b < k; ++b) {
            if ((x >> b) & 1) {
                block* dst = v_planes_chunk + b * bs;
                for (int64_t i = 0; i < bs; ++i)
                    dst[i] = dst[i] ^ r_x[i];
            }
        }
    }
}

// Receiver-side chunked sfvole. Skips x = alpha; folds into w_planes
// using (alpha XOR x) coefficient.
template <int k>
inline void sfvole_receiver_compute_chunk(int alpha,
                                          const block leaves[1 << k],
                                          uint64_t session,
                                          int64_t b0,
                                          int64_t bs,
                                          block* w_planes_chunk) {
    constexpr int Q = 1 << k;

    std::memset(w_planes_chunk, 0, sizeof(block) * k * bs);

    alignas(16) block r_x[kMaxChunkBlocks];
    AES_KEY aes_local;
    const block session_xor = makeBlock(0LL, static_cast<int64_t>(session));

    for (int x = 0; x < Q; ++x) {
        if (x == alpha) continue;

        const block seed = leaves[x] ^ session_xor;
        AES_set_encrypt_key(seed, &aes_local);
        for (int64_t b = 0; b < bs; ++b)
            r_x[b] = makeBlock(0LL, b0 + b);
        ParaEnc(r_x, &aes_local, 1, static_cast<int>(bs));

        const int coeff = alpha ^ x;
        for (int b = 0; b < k; ++b) {
            if ((coeff >> b) & 1) {
                block* dst = w_planes_chunk + b * bs;
                for (int64_t i = 0; i < bs; ++i)
                    dst[i] = dst[i] ^ r_x[i];
            }
        }
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

// Pack one row j across all n sub-VOLEs (scalar fallback used when
// n*k != 128). For row j, byte i is sum_b ((bit j of plane[i*k+b]) << b),
// then conv::pack<k> folds those n bytes into one block.
template <int k>
inline block pack_row(const block* const* planes, int n, int64_t j) {
    uint8_t bytes[256];  // n ≤ 128; 256 is safe upper bound.
    const int64_t blk = j >> 7;
    const int     bit = j & 127;
    for (int i = 0; i < n; ++i) {
        uint8_t v = 0;
        for (int b = 0; b < k; ++b) {
            const block plane_blk = planes[i * k + b][blk];
            const uint8_t* bytes_p = reinterpret_cast<const uint8_t*>(&plane_blk);
            v |= ((bytes_p[bit >> 3] >> (bit & 7)) & 1u) << b;
        }
        bytes[i] = v;
    }
    return pack<k>(bytes);
}

// Bulk-pack ell rows into ell output blocks. Fast path when n*k == 128
// (k in {2, 4, 8}): for each chunk of 128 rows, gather one block from
// each of the 128 bit-planes and run a 128×128 sse_trans, which is
// exactly the inverse of the inner-loop structure needed to assemble
// bit (i*k+b) of out[j] from bit j of plane (i*k+b). Cuts pack work
// by ~128× vs row-by-row pack_row. Falls back to pack_row when n*k != 128.
template <int k>
inline void pack_planes_to_blocks(const block* const* planes, int n,
                                  int64_t ell, int64_t bpr,
                                  block* out) {
    constexpr int NK = 128;
    if (n * k != NK) {
        for (int64_t j = 0; j < ell; ++j)
            out[j] = pack_row<k>(planes, n, j);
        return;
    }

    block input[NK];
    block output[NK];

    const int64_t full_chunks = ell / 128;
    for (int64_t chunk = 0; chunk < full_chunks; ++chunk) {
        for (int p = 0; p < NK; ++p)
            input[p] = planes[p][chunk];
        sse_trans(reinterpret_cast<uint8_t*>(output),
                  reinterpret_cast<const uint8_t*>(input), NK, NK);
        for (int r = 0; r < 128; ++r)
            out[chunk * 128 + r] = output[r];
    }

    const int64_t tail = ell - full_chunks * 128;
    if (tail > 0) {
        const int64_t chunk = full_chunks;
        for (int p = 0; p < NK; ++p)
            input[p] = planes[p][chunk];
        sse_trans(reinterpret_cast<uint8_t*>(output),
                  reinterpret_cast<const uint8_t*>(input), NK, NK);
        for (int64_t r = 0; r < tail; ++r)
            out[full_chunks * 128 + r] = output[r];
    }
    (void)bpr;  // unused in fast path
}

}}  // namespace emp::softspoken

namespace emp {

/*
 * SoftSpoken OT Extension — semi-honest, RandomCOT subclass.
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
 */
template <int k>
class SoftSpokenOT : public RandomCOT {
    static_assert(k >= 1 && k <= 8, "SoftSpokenOT supports k in [1, 8]");
public:
    static constexpr int n = softspoken::n_subvoles<k>();
    static constexpr int Q = 1 << k;

    explicit SoftSpokenOT(IOChannel* io_);
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

private:
    OTCO base_ot_;
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

    void setup_send();
};

extern template class SoftSpokenOT<2>;
extern template class SoftSpokenOT<4>;
extern template class SoftSpokenOT<8>;

} // namespace emp
#endif
