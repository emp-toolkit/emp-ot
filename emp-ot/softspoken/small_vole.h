#ifndef EMP_SOFTSPOKEN_SMALL_VOLE_H__
#define EMP_SOFTSPOKEN_SMALL_VOLE_H__
#include <emp-tool/emp-tool.h>
#include <cstdint>
#include <cstring>

namespace emp { namespace softspoken {

// Single small-field VOLE over F_{2^k}, length ell (in COT bits).
// G''(seed) is implemented as PRG(seed, session) producing an
// ell-bit pseudo-random vector r_x.
//
// Sender holds all 2^k leaves; outputs:
//   u_bits   : ceil(ell/128) blocks; bit j = XOR over x of r_x[j]
//   v_planes : k * ceil(ell/128) blocks (k bit-planes)
//              plane b's bit j = bit b of v[j] in F_{2^k}
//              v[j] = sum over x of r_x[j] * x  (all arithmetic in F_2 / F_{2^k})
//
// Receiver holds leaves[x] for x != alpha (leaf at alpha is unused);
// outputs:
//   w_planes : k * ceil(ell/128) blocks
//              w[j] = sum over x != alpha of r_x[j] * (alpha XOR x)
//
// Correlation (over F_{2^k}, per row j): w[j] = u[j] * Delta_i + v[j].
//
// Chunked variants take a counter offset b0 and chunk length bs (both
// in bpr-blocks) so each leaf's keystream can be produced in pieces —
// chunk c reads PRG output blocks [b0, b0+bs). The chunked output is
// bit-identical to the one-shot path because emp::PRG is plain CTR
// (output[j] = AES_{seed^session}(makeBlock(0, j))), so re-keying per
// chunk and starting the counter at b0 reproduces the same slice of
// keystream that PRG.random_block(..., b0+bs) would have produced if
// read at offset b0. We pay one AES_set_encrypt_key per leaf per
// chunk (~30 cycles) instead of persisting Q PRG objects across
// chunks (~800 KB of resident state at k=8); amortized over bs * 10
// cycles of encrypt work the overhead is ~3/bs (≈9% at bs=32).

// Per-k chunk size (in bpr-blocks). Larger k has heavier per-leaf
// inner-loop work — bs * (k/2 + 2) cycles roughly — so the per-leaf
// AES re-key cost (~30 cycles) amortizes at smaller bs for large k
// and needs a larger window for small k. Cross-platform A/B (Apple
// M / Sapphire Rapids+ / Zen 5c) puts the joint-peak around:
//   k=2 → 64  (re-key cost is already 5% at bs=64; bigger just adds
//              cache pressure on small-L1 parts)
//   k=4 → 128 (Intel still climbs to 256 here, but Zen 5c peaks at 128)
//   k=8 → 256 (Intel and Zen 5c send/recv all maximize around 256;
//              Q=256 means each leaf's compute is small enough that
//              amortization keeps winning)
template <int k>
constexpr int chunk_blocks_for() {
    if constexpr (k <= 2)      return 128;
    else if constexpr (k <= 4) return 1024;
    else                       return 1024;
}

// kMaxChunkBlocks bounds the stack-resident locals (r_x in the
// chunked sfvole helpers; u_canonical / u_temp in rcot_recv_next).
// Plane scratch is on the heap (member BlockVec on SoftSpokenOT) and
// is sized via kChunkBlocks at the class.
constexpr int kMaxChunkBlocks = 1024;

// Sender-side compute restricted to a chunk [b0, b0+bs) of the bpr axis.
// Re-expands the AES key from each leaf seed instead of persisting Q
// PRG objects across chunks: per-leaf state during this call is just
// 16 B of seed (already in `leaves`) + 176 B of stack-local AES_KEY.
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
        // Per-call re-key — matches PRG(seed=leaves[x], id=session) ctor:
        // PRG::reseed does v = seed XOR makeBlock(0, id);
        // AES_set_encrypt_key(v, &aes); counter = 0.
        const block seed = leaves[x] ^ session_xor;
        AES_set_encrypt_key(seed, &aes_local);

        // CTR keystream: r_x[b] = AES_seed(makeBlock(0, b0 + b)). Equal
        // to the bytes PRG.random_block(buf, b0+bs) would put in
        // buf[b0..b0+bs).
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

// Receiver-side compute restricted to a chunk [b0, b0+bs) of the bpr
// axis. Same re-key-per-leaf strategy as the sender; skips x = alpha.
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

        // For each set bit b of (alpha XOR x), plane b ^= r_x.
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

}} // namespace emp::softspoken
#endif
