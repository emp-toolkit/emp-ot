#ifndef EMP_SOFTSPOKEN_SMALL_VOLE_H__
#define EMP_SOFTSPOKEN_SMALL_VOLE_H__
#include <emp-tool/emp-tool.h>
#include <cstdint>
#include <cstring>
#include <vector>

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

template <int k>
inline void sfvole_sender_compute(const block leaves[1 << k],
                                  uint64_t session,
                                  int64_t ell,
                                  block* u_bits,
                                  block* v_planes) {
    constexpr int Q = 1 << k;
    const int64_t bpr = (ell + 127) / 128;

    std::memset(u_bits,   0, sizeof(block) * bpr);
    std::memset(v_planes, 0, sizeof(block) * k * bpr);

    std::vector<block> r_x(bpr);
    for (int x = 0; x < Q; ++x) {
        // G''(leaves[x]) — keystream is a function of (seed, session id).
        PRG prg(&leaves[x], static_cast<int>(session));
        prg.random_block(r_x.data(), static_cast<int>(bpr));

        // u ^= r_x
        for (int64_t b = 0; b < bpr; ++b)
            u_bits[b] = u_bits[b] ^ r_x[b];

        // For each bit b in x, plane b of v gets r_x XORed in.
        // (v[j] = sum_x r_x[j] * x = sum_b 2^b * sum_{x: bit_b(x)=1} r_x[j])
        for (int b = 0; b < k; ++b) {
            if ((x >> b) & 1) {
                block* dst = v_planes + b * bpr;
                for (int64_t i = 0; i < bpr; ++i)
                    dst[i] = dst[i] ^ r_x[i];
            }
        }
    }
}

template <int k>
inline void sfvole_receiver_compute(int alpha,
                                    const block leaves[1 << k],
                                    uint64_t session,
                                    int64_t ell,
                                    block* w_planes) {
    constexpr int Q = 1 << k;
    const int64_t bpr = (ell + 127) / 128;

    std::memset(w_planes, 0, sizeof(block) * k * bpr);

    std::vector<block> r_x(bpr);
    for (int x = 0; x < Q; ++x) {
        if (x == alpha) continue;

        PRG prg(&leaves[x], static_cast<int>(session));
        prg.random_block(r_x.data(), static_cast<int>(bpr));

        // For each bit b of (alpha XOR x), plane b of w gets r_x XORed in.
        const int coeff = alpha ^ x;
        for (int b = 0; b < k; ++b) {
            if ((coeff >> b) & 1) {
                block* dst = w_planes + b * bpr;
                for (int64_t i = 0; i < bpr; ++i)
                    dst[i] = dst[i] ^ r_x[i];
            }
        }
    }
}

}} // namespace emp::softspoken
#endif
