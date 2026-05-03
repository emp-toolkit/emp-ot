#ifndef EMP_SOFTSPOKEN_CONV_H__
#define EMP_SOFTSPOKEN_CONV_H__
#include <emp-tool/emp-tool.h>
#include <cstdint>
#include <cstring>

namespace emp { namespace softspoken {

// Conv: F_2-linear bit packing between F_{2^k}^n and F_{2^128}.
// Bit (i*k + b) of the 128-bit output = bit b of the i-th F_{2^k} input.
// We pick n = ceil(128/k); for k in {1,2,4,8,16} every bit is used,
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

}} // namespace emp::softspoken
#endif
