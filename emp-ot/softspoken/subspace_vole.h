#ifndef EMP_SOFTSPOKEN_SUBSPACE_VOLE_H__
#define EMP_SOFTSPOKEN_SUBSPACE_VOLE_H__
#include <emp-tool/emp-tool.h>
#include "emp-ot/softspoken/conv.h"
#include <cstdint>
#include <cstring>

namespace emp { namespace softspoken {

// Apply d_i (length-ell bit vector, in `bpr` blocks) to receiver's
// w_i bit-planes: for each bit b of Delta_i where it is set,
// w_planes[b] ^= d_i. This is the cot.tex sub-space VOLE
// derandomization step on the receiver side.
template <int k>
inline void apply_derand_to_w_planes(int alpha_i,
                                     const block* d_i,
                                     int64_t bpr,
                                     block* w_planes) {
    for (int b = 0; b < k; ++b) {
        if ((alpha_i >> b) & 1) {
            block* dst = w_planes + b * bpr;
            for (int64_t j = 0; j < bpr; ++j)
                dst[j] = dst[j] ^ d_i[j];
        }
    }
}

// Pack one row j across all n sub-VOLEs (scalar fallback used when
// n*k != 128). plane_buf[i*k + b] points at the b-th bit-plane of
// sub-VOLE i (a `bpr`-block vector). For row j, byte i of the
// unpacked F_{2^k}^n element is sum_b ((bit j of plane[i*k+b]) << b),
// then conv::pack<k> folds those n bytes into one block.
template <int k>
inline block pack_row(const block* const* planes, int n, int64_t j) {
    uint8_t bytes[256];  // n <= 128 always; 256 is safe upper bound.
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
// each of the 128 bit-planes (this is the only cache-strided step:
// 128 reads at offset `chunk` in 128 separate plane arrays) and run a
// 128x128 sse_trans, which is exactly the inverse of the inner-loop
// structure needed to assemble bit (i*k+b) of out[j] from bit j of
// plane (i*k+b). Cuts pack work by ~128x vs row-by-row pack_row.
//
// Falls back to row-by-row pack_row when n*k != 128.
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
    (void)bpr;  // unused in fast path (input layout is implicit)
}

}} // namespace emp::softspoken
#endif
