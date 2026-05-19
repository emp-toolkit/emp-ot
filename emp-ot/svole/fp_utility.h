#ifndef EMP_OT_SVOLE_FP_UTILITY_H__
#define EMP_OT_SVOLE_FP_UTILITY_H__

#include <emp-tool/emp-tool.h>

// Mersenne 2^61 - 1 arithmetic helpers used by FpVOLE / FpMpsvole /
// LpnFp. mod / add_mod / mult_mod come in scalar (uint64_t) and SIMD
// (block / __m512i) flavors. extract_fp reduces a __uint128_t's low
// 64 bits in place. uni_hash_coeff_gen / vector_inn_prdt_sum_red are
// the F_p variants of the corresponding emp-tool helpers (the
// emp-tool versions are GF(2^128)).

namespace emp {

#define MERSENNE_PRIME_EXP 61
#define FIELD_TYPE uint64_t
const static __uint128_t p = 2305843009213693951;
const static int r = 1;
const static __uint128_t pr = 2305843009213693951;
inline constexpr block prs =
    makeBlock(2305843009213693951ULL, 2305843009213693951ULL);
const static uint64_t PR = 2305843009213693951;
inline constexpr __m128i PRs = makeBlock(PR, PR);

#if defined(__x86_64__) && defined(__BMI2__)
inline uint64_t mul64(uint64_t a, uint64_t b, uint64_t *c) {
  return _mulx_u64((unsigned long long)a, (unsigned long long)b,
                   (unsigned long long *)c);
}
#else
inline uint64_t mul64(uint64_t a, uint64_t b, uint64_t *c) {
  __uint128_t aa = a;
  __uint128_t bb = b;
  auto cc = aa * bb;
  *c = cc >> 64;
  return (uint64_t)cc;
}
#endif

inline uint64_t mod_pre(__uint128_t x) {
  return (x & PR) + (x >> MERSENNE_PRIME_EXP);
}

inline uint64_t mod(uint64_t x) {
  uint64_t i = (x & PR) + (x >> MERSENNE_PRIME_EXP);
  return (i >= p) ? i - p : i;
}

template <typename T> T mod(T k, T pv) {
  T i = (k & pv) + (k >> MERSENNE_PRIME_EXP);
  return (i >= pv) ? i - pv : i;
}

inline block vec_partial_mod(block i) {
  return _mm_sub_epi64(i, _mm_andnot_si128(_mm_cmpgt_epi64(prs, i), prs));
}

#ifdef __AVX512F__
const static __m512i PR8 = _mm512_set_epi64(PR, PR, PR, PR, PR, PR, PR, PR);
inline __m512i vec_partial_mod_bch4(__m512i i) {
  __m512i tmp;
  block *pt = (block *)(&tmp);
  block *pti = (block *)(&i);
  pt[0] = _mm_andnot_si128(_mm_cmpgt_epi64(prs, pti[0]), prs);
  pt[1] = _mm_andnot_si128(_mm_cmpgt_epi64(prs, pti[1]), prs);
  pt[2] = _mm_andnot_si128(_mm_cmpgt_epi64(prs, pti[2]), prs);
  pt[3] = _mm_andnot_si128(_mm_cmpgt_epi64(prs, pti[3]), prs);
  return _mm512_sub_epi64(i, tmp);
}
#endif

inline block vec_mod(block i) {
  i = _mm_add_epi64((i & prs), _mm_srli_epi64(i, MERSENNE_PRIME_EXP));
  return vec_partial_mod(i);
}

inline block mult_mod(block a, uint64_t b) {
  uint64_t H = _mm_extract_epi64(a, 1);
  uint64_t L = _mm_extract_epi64(a, 0);
  block bs[2];
  uint64_t *is = (uint64_t *)(bs);
  is[1] = mul64(H, b, (uint64_t *)(is + 3));
  is[0] = mul64(L, b, (uint64_t *)(is + 2));
  block t1 = bs[0] & prs;
  block t2 = _mm_srli_epi64(bs[0], MERSENNE_PRIME_EXP) ^
             _mm_slli_epi64(bs[1], 64 - MERSENNE_PRIME_EXP);
  block res = _mm_add_epi64(t1, t2);
  return vec_partial_mod(res);
}

inline uint64_t mult_mod(uint64_t a, uint64_t b) {
  uint64_t c = 0;
  uint64_t e = mul64(a, b, (uint64_t *)&c);
  uint64_t res =
      (e & PR) + ((e >> MERSENNE_PRIME_EXP) ^ (c << (64 - MERSENNE_PRIME_EXP)));
  return (res >= PR) ? (res - PR) : res;
}

inline block add_mod(block a, block b) {
  block res = _mm_add_epi64(a, b);
  return vec_partial_mod(res);
}

inline block add_mod(block a, uint64_t b) {
  block res = _mm_add_epi64(a, _mm_set_epi64((__m64)b, (__m64)b));
  return vec_partial_mod(res);
}

inline uint64_t add_mod(uint64_t a, uint64_t b) {
  uint64_t res = a + b;
  return (res >= PR) ? (res - PR) : res;
}

inline void extract_fp(__uint128_t &x) {
  x = mod(_mm_extract_epi64((block)x, 0));
}

template <typename T> void uni_hash_coeff_gen(T *coeff, T seed, int64_t sz) {
  coeff[0] = seed;
  for (int64_t i = 1; i < sz; ++i)
    coeff[i] = mult_mod(coeff[i - 1], seed);
}

template <typename T>
T vector_inn_prdt_sum_red(const T *a, const T *b, int64_t sz) {
  T res = (T)0;
  for (int64_t i = 0; i < sz; ++i)
    res = add_mod(res, mult_mod(a[i], b[i]));
  return res;
}

template <typename S, typename T>
T vector_inn_prdt_sum_red(const S *a, const T *b, int64_t sz) {
  T res = (T)0;
  for (int64_t i = 0; i < sz; ++i)
    res = add_mod(res, mult_mod((T)a[i], b[i]));
  return res;
}

} // namespace emp

#endif
