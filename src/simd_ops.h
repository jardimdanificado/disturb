/*
 * simd_ops.h — Portable SIMD kernels for Disturb vectorized operations.
 *
 * Header-only. No runtime dependencies. Controlled by DISTURB_ENABLE_SIMD.
 * When SIMD is not available, all functions compile to plain scalar loops
 * that the compiler can auto-vectorize with -O3.
 *
 * Supported backends:
 *   - AVX2    (x86-64, 4×i64 / 4×f64 per instruction)
 *   - SSE4.2  (x86-64, 2×i64 / 2×f64)
 *   - NEON    (AArch64, 2×i64 / 2×f64)
 *   - Scalar  (any C99 target — microcontrollers, etc.)
 *
 * Int/Float width adapts to the platform via urb.h:
 *   64-bit: Int = int64_t, Float = double
 *   32-bit: Int = int32_t, Float = float
 */

#ifndef DISTURB_SIMD_OPS_H
#define DISTURB_SIMD_OPS_H

#include <stddef.h>
#include <stdint.h>
#include <math.h>

/* ---- Backend detection ------------------------------------------------- */

#if defined(DISTURB_ENABLE_SIMD)
#  if defined(__AVX2__)
#    include <immintrin.h>
#    define DISTURB_SIMD_AVX2 1
#  elif defined(__SSE4_2__) || defined(__SSE2__)
#    if defined(__SSE4_2__)
#      include <nmmintrin.h>
#    else
#      include <emmintrin.h>
#    endif
#    define DISTURB_SIMD_SSE 1
#  elif defined(__ARM_NEON) || defined(__aarch64__)
#    include <arm_neon.h>
#    define DISTURB_SIMD_NEON 1
#  endif
#endif

/* No SIMD? Everything still compiles — scalar fallback. */

/* Threshold: below this, SIMD dispatch overhead > gain */
#ifndef DISTURB_SIMD_THRESHOLD
#  define DISTURB_SIMD_THRESHOLD 8
#endif

/* ---- Helpers for broadcast handling ------------------------------------ */

/* All kernels follow the pattern:
 *   void simd_TY_OP(const TY *a, const TY *b, TY *out, size_t n,
 *                   int broadcast_a, int broadcast_b);
 *
 * broadcast_a == 1 means a[0] is the scalar to broadcast across all lanes.
 * broadcast_b == 1 means b[0] is the scalar to broadcast across all lanes.
 */

/* ========================================================================
 * INT kernels — Int width adapts via INTPTR_MAX
 * On 64-bit: Int = int64_t, sizeof(Int) = 8
 * On 32-bit: Int = int32_t, sizeof(Int) = 4
 * ======================================================================== */

/* We need intptr_t available */
#include <stdint.h>

/* ---- i64 ADD ----------------------------------------------------------- */

#if INTPTR_MAX == INT64_MAX

static inline void
simd_int_add(const int64_t *a, const int64_t *b, int64_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi64x(a[0]);
    if (bb) vb = _mm256_set1_epi64x(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_add_epi64(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi64x(a[0]);
    if (bb) vb = _mm_set1_epi64x(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_add_epi64(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t va, vb;
    if (ba) va = vdupq_n_s64(a[0]);
    if (bb) vb = vdupq_n_s64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_s64(a + i);
        if (!bb) vb = vld1q_s64(b + i);
        vst1q_s64(out + i, vaddq_s64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) + (bb ? b[0] : b[i]);
}

static inline void
simd_int_sub(const int64_t *a, const int64_t *b, int64_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi64x(a[0]);
    if (bb) vb = _mm256_set1_epi64x(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_sub_epi64(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi64x(a[0]);
    if (bb) vb = _mm_set1_epi64x(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_sub_epi64(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t va, vb;
    if (ba) va = vdupq_n_s64(a[0]);
    if (bb) vb = vdupq_n_s64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_s64(a + i);
        if (!bb) vb = vld1q_s64(b + i);
        vst1q_s64(out + i, vsubq_s64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) - (bb ? b[0] : b[i]);
}

static inline void
simd_int_mul(const int64_t *a, const int64_t *b, int64_t *out,
             size_t n, int ba, int bb)
{
    /* No native 64-bit multiply in AVX2/SSE — scalar loop.
     * The compiler will auto-vectorize this with -O3 if it can. */
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) * (bb ? b[0] : b[i]);
}

static inline void
simd_int_and(const int64_t *a, const int64_t *b, int64_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi64x(a[0]);
    if (bb) vb = _mm256_set1_epi64x(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_and_si256(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi64x(a[0]);
    if (bb) vb = _mm_set1_epi64x(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_and_si128(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t va, vb;
    if (ba) va = vdupq_n_s64(a[0]);
    if (bb) vb = vdupq_n_s64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_s64(a + i);
        if (!bb) vb = vld1q_s64(b + i);
        vst1q_s64(out + i, vandq_s64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) & (bb ? b[0] : b[i]);
}

static inline void
simd_int_or(const int64_t *a, const int64_t *b, int64_t *out,
            size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi64x(a[0]);
    if (bb) vb = _mm256_set1_epi64x(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_or_si256(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi64x(a[0]);
    if (bb) vb = _mm_set1_epi64x(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_or_si128(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t va, vb;
    if (ba) va = vdupq_n_s64(a[0]);
    if (bb) vb = vdupq_n_s64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_s64(a + i);
        if (!bb) vb = vld1q_s64(b + i);
        vst1q_s64(out + i, vorrq_s64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) | (bb ? b[0] : b[i]);
}

static inline void
simd_int_xor(const int64_t *a, const int64_t *b, int64_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi64x(a[0]);
    if (bb) vb = _mm256_set1_epi64x(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_xor_si256(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi64x(a[0]);
    if (bb) vb = _mm_set1_epi64x(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_xor_si128(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t va, vb;
    if (ba) va = vdupq_n_s64(a[0]);
    if (bb) vb = vdupq_n_s64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_s64(a + i);
        if (!bb) vb = vld1q_s64(b + i);
        vst1q_s64(out + i, veorq_s64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) ^ (bb ? b[0] : b[i]);
}

static inline void
simd_int_neg(const int64_t *a, int64_t *out, size_t n)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i zero = _mm256_setzero_si256();
    for (; i + 4 <= n; i += 4) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_sub_epi64(zero, va));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i zero = _mm_setzero_si128();
    for (; i + 2 <= n; i += 2) {
        __m128i va = _mm_loadu_si128((const __m128i *)(a + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_sub_epi64(zero, va));
    }
#elif defined(DISTURB_SIMD_NEON)
    for (; i + 2 <= n; i += 2) {
        int64x2_t va = vld1q_s64(a + i);
        vst1q_s64(out + i, vnegq_s64(va));
    }
#endif
    for (; i < n; i++) out[i] = -a[i];
}

static inline void
simd_int_not(const int64_t *a, int64_t *out, size_t n)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i ones = _mm256_set1_epi64x((int64_t)-1);
    for (; i + 4 <= n; i += 4) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_xor_si256(va, ones));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i ones = _mm_set1_epi64x((int64_t)-1);
    for (; i + 2 <= n; i += 2) {
        __m128i va = _mm_loadu_si128((const __m128i *)(a + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_xor_si128(va, ones));
    }
#elif defined(DISTURB_SIMD_NEON)
    for (; i + 2 <= n; i += 2) {
        int64x2_t va = vld1q_s64(a + i);
        vst1q_s64(out + i, vmvnq_s64(va));
    }
#endif
    for (; i < n; i++) out[i] = ~a[i];
}

#else /* 32-bit platform: Int = int32_t */

static inline void
simd_int_add(const int32_t *a, const int32_t *b, int32_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi32(a[0]);
    if (bb) vb = _mm256_set1_epi32(b[0]);
    for (; i + 8 <= n; i += 8) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_add_epi32(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi32(a[0]);
    if (bb) vb = _mm_set1_epi32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_add_epi32(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int32x4_t va, vb;
    if (ba) va = vdupq_n_s32(a[0]);
    if (bb) vb = vdupq_n_s32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = vld1q_s32(a + i);
        if (!bb) vb = vld1q_s32(b + i);
        vst1q_s32(out + i, vaddq_s32(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) + (bb ? b[0] : b[i]);
}

static inline void
simd_int_sub(const int32_t *a, const int32_t *b, int32_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi32(a[0]);
    if (bb) vb = _mm256_set1_epi32(b[0]);
    for (; i + 8 <= n; i += 8) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_sub_epi32(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi32(a[0]);
    if (bb) vb = _mm_set1_epi32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_sub_epi32(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int32x4_t va, vb;
    if (ba) va = vdupq_n_s32(a[0]);
    if (bb) vb = vdupq_n_s32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = vld1q_s32(a + i);
        if (!bb) vb = vld1q_s32(b + i);
        vst1q_s32(out + i, vsubq_s32(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) - (bb ? b[0] : b[i]);
}

static inline void
simd_int_mul(const int32_t *a, const int32_t *b, int32_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va, vb;
    if (ba) va = _mm256_set1_epi32(a[0]);
    if (bb) vb = _mm256_set1_epi32(b[0]);
    for (; i + 8 <= n; i += 8) {
        if (!ba) va = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb = _mm256_loadu_si256((const __m256i *)(b + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_mullo_epi32(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va, vb;
    if (ba) va = _mm_set1_epi32(a[0]);
    if (bb) vb = _mm_set1_epi32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb = _mm_loadu_si128((const __m128i *)(b + i));
        _mm_storeu_si128((__m128i *)(out + i), _mm_mullo_epi32(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    int32x4_t va, vb;
    if (ba) va = vdupq_n_s32(a[0]);
    if (bb) vb = vdupq_n_s32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = vld1q_s32(a + i);
        if (!bb) vb = vld1q_s32(b + i);
        vst1q_s32(out + i, vmulq_s32(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) * (bb ? b[0] : b[i]);
}

static inline void
simd_int_and(const int32_t *a, const int32_t *b, int32_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) & (bb ? b[0] : b[i]);
}

static inline void
simd_int_or(const int32_t *a, const int32_t *b, int32_t *out,
            size_t n, int ba, int bb)
{
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) | (bb ? b[0] : b[i]);
}

static inline void
simd_int_xor(const int32_t *a, const int32_t *b, int32_t *out,
             size_t n, int ba, int bb)
{
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) ^ (bb ? b[0] : b[i]);
}

static inline void
simd_int_neg(const int32_t *a, int32_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = -a[i];
}

static inline void
simd_int_not(const int32_t *a, int32_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = ~a[i];
}

#endif /* INTPTR_MAX check */


/* ========================================================================
 * FLOAT kernels — Float = double on 64-bit, float on 32-bit
 * ======================================================================== */

#if INTPTR_MAX == INT64_MAX

/* --- f64 kernels (64-bit platform) --- */

static inline void
simd_float_add(const double *a, const double *b, double *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d va, vb;
    if (ba) va = _mm256_set1_pd(a[0]);
    if (bb) vb = _mm256_set1_pd(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_pd(a + i);
        if (!bb) vb = _mm256_loadu_pd(b + i);
        _mm256_storeu_pd(out + i, _mm256_add_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128d va, vb;
    if (ba) va = _mm_set1_pd(a[0]);
    if (bb) vb = _mm_set1_pd(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_pd(a + i);
        if (!bb) vb = _mm_loadu_pd(b + i);
        _mm_storeu_pd(out + i, _mm_add_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t va, vb;
    if (ba) va = vdupq_n_f64(a[0]);
    if (bb) vb = vdupq_n_f64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_f64(a + i);
        if (!bb) vb = vld1q_f64(b + i);
        vst1q_f64(out + i, vaddq_f64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) + (bb ? b[0] : b[i]);
}

static inline void
simd_float_sub(const double *a, const double *b, double *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d va, vb;
    if (ba) va = _mm256_set1_pd(a[0]);
    if (bb) vb = _mm256_set1_pd(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_pd(a + i);
        if (!bb) vb = _mm256_loadu_pd(b + i);
        _mm256_storeu_pd(out + i, _mm256_sub_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128d va, vb;
    if (ba) va = _mm_set1_pd(a[0]);
    if (bb) vb = _mm_set1_pd(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_pd(a + i);
        if (!bb) vb = _mm_loadu_pd(b + i);
        _mm_storeu_pd(out + i, _mm_sub_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t va, vb;
    if (ba) va = vdupq_n_f64(a[0]);
    if (bb) vb = vdupq_n_f64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_f64(a + i);
        if (!bb) vb = vld1q_f64(b + i);
        vst1q_f64(out + i, vsubq_f64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) - (bb ? b[0] : b[i]);
}

static inline void
simd_float_mul(const double *a, const double *b, double *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d va, vb;
    if (ba) va = _mm256_set1_pd(a[0]);
    if (bb) vb = _mm256_set1_pd(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_pd(a + i);
        if (!bb) vb = _mm256_loadu_pd(b + i);
        _mm256_storeu_pd(out + i, _mm256_mul_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128d va, vb;
    if (ba) va = _mm_set1_pd(a[0]);
    if (bb) vb = _mm_set1_pd(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_pd(a + i);
        if (!bb) vb = _mm_loadu_pd(b + i);
        _mm_storeu_pd(out + i, _mm_mul_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t va, vb;
    if (ba) va = vdupq_n_f64(a[0]);
    if (bb) vb = vdupq_n_f64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_f64(a + i);
        if (!bb) vb = vld1q_f64(b + i);
        vst1q_f64(out + i, vmulq_f64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) * (bb ? b[0] : b[i]);
}

static inline void
simd_float_div(const double *a, const double *b, double *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d va, vb;
    if (ba) va = _mm256_set1_pd(a[0]);
    if (bb) vb = _mm256_set1_pd(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_pd(a + i);
        if (!bb) vb = _mm256_loadu_pd(b + i);
        _mm256_storeu_pd(out + i, _mm256_div_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128d va, vb;
    if (ba) va = _mm_set1_pd(a[0]);
    if (bb) vb = _mm_set1_pd(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = _mm_loadu_pd(a + i);
        if (!bb) vb = _mm_loadu_pd(b + i);
        _mm_storeu_pd(out + i, _mm_div_pd(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t va, vb;
    if (ba) va = vdupq_n_f64(a[0]);
    if (bb) vb = vdupq_n_f64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_f64(a + i);
        if (!bb) vb = vld1q_f64(b + i);
        vst1q_f64(out + i, vdivq_f64(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) / (bb ? b[0] : b[i]);
}

static inline void
simd_float_neg(const double *a, double *out, size_t n)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d neg = _mm256_set1_pd(-0.0);
    for (; i + 4 <= n; i += 4) {
        __m256d va = _mm256_loadu_pd(a + i);
        _mm256_storeu_pd(out + i, _mm256_xor_pd(va, neg));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128d neg = _mm_set1_pd(-0.0);
    for (; i + 2 <= n; i += 2) {
        __m128d va = _mm_loadu_pd(a + i);
        _mm_storeu_pd(out + i, _mm_xor_pd(va, neg));
    }
#elif defined(DISTURB_SIMD_NEON)
    for (; i + 2 <= n; i += 2) {
        float64x2_t va = vld1q_f64(a + i);
        vst1q_f64(out + i, vnegq_f64(va));
    }
#endif
    for (; i < n; i++) out[i] = -a[i];
}

/* Scalar mod — no SIMD for fmod */
static inline void
simd_float_mod(const double *a, const double *b, double *out,
               size_t n, int ba, int bb)
{
    for (size_t i = 0; i < n; i++)
        out[i] = fmod(ba ? a[0] : a[i], bb ? b[0] : b[i]);
}

#else /* 32-bit: Float = float */

static inline void
simd_float_add(const float *a, const float *b, float *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256 va, vb;
    if (ba) va = _mm256_set1_ps(a[0]);
    if (bb) vb = _mm256_set1_ps(b[0]);
    for (; i + 8 <= n; i += 8) {
        if (!ba) va = _mm256_loadu_ps(a + i);
        if (!bb) vb = _mm256_loadu_ps(b + i);
        _mm256_storeu_ps(out + i, _mm256_add_ps(va, vb));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128 va, vb;
    if (ba) va = _mm_set1_ps(a[0]);
    if (bb) vb = _mm_set1_ps(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm_loadu_ps(a + i);
        if (!bb) vb = _mm_loadu_ps(b + i);
        _mm_storeu_ps(out + i, _mm_add_ps(va, vb));
    }
#elif defined(DISTURB_SIMD_NEON)
    float32x4_t va, vb;
    if (ba) va = vdupq_n_f32(a[0]);
    if (bb) vb = vdupq_n_f32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = vld1q_f32(a + i);
        if (!bb) vb = vld1q_f32(b + i);
        vst1q_f32(out + i, vaddq_f32(va, vb));
    }
#endif
    for (; i < n; i++) out[i] = (ba ? a[0] : a[i]) + (bb ? b[0] : b[i]);
}

static inline void
simd_float_sub(const float *a, const float *b, float *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) - (bb ? b[0] : b[i]);
}

static inline void
simd_float_mul(const float *a, const float *b, float *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) * (bb ? b[0] : b[i]);
}

static inline void
simd_float_div(const float *a, const float *b, float *out,
               size_t n, int ba, int bb)
{
    size_t i = 0;
    (void)i;
    for (i = 0; i < n; i++) out[i] = (ba ? a[0] : a[i]) / (bb ? b[0] : b[i]);
}

static inline void
simd_float_neg(const float *a, float *out, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = -a[i];
}

static inline void
simd_float_mod(const float *a, const float *b, float *out,
               size_t n, int ba, int bb)
{
    for (size_t i = 0; i < n; i++)
        out[i] = fmodf(ba ? a[0] : a[i], bb ? b[0] : b[i]);
}

#endif /* Float width check */

/* ========================================================================
 * COMPARISON kernels — output is Int (0 or 1 per element)
 * op: 0=eq  1=neq  2=lt  3=lte  4=gt  5=gte
 * ======================================================================== */

#define SIMD_CMP_EQ  0
#define SIMD_CMP_NEQ 1
#define SIMD_CMP_LT  2
#define SIMD_CMP_LTE 3
#define SIMD_CMP_GT  4
#define SIMD_CMP_GTE 5

#if INTPTR_MAX == INT64_MAX

/* --- i64 comparison → i64[0|1] ---------------------------------------- */
static inline void
simd_int_cmp(const int64_t *a, const int64_t *b, int64_t *out,
             size_t n, int ba, int bb, int cmp_op)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    /* AVX2 has vpcmpeqq and vpcmpgtq only — derive others from those */
    __m256i va_v, vb_v;
    __m256i one = _mm256_set1_epi64x(1);
    __m256i zero = _mm256_setzero_si256();
    if (ba) va_v = _mm256_set1_epi64x(a[0]);
    if (bb) vb_v = _mm256_set1_epi64x(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va_v = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb_v = _mm256_loadu_si256((const __m256i *)(b + i));
        __m256i mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = _mm256_cmpeq_epi64(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = _mm256_cmpeq_epi64(va_v, vb_v);
                           mask = _mm256_xor_si256(mask, _mm256_set1_epi64x(-1)); break;
        case SIMD_CMP_GT:  mask = _mm256_cmpgt_epi64(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = _mm256_cmpgt_epi64(vb_v, va_v); break;
        case SIMD_CMP_GTE: mask = _mm256_or_si256(_mm256_cmpgt_epi64(va_v, vb_v),
                                                   _mm256_cmpeq_epi64(va_v, vb_v)); break;
        case SIMD_CMP_LTE: mask = _mm256_or_si256(_mm256_cmpgt_epi64(vb_v, va_v),
                                                   _mm256_cmpeq_epi64(va_v, vb_v)); break;
        default: mask = zero; break;
        }
        /* mask is all-ones per lane; convert to 1/0 */
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_and_si256(mask, one));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va_v, vb_v;
    __m128i one = _mm_set1_epi64x(1);
    __m128i zero_v = _mm_setzero_si128();
    if (ba) va_v = _mm_set1_epi64x(a[0]);
    if (bb) vb_v = _mm_set1_epi64x(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va_v = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb_v = _mm_loadu_si128((const __m128i *)(b + i));
        __m128i mask;
        (void)zero_v;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = _mm_cmpeq_epi64(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = _mm_cmpeq_epi64(va_v, vb_v);
                           mask = _mm_xor_si128(mask, _mm_set1_epi64x(-1)); break;
        case SIMD_CMP_GT:  mask = _mm_cmpgt_epi64(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = _mm_cmpgt_epi64(vb_v, va_v); break;
        case SIMD_CMP_GTE: mask = _mm_or_si128(_mm_cmpgt_epi64(va_v, vb_v),
                                                _mm_cmpeq_epi64(va_v, vb_v)); break;
        case SIMD_CMP_LTE: mask = _mm_or_si128(_mm_cmpgt_epi64(vb_v, va_v),
                                                _mm_cmpeq_epi64(va_v, vb_v)); break;
        default: mask = _mm_setzero_si128(); break;
        }
        _mm_storeu_si128((__m128i *)(out + i), _mm_and_si128(mask, one));
    }
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t va_v, vb_v;
    int64x2_t one = vdupq_n_s64(1);
    if (ba) va_v = vdupq_n_s64(a[0]);
    if (bb) vb_v = vdupq_n_s64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va_v = vld1q_s64(a + i);
        if (!bb) vb_v = vld1q_s64(b + i);
        uint64x2_t mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = vceqq_s64(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = vmvnq_u64(vceqq_s64(va_v, vb_v)); break;
        case SIMD_CMP_GT:  mask = vcgtq_s64(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = vcltq_s64(va_v, vb_v); break;
        case SIMD_CMP_GTE: mask = vcgeq_s64(va_v, vb_v); break;
        case SIMD_CMP_LTE: mask = vcleq_s64(va_v, vb_v); break;
        default: mask = vdupq_n_u64(0); break;
        }
        vst1q_s64(out + i, vandq_s64(vreinterpretq_s64_u64(mask), one));
    }
#endif
    for (; i < n; i++) {
        int64_t lv = ba ? a[0] : a[i];
        int64_t rv = bb ? b[0] : b[i];
        int r = 0;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  r = (lv == rv); break;
        case SIMD_CMP_NEQ: r = (lv != rv); break;
        case SIMD_CMP_LT:  r = (lv <  rv); break;
        case SIMD_CMP_LTE: r = (lv <= rv); break;
        case SIMD_CMP_GT:  r = (lv >  rv); break;
        case SIMD_CMP_GTE: r = (lv >= rv); break;
        default: break;
        }
        out[i] = r;
    }
}

/* --- f64 comparison → i64[0|1] ---------------------------------------- */
static inline void
simd_float_cmp(const double *a, const double *b, int64_t *out,
               size_t n, int ba, int bb, int cmp_op)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d va_v, vb_v;
    __m256i one = _mm256_set1_epi64x(1);
    if (ba) va_v = _mm256_set1_pd(a[0]);
    if (bb) vb_v = _mm256_set1_pd(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va_v = _mm256_loadu_pd(a + i);
        if (!bb) vb_v = _mm256_loadu_pd(b + i);
        __m256d mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = _mm256_cmp_pd(va_v, vb_v, _CMP_EQ_OQ); break;
        case SIMD_CMP_NEQ: mask = _mm256_cmp_pd(va_v, vb_v, _CMP_NEQ_UQ); break;
        case SIMD_CMP_LT:  mask = _mm256_cmp_pd(va_v, vb_v, _CMP_LT_OQ); break;
        case SIMD_CMP_LTE: mask = _mm256_cmp_pd(va_v, vb_v, _CMP_LE_OQ); break;
        case SIMD_CMP_GT:  mask = _mm256_cmp_pd(va_v, vb_v, _CMP_GT_OQ); break;
        case SIMD_CMP_GTE: mask = _mm256_cmp_pd(va_v, vb_v, _CMP_GE_OQ); break;
        default: mask = _mm256_setzero_pd(); break;
        }
        _mm256_storeu_si256((__m256i *)(out + i),
                            _mm256_and_si256(_mm256_castpd_si256(mask), one));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128d va_v, vb_v;
    __m128i one = _mm_set1_epi64x(1);
    if (ba) va_v = _mm_set1_pd(a[0]);
    if (bb) vb_v = _mm_set1_pd(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va_v = _mm_loadu_pd(a + i);
        if (!bb) vb_v = _mm_loadu_pd(b + i);
        __m128d mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = _mm_cmpeq_pd(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = _mm_cmpneq_pd(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = _mm_cmplt_pd(va_v, vb_v); break;
        case SIMD_CMP_LTE: mask = _mm_cmple_pd(va_v, vb_v); break;
        case SIMD_CMP_GT:  mask = _mm_cmpgt_pd(va_v, vb_v); break;
        case SIMD_CMP_GTE: mask = _mm_cmpge_pd(va_v, vb_v); break;
        default: mask = _mm_setzero_pd(); break;
        }
        _mm_storeu_si128((__m128i *)(out + i),
                         _mm_and_si128(_mm_castpd_si128(mask), one));
    }
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t va_v, vb_v;
    int64x2_t one = vdupq_n_s64(1);
    if (ba) va_v = vdupq_n_f64(a[0]);
    if (bb) vb_v = vdupq_n_f64(b[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va_v = vld1q_f64(a + i);
        if (!bb) vb_v = vld1q_f64(b + i);
        uint64x2_t mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = vceqq_f64(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = vmvnq_u64(vceqq_f64(va_v, vb_v)); break;
        case SIMD_CMP_LT:  mask = vcltq_f64(va_v, vb_v); break;
        case SIMD_CMP_LTE: mask = vcleq_f64(va_v, vb_v); break;
        case SIMD_CMP_GT:  mask = vcgtq_f64(va_v, vb_v); break;
        case SIMD_CMP_GTE: mask = vcgeq_f64(va_v, vb_v); break;
        default: mask = vdupq_n_u64(0); break;
        }
        vst1q_s64(out + i, vandq_s64(vreinterpretq_s64_u64(mask), one));
    }
#endif
    for (; i < n; i++) {
        double lv = ba ? a[0] : a[i];
        double rv = bb ? b[0] : b[i];
        int r = 0;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  r = (lv == rv); break;
        case SIMD_CMP_NEQ: r = (lv != rv); break;
        case SIMD_CMP_LT:  r = (lv <  rv); break;
        case SIMD_CMP_LTE: r = (lv <= rv); break;
        case SIMD_CMP_GT:  r = (lv >  rv); break;
        case SIMD_CMP_GTE: r = (lv >= rv); break;
        default: break;
        }
        out[i] = r;
    }
}

#else /* 32-bit platform comparisons */

static inline void
simd_int_cmp(const int32_t *a, const int32_t *b, int32_t *out,
             size_t n, int ba, int bb, int cmp_op)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i va_v, vb_v;
    __m256i one = _mm256_set1_epi32(1);
    if (ba) va_v = _mm256_set1_epi32(a[0]);
    if (bb) vb_v = _mm256_set1_epi32(b[0]);
    for (; i + 8 <= n; i += 8) {
        if (!ba) va_v = _mm256_loadu_si256((const __m256i *)(a + i));
        if (!bb) vb_v = _mm256_loadu_si256((const __m256i *)(b + i));
        __m256i mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = _mm256_cmpeq_epi32(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = _mm256_cmpeq_epi32(va_v, vb_v);
                           mask = _mm256_xor_si256(mask, _mm256_set1_epi32(-1)); break;
        case SIMD_CMP_GT:  mask = _mm256_cmpgt_epi32(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = _mm256_cmpgt_epi32(vb_v, va_v); break;
        case SIMD_CMP_GTE: mask = _mm256_or_si256(_mm256_cmpgt_epi32(va_v, vb_v),
                                                   _mm256_cmpeq_epi32(va_v, vb_v)); break;
        case SIMD_CMP_LTE: mask = _mm256_or_si256(_mm256_cmpgt_epi32(vb_v, va_v),
                                                   _mm256_cmpeq_epi32(va_v, vb_v)); break;
        default: mask = _mm256_setzero_si256(); break;
        }
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_and_si256(mask, one));
    }
#elif defined(DISTURB_SIMD_SSE)
    __m128i va_v, vb_v;
    __m128i one = _mm_set1_epi32(1);
    if (ba) va_v = _mm_set1_epi32(a[0]);
    if (bb) vb_v = _mm_set1_epi32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va_v = _mm_loadu_si128((const __m128i *)(a + i));
        if (!bb) vb_v = _mm_loadu_si128((const __m128i *)(b + i));
        __m128i mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = _mm_cmpeq_epi32(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = _mm_cmpeq_epi32(va_v, vb_v);
                           mask = _mm_xor_si128(mask, _mm_set1_epi32(-1)); break;
        case SIMD_CMP_GT:  mask = _mm_cmpgt_epi32(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = _mm_cmpgt_epi32(vb_v, va_v); break;
        case SIMD_CMP_GTE: mask = _mm_or_si128(_mm_cmpgt_epi32(va_v, vb_v),
                                                _mm_cmpeq_epi32(va_v, vb_v)); break;
        case SIMD_CMP_LTE: mask = _mm_or_si128(_mm_cmpgt_epi32(vb_v, va_v),
                                                _mm_cmpeq_epi32(va_v, vb_v)); break;
        default: mask = _mm_setzero_si128(); break;
        }
        _mm_storeu_si128((__m128i *)(out + i), _mm_and_si128(mask, one));
    }
#elif defined(DISTURB_SIMD_NEON)
    int32x4_t va_v, vb_v;
    int32x4_t one = vdupq_n_s32(1);
    if (ba) va_v = vdupq_n_s32(a[0]);
    if (bb) vb_v = vdupq_n_s32(b[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va_v = vld1q_s32(a + i);
        if (!bb) vb_v = vld1q_s32(b + i);
        uint32x4_t mask;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  mask = vceqq_s32(va_v, vb_v); break;
        case SIMD_CMP_NEQ: mask = vmvnq_u32(vceqq_s32(va_v, vb_v)); break;
        case SIMD_CMP_GT:  mask = vcgtq_s32(va_v, vb_v); break;
        case SIMD_CMP_LT:  mask = vcltq_s32(va_v, vb_v); break;
        case SIMD_CMP_GTE: mask = vcgeq_s32(va_v, vb_v); break;
        case SIMD_CMP_LTE: mask = vcleq_s32(va_v, vb_v); break;
        default: mask = vdupq_n_u32(0); break;
        }
        vst1q_s32(out + i, vandq_s32(vreinterpretq_s32_u32(mask), one));
    }
#endif
    for (; i < n; i++) {
        int32_t lv = ba ? a[0] : a[i];
        int32_t rv = bb ? b[0] : b[i];
        int r = 0;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  r = (lv == rv); break;
        case SIMD_CMP_NEQ: r = (lv != rv); break;
        case SIMD_CMP_LT:  r = (lv <  rv); break;
        case SIMD_CMP_LTE: r = (lv <= rv); break;
        case SIMD_CMP_GT:  r = (lv >  rv); break;
        case SIMD_CMP_GTE: r = (lv >= rv); break;
        default: break;
        }
        out[i] = r;
    }
}

static inline void
simd_float_cmp(const float *a, const float *b, int32_t *out,
               size_t n, int ba, int bb, int cmp_op)
{
    for (size_t i = 0; i < n; i++) {
        float lv = ba ? a[0] : a[i];
        float rv = bb ? b[0] : b[i];
        int r = 0;
        switch (cmp_op) {
        case SIMD_CMP_EQ:  r = (lv == rv); break;
        case SIMD_CMP_NEQ: r = (lv != rv); break;
        case SIMD_CMP_LT:  r = (lv <  rv); break;
        case SIMD_CMP_LTE: r = (lv <= rv); break;
        case SIMD_CMP_GT:  r = (lv >  rv); break;
        case SIMD_CMP_GTE: r = (lv >= rv); break;
        default: break;
        }
        out[i] = r;
    }
}

#endif /* comparison width check */


/* ========================================================================
 * REDUCTION & FMA kernels
 * ======================================================================== */

#if INTPTR_MAX == INT64_MAX

/* --- f64 horizontal sum ------------------------------------------------ */
static inline double simd_f64_sum(const double *a, size_t n)
{
    double sum = 0.0;
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256d acc = _mm256_setzero_pd();
    for (; i + 4 <= n; i += 4)
        acc = _mm256_add_pd(acc, _mm256_loadu_pd(a + i));
    /* horizontal reduce 4→1 */
    __m128d lo = _mm256_castpd256_pd128(acc);
    __m128d hi = _mm256_extractf128_pd(acc, 1);
    lo = _mm_add_pd(lo, hi);
    __m128d t = _mm_unpackhi_pd(lo, lo);
    lo = _mm_add_sd(lo, t);
    sum = _mm_cvtsd_f64(lo);
#elif defined(DISTURB_SIMD_SSE)
    __m128d acc = _mm_setzero_pd();
    for (; i + 2 <= n; i += 2)
        acc = _mm_add_pd(acc, _mm_loadu_pd(a + i));
    __m128d t = _mm_unpackhi_pd(acc, acc);
    acc = _mm_add_sd(acc, t);
    sum = _mm_cvtsd_f64(acc);
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t acc = vdupq_n_f64(0.0);
    for (; i + 2 <= n; i += 2)
        acc = vaddq_f64(acc, vld1q_f64(a + i));
    sum = vgetq_lane_f64(acc, 0) + vgetq_lane_f64(acc, 1);
#endif
    for (; i < n; i++) sum += a[i];
    return sum;
}

/* --- f64 dot product --------------------------------------------------- */
static inline double simd_f64_dot(const double *a, const double *b, size_t n)
{
    double dot = 0.0;
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2) && defined(__FMA__)
    __m256d acc = _mm256_setzero_pd();
    for (; i + 4 <= n; i += 4)
        acc = _mm256_fmadd_pd(_mm256_loadu_pd(a + i), _mm256_loadu_pd(b + i), acc);
    __m128d lo = _mm256_castpd256_pd128(acc);
    __m128d hi = _mm256_extractf128_pd(acc, 1);
    lo = _mm_add_pd(lo, hi);
    __m128d t = _mm_unpackhi_pd(lo, lo);
    lo = _mm_add_sd(lo, t);
    dot = _mm_cvtsd_f64(lo);
#elif defined(DISTURB_SIMD_AVX2)
    __m256d acc = _mm256_setzero_pd();
    for (; i + 4 <= n; i += 4)
        acc = _mm256_add_pd(acc, _mm256_mul_pd(_mm256_loadu_pd(a + i), _mm256_loadu_pd(b + i)));
    __m128d lo = _mm256_castpd256_pd128(acc);
    __m128d hi = _mm256_extractf128_pd(acc, 1);
    lo = _mm_add_pd(lo, hi);
    __m128d t = _mm_unpackhi_pd(lo, lo);
    lo = _mm_add_sd(lo, t);
    dot = _mm_cvtsd_f64(lo);
#elif defined(DISTURB_SIMD_SSE)
    __m128d acc = _mm_setzero_pd();
    for (; i + 2 <= n; i += 2)
        acc = _mm_add_pd(acc, _mm_mul_pd(_mm_loadu_pd(a + i), _mm_loadu_pd(b + i)));
    __m128d t = _mm_unpackhi_pd(acc, acc);
    acc = _mm_add_sd(acc, t);
    dot = _mm_cvtsd_f64(acc);
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t acc = vdupq_n_f64(0.0);
    for (; i + 2 <= n; i += 2)
        acc = vfmaq_f64(acc, vld1q_f64(a + i), vld1q_f64(b + i));
    dot = vgetq_lane_f64(acc, 0) + vgetq_lane_f64(acc, 1);
#endif
    for (; i < n; i++) dot += a[i] * b[i];
    return dot;
}

/* --- f64 fused multiply-add: out[i] = a[i] * b[i] + c[i] ------------- */
static inline void
simd_float_fma(const double *a, const double *b, const double *c, double *out,
               size_t n, int ba, int bb, int bc)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2) && defined(__FMA__)
    __m256d va, vb, vc;
    if (ba) va = _mm256_set1_pd(a[0]);
    if (bb) vb = _mm256_set1_pd(b[0]);
    if (bc) vc = _mm256_set1_pd(c[0]);
    for (; i + 4 <= n; i += 4) {
        if (!ba) va = _mm256_loadu_pd(a + i);
        if (!bb) vb = _mm256_loadu_pd(b + i);
        if (!bc) vc = _mm256_loadu_pd(c + i);
        _mm256_storeu_pd(out + i, _mm256_fmadd_pd(va, vb, vc));
    }
#elif defined(DISTURB_SIMD_NEON)
    float64x2_t va, vb, vc;
    if (ba) va = vdupq_n_f64(a[0]);
    if (bb) vb = vdupq_n_f64(b[0]);
    if (bc) vc = vdupq_n_f64(c[0]);
    for (; i + 2 <= n; i += 2) {
        if (!ba) va = vld1q_f64(a + i);
        if (!bb) vb = vld1q_f64(b + i);
        if (!bc) vc = vld1q_f64(c + i);
        vst1q_f64(out + i, vfmaq_f64(vc, va, vb));
    }
#endif
    for (; i < n; i++)
        out[i] = (ba ? a[0] : a[i]) * (bb ? b[0] : b[i]) + (bc ? c[0] : c[i]);
}

/* --- i64 horizontal sum ------------------------------------------------ */
static inline int64_t simd_int_sum(const int64_t *a, size_t n)
{
    int64_t sum = 0;
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    __m256i acc = _mm256_setzero_si256();
    for (; i + 4 <= n; i += 4)
        acc = _mm256_add_epi64(acc, _mm256_loadu_si256((const __m256i*)(a + i)));
    /* horizontal reduce 4→1 */
    __m128i lo = _mm256_castsi256_si128(acc);
    __m128i hi = _mm256_extracti128_si256(acc, 1);
    lo = _mm_add_epi64(lo, hi);
    sum = _mm_extract_epi64(lo, 0) + _mm_extract_epi64(lo, 1);
#elif defined(DISTURB_SIMD_SSE)
    __m128i acc = _mm_setzero_si128();
    for (; i + 2 <= n; i += 2)
        acc = _mm_add_epi64(acc, _mm_loadu_si128((const __m128i*)(a + i)));
    sum = _mm_extract_epi64(acc, 0) + _mm_extract_epi64(acc, 1);
#elif defined(DISTURB_SIMD_NEON)
    int64x2_t acc = vdupq_n_s64(0);
    for (; i + 2 <= n; i += 2)
        acc = vaddq_s64(acc, vld1q_s64(a + i));
    sum = vgetq_lane_s64(acc, 0) + vgetq_lane_s64(acc, 1);
#endif
    for (; i < n; i++) sum += a[i];
    return sum;
}

/* --- i64 dot product --------------------------------------------------- */
static inline int64_t simd_int_dot(const int64_t *a, const int64_t *b, size_t n)
{
    int64_t dot = 0;
    /* No native 64-bit multiply in AVX2/SSE, use scalar */
    for (size_t i = 0; i < n; i++) dot += a[i] * b[i];
    return dot;
}

/* --- f64 horizontal min ------------------------------------------------ */
static inline double simd_f64_min(const double *a, size_t n)
{
    if (n == 0) return 0.0;
    double mn = a[0];
    size_t i = 1;
#if defined(DISTURB_SIMD_AVX2)
    if (n >= 4) {
        __m256d acc = _mm256_loadu_pd(a);
        for (i = 4; i + 4 <= n; i += 4)
            acc = _mm256_min_pd(acc, _mm256_loadu_pd(a + i));
        __m128d lo = _mm256_castpd256_pd128(acc);
        __m128d hi = _mm256_extractf128_pd(acc, 1);
        lo = _mm_min_pd(lo, hi);
        __m128d t = _mm_unpackhi_pd(lo, lo);
        lo = _mm_min_sd(lo, t);
        mn = _mm_cvtsd_f64(lo);
    }
#elif defined(DISTURB_SIMD_SSE)
    if (n >= 2) {
        __m128d acc = _mm_loadu_pd(a);
        for (i = 2; i + 2 <= n; i += 2)
            acc = _mm_min_pd(acc, _mm_loadu_pd(a + i));
        __m128d t = _mm_unpackhi_pd(acc, acc);
        acc = _mm_min_sd(acc, t);
        mn = _mm_cvtsd_f64(acc);
    }
#elif defined(DISTURB_SIMD_NEON)
    if (n >= 2) {
        float64x2_t acc = vld1q_f64(a);
        for (i = 2; i + 2 <= n; i += 2)
            acc = vminq_f64(acc, vld1q_f64(a + i));
        mn = vgetq_lane_f64(acc, 0) < vgetq_lane_f64(acc, 1)
           ? vgetq_lane_f64(acc, 0) : vgetq_lane_f64(acc, 1);
    }
#endif
    for (; i < n; i++) if (a[i] < mn) mn = a[i];
    return mn;
}

/* --- f64 horizontal max ------------------------------------------------ */
static inline double simd_f64_max(const double *a, size_t n)
{
    if (n == 0) return 0.0;
    double mx = a[0];
    size_t i = 1;
#if defined(DISTURB_SIMD_AVX2)
    if (n >= 4) {
        __m256d acc = _mm256_loadu_pd(a);
        for (i = 4; i + 4 <= n; i += 4)
            acc = _mm256_max_pd(acc, _mm256_loadu_pd(a + i));
        __m128d lo = _mm256_castpd256_pd128(acc);
        __m128d hi = _mm256_extractf128_pd(acc, 1);
        lo = _mm_max_pd(lo, hi);
        __m128d t = _mm_unpackhi_pd(lo, lo);
        lo = _mm_max_sd(lo, t);
        mx = _mm_cvtsd_f64(lo);
    }
#elif defined(DISTURB_SIMD_SSE)
    if (n >= 2) {
        __m128d acc = _mm_loadu_pd(a);
        for (i = 2; i + 2 <= n; i += 2)
            acc = _mm_max_pd(acc, _mm_loadu_pd(a + i));
        __m128d t = _mm_unpackhi_pd(acc, acc);
        acc = _mm_max_sd(acc, t);
        mx = _mm_cvtsd_f64(acc);
    }
#elif defined(DISTURB_SIMD_NEON)
    if (n >= 2) {
        float64x2_t acc = vld1q_f64(a);
        for (i = 2; i + 2 <= n; i += 2)
            acc = vmaxq_f64(acc, vld1q_f64(a + i));
        mx = vgetq_lane_f64(acc, 0) > vgetq_lane_f64(acc, 1)
           ? vgetq_lane_f64(acc, 0) : vgetq_lane_f64(acc, 1);
    }
#endif
    for (; i < n; i++) if (a[i] > mx) mx = a[i];
    return mx;
}

/* --- f64 element-wise abs ---------------------------------------------- */
static inline void simd_f64_abs(const double *a, double *out, size_t n)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    /* Clear sign bit: AND with ~(1<<63) */
    __m256d mask = _mm256_castsi256_pd(_mm256_set1_epi64x(0x7FFFFFFFFFFFFFFFLL));
    for (; i + 4 <= n; i += 4)
        _mm256_storeu_pd(out + i, _mm256_and_pd(_mm256_loadu_pd(a + i), mask));
#elif defined(DISTURB_SIMD_SSE)
    __m128d mask = _mm_castsi128_pd(_mm_set1_epi64x(0x7FFFFFFFFFFFFFFFLL));
    for (; i + 2 <= n; i += 2)
        _mm_storeu_pd(out + i, _mm_and_pd(_mm_loadu_pd(a + i), mask));
#elif defined(DISTURB_SIMD_NEON)
    for (; i + 2 <= n; i += 2)
        vst1q_f64(out + i, vabsq_f64(vld1q_f64(a + i)));
#endif
    for (; i < n; i++) out[i] = a[i] < 0 ? -a[i] : a[i];
}

/* --- f64 element-wise sqrt --------------------------------------------- */
static inline void simd_f64_sqrt(const double *a, double *out, size_t n)
{
    size_t i = 0;
#if defined(DISTURB_SIMD_AVX2)
    for (; i + 4 <= n; i += 4)
        _mm256_storeu_pd(out + i, _mm256_sqrt_pd(_mm256_loadu_pd(a + i)));
#elif defined(DISTURB_SIMD_SSE)
    for (; i + 2 <= n; i += 2)
        _mm_storeu_pd(out + i, _mm_sqrt_pd(_mm_loadu_pd(a + i)));
#elif defined(DISTURB_SIMD_NEON)
    for (; i + 2 <= n; i += 2)
        vst1q_f64(out + i, vsqrtq_f64(vld1q_f64(a + i)));
#endif
    for (; i < n; i++) out[i] = sqrt(a[i]);
}

#else /* 32-bit reductions */

static inline float simd_f64_sum(const float *a, size_t n)
{
    float sum = 0.0f;
    for (size_t i = 0; i < n; i++) sum += a[i];
    return sum;
}

static inline float simd_f64_dot(const float *a, const float *b, size_t n)
{
    float dot = 0.0f;
    for (size_t i = 0; i < n; i++) dot += a[i] * b[i];
    return dot;
}

static inline void
simd_float_fma(const float *a, const float *b, const float *c, float *out,
               size_t n, int ba, int bb, int bc)
{
    for (size_t i = 0; i < n; i++)
        out[i] = (ba ? a[0] : a[i]) * (bb ? b[0] : b[i]) + (bc ? c[0] : c[i]);
}

#endif /* reduction width check */

#endif /* DISTURB_SIMD_OPS_H */
