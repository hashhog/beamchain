/**
 * beamchain_crypto_nif.c — secp256k1 and SHA256 NIF bindings for Erlang
 *
 * Wraps libsecp256k1 for ECDSA/Schnorr signature verification
 * and public key operations. Also provides hardware-accelerated SHA256
 * using CPU intrinsics (SHA-NI on x86, SHA extensions on ARM).
 * All functions run on dirty CPU schedulers to avoid blocking the
 * Erlang VM's normal schedulers.
 */

#include <string.h>
#include <stdint.h>
#include <erl_nif.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
#include <secp256k1_ellswift.h>

/* ------------------------------------------------------------------ */
/* SHA-256 implementation with hardware acceleration                    */
/* ------------------------------------------------------------------ */

/* Detect CPU architecture at compile time */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define BEAMCHAIN_X86 1
    /* Always include immintrin.h if SHA intrinsics available at compile time */
    #if defined(__SHA__)
        #define BEAMCHAIN_SHA_NI_COMPILED 1
        #include <immintrin.h>
    #endif
    /* For CPUID detection */
    #if defined(__GNUC__) || defined(__clang__)
        #include <cpuid.h>
        #define BEAMCHAIN_HAS_CPUID 1
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define BEAMCHAIN_ARM64 1
    #if defined(__ARM_FEATURE_CRYPTO)
        #define BEAMCHAIN_ARM_SHA_COMPILED 1
        #include <arm_neon.h>
    #endif
    /* For runtime feature detection on Linux */
    #if defined(__linux__)
        #include <sys/auxv.h>
        #include <asm/hwcap.h>
        #define BEAMCHAIN_ARM_HWCAP 1
    #endif
#endif

/* SHA-256 implementation type - determined at runtime */
typedef enum {
    SHA256_IMPL_PORTABLE = 0,
    SHA256_IMPL_SHA_NI,
    SHA256_IMPL_ARM_SHA
} sha256_impl_t;

/* Global variable set at NIF load time */
static sha256_impl_t sha256_implementation = SHA256_IMPL_PORTABLE;

/* SHA-256 constants */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Initial hash values for SHA-256 */
static const uint32_t H256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* Portable SHA-256 helper macros */
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

/* Read big-endian 32-bit word */
static inline uint32_t read_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

/* Write big-endian 32-bit word */
static inline void write_be32(unsigned char *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff;
    p[3] = v & 0xff;
}

/* Process a single 64-byte block - portable implementation */
static void sha256_transform_portable(uint32_t state[8],
                                       const unsigned char block[64])
{
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t W[64];
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = read_be32(block + i * 4);
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds */
    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

#ifdef BEAMCHAIN_SHA_NI_COMPILED
/* SHA-NI accelerated transform for x86 with SHA extensions */
static void sha256_transform_shani(uint32_t state[8],
                                    const unsigned char block[64])
{
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL,
                                         0x0405060700010203ULL);

    /* Load initial state */
    TMP = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);

    TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);   /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

    /* Save state for final add */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Rounds 0-3 */
    MSG = _mm_loadu_si128((const __m128i *)(block + 0));
    MSG0 = _mm_shuffle_epi8(MSG, MASK);
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL,
                                              0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    MSG1 = _mm_loadu_si128((const __m128i *)(block + 16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL,
                                              0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_loadu_si128((const __m128i *)(block + 32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL,
                                              0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_loadu_si128((const __m128i *)(block + 48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL,
                                              0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL,
                                              0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 20-23 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL,
                                              0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 24-27 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL,
                                              0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 28-31 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL,
                                              0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 32-35 */
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL,
                                              0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 36-39 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL,
                                              0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 40-43 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL,
                                              0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 44-47 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL,
                                              0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 48-51 */
    MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL,
                                              0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 52-55 */
    MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL,
                                              0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 56-59 */
    MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL,
                                              0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL,
                                              0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Combine state */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);   /* ABEF */

    /* Save state */
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}
#endif /* BEAMCHAIN_SHA_NI_COMPILED */

#ifdef BEAMCHAIN_ARM_SHA_COMPILED
/* ARM SHA extensions accelerated transform */
static void sha256_transform_arm(uint32_t state[8],
                                  const unsigned char block[64])
{
    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;

    /* Load state */
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Load and byte-swap message */
    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    /* Rounds 0-3 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[0]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su0q_u32(MSG0, MSG1);

    /* Rounds 4-7 */
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[4]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    MSG1 = vsha256su0q_u32(MSG1, MSG2);

    /* Rounds 8-11 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[8]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    MSG2 = vsha256su0q_u32(MSG2, MSG3);

    /* Rounds 12-15 */
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[12]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    MSG3 = vsha256su0q_u32(MSG3, MSG0);

    /* Rounds 16-19 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[16]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    MSG0 = vsha256su0q_u32(MSG0, MSG1);

    /* Rounds 20-23 */
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[20]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    MSG1 = vsha256su0q_u32(MSG1, MSG2);

    /* Rounds 24-27 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[24]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    MSG2 = vsha256su0q_u32(MSG2, MSG3);

    /* Rounds 28-31 */
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[28]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    MSG3 = vsha256su0q_u32(MSG3, MSG0);

    /* Rounds 32-35 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[32]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);
    MSG0 = vsha256su0q_u32(MSG0, MSG1);

    /* Rounds 36-39 */
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[36]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);
    MSG1 = vsha256su0q_u32(MSG1, MSG2);

    /* Rounds 40-43 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[40]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);
    MSG2 = vsha256su0q_u32(MSG2, MSG3);

    /* Rounds 44-47 */
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[44]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);
    MSG3 = vsha256su0q_u32(MSG3, MSG0);

    /* Rounds 48-51 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[48]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 52-55 */
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[52]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Rounds 56-59 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[56]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 60-63 */
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[60]));
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Combine state */
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}
#endif /* BEAMCHAIN_ARM_SHA_COMPILED */

/* ------------------------------------------------------------------ */
/* Runtime CPU feature detection                                        */
/* ------------------------------------------------------------------ */

#ifdef BEAMCHAIN_HAS_CPUID
/* Detect SHA-NI support via CPUID on x86/x86_64 */
static int detect_sha_ni(void)
{
    unsigned int eax, ebx, ecx, edx;

    /* Check if CPUID supports leaf 7 (extended features) */
    if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx) || eax < 7) {
        return 0;
    }

    /* Check CPUID leaf 7, subleaf 0:
     * EBX bit 29 = SHA extensions */
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }

    return (ebx >> 29) & 1;
}
#endif

/* Detect CPU features and select best SHA-256 implementation */
static void detect_sha256_implementation(void)
{
    sha256_implementation = SHA256_IMPL_PORTABLE;

#if defined(BEAMCHAIN_X86) && defined(BEAMCHAIN_HAS_CPUID)
    #ifdef BEAMCHAIN_SHA_NI_COMPILED
    /* If compiled with SHA-NI support, check runtime availability */
    if (detect_sha_ni()) {
        sha256_implementation = SHA256_IMPL_SHA_NI;
        return;
    }
    #endif
#endif

#if defined(BEAMCHAIN_ARM64)
    #if defined(BEAMCHAIN_ARM_HWCAP) && defined(BEAMCHAIN_ARM_SHA_COMPILED)
    /* On Linux ARM64, check for SHA2 support via hwcap */
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_SHA2) {
        sha256_implementation = SHA256_IMPL_ARM_SHA;
        return;
    }
    #elif defined(__APPLE__) && defined(BEAMCHAIN_ARM_SHA_COMPILED)
    /* On Apple Silicon, crypto extensions are always available */
    sha256_implementation = SHA256_IMPL_ARM_SHA;
    #endif
#endif
}

/* Select transform function based on detected implementation */
static void sha256_transform(uint32_t state[8],
                              const unsigned char block[64])
{
    switch (sha256_implementation) {
#ifdef BEAMCHAIN_SHA_NI_COMPILED
        case SHA256_IMPL_SHA_NI:
            sha256_transform_shani(state, block);
            return;
#endif
#ifdef BEAMCHAIN_ARM_SHA_COMPILED
        case SHA256_IMPL_ARM_SHA:
            sha256_transform_arm(state, block);
            return;
#endif
        default:
            sha256_transform_portable(state, block);
            return;
    }
}

/* Full SHA-256 hash with proper padding */
static void sha256_full(const unsigned char *data, size_t len,
                        unsigned char out[32])
{
    uint32_t state[8];
    unsigned char block[64];
    size_t remaining = len;
    size_t processed = 0;
    int i;

    /* Initialize state */
    memcpy(state, H256_INIT, sizeof(state));

    /* Process complete 64-byte blocks */
    while (remaining >= 64) {
        sha256_transform(state, data + processed);
        processed += 64;
        remaining -= 64;
    }

    /* Pad final block(s) */
    memset(block, 0, 64);
    memcpy(block, data + processed, remaining);
    block[remaining] = 0x80;

    if (remaining >= 56) {
        /* Need two blocks for padding */
        sha256_transform(state, block);
        memset(block, 0, 64);
    }

    /* Append length in bits (big-endian 64-bit) */
    {
        uint64_t bits = (uint64_t)len * 8;
        block[56] = (bits >> 56) & 0xff;
        block[57] = (bits >> 48) & 0xff;
        block[58] = (bits >> 40) & 0xff;
        block[59] = (bits >> 32) & 0xff;
        block[60] = (bits >> 24) & 0xff;
        block[61] = (bits >> 16) & 0xff;
        block[62] = (bits >> 8) & 0xff;
        block[63] = bits & 0xff;
    }

    sha256_transform(state, block);

    /* Output hash (big-endian) */
    for (i = 0; i < 8; i++) {
        write_be32(out + i * 4, state[i]);
    }
}

static secp256k1_context *ctx = NULL;

/* ------------------------------------------------------------------ */
/* NIF lifecycle                                                       */
/* ------------------------------------------------------------------ */

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    if (!ctx) return -1;

    /* Detect best SHA-256 implementation at load time */
    detect_sha256_implementation();

    return 0;
}

static void unload(ErlNifEnv *env, void *priv_data)
{
    if (ctx) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason)
{
    return enif_make_tuple2(env,
        enif_make_atom(env, "error"),
        enif_make_atom(env, reason));
}

static ERL_NIF_TERM make_ok_binary(ErlNifEnv *env,
                                    const unsigned char *data, size_t len)
{
    ERL_NIF_TERM bin;
    unsigned char *buf = enif_make_new_binary(env, len, &bin);
    memcpy(buf, data, len);
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), bin);
}

/* ------------------------------------------------------------------ */
/* sha256_hardware_info_nif() -> {ok, sha_ni | arm_sha | generic}      */
/* Reports which SHA-256 implementation is in use.                      */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM sha256_hardware_info_nif(ErlNifEnv *env, int argc,
                                              const ERL_NIF_TERM argv[])
{
    const char *impl_name;

    switch (sha256_implementation) {
        case SHA256_IMPL_SHA_NI:
            impl_name = "sha_ni";
            break;
        case SHA256_IMPL_ARM_SHA:
            impl_name = "arm_sha";
            break;
        default:
            impl_name = "generic";
            break;
    }

    return enif_make_tuple2(env,
        enif_make_atom(env, "ok"),
        enif_make_atom(env, impl_name));
}

/* ------------------------------------------------------------------ */
/* sha256_nif(Data) -> Hash32                                          */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM sha256_nif(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[])
{
    ErlNifBinary data;

    if (!enif_inspect_binary(env, argv[0], &data))
        return enif_make_badarg(env);

    ERL_NIF_TERM result;
    unsigned char *out = enif_make_new_binary(env, 32, &result);
    sha256_full(data.data, data.size, out);

    return result;
}

/* ------------------------------------------------------------------ */
/* double_sha256_nif(Data) -> Hash32                                   */
/* Bitcoin's hash256 = SHA256(SHA256(data))                            */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM double_sha256_nif(ErlNifEnv *env, int argc,
                                       const ERL_NIF_TERM argv[])
{
    ErlNifBinary data;

    if (!enif_inspect_binary(env, argv[0], &data))
        return enif_make_badarg(env);

    unsigned char intermediate[32];
    sha256_full(data.data, data.size, intermediate);

    ERL_NIF_TERM result;
    unsigned char *out = enif_make_new_binary(env, 32, &result);
    sha256_full(intermediate, 32, out);

    return result;
}

/* ------------------------------------------------------------------ */
/* ecdsa_verify_nif(Msg32, DerSig, PubKey) -> true | false             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ecdsa_verify_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, sig, pubkey;

    if (!enif_inspect_binary(env, argv[0], &msg) ||
        !enif_inspect_binary(env, argv[1], &sig) ||
        !enif_inspect_binary(env, argv[2], &pubkey))
        return enif_make_badarg(env);

    if (msg.size != 32)
        return make_error(env, "invalid_msg_size");

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey.data, pubkey.size))
        return make_error(env, "invalid_pubkey");

    secp256k1_ecdsa_signature ecdsa_sig;
    if (!secp256k1_ecdsa_signature_parse_der(ctx, &ecdsa_sig,
                                              sig.data, sig.size))
        return make_error(env, "invalid_signature");

    int result = secp256k1_ecdsa_verify(ctx, &ecdsa_sig, msg.data, &pk);
    return enif_make_atom(env, result ? "true" : "false");
}

/* ------------------------------------------------------------------ */
/* schnorr_verify_nif(Msg32, Sig64, XOnlyPubKey32) -> true | false     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM schnorr_verify_nif(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, sig, pubkey;

    if (!enif_inspect_binary(env, argv[0], &msg) ||
        !enif_inspect_binary(env, argv[1], &sig) ||
        !enif_inspect_binary(env, argv[2], &pubkey))
        return enif_make_badarg(env);

    if (msg.size != 32 || sig.size != 64 || pubkey.size != 32)
        return make_error(env, "invalid_size");

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, pubkey.data))
        return make_error(env, "invalid_pubkey");

    int result = secp256k1_schnorrsig_verify(ctx, sig.data,
                                              msg.data, 32, &xpk);
    return enif_make_atom(env, result ? "true" : "false");
}

/* ------------------------------------------------------------------ */
/* pubkey_create_nif(SecKey32) -> {ok, PubKey33} | {error, reason}     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_create_nif(ErlNifEnv *env, int argc,
                                       const ERL_NIF_TERM argv[])
{
    ErlNifBinary seckey;

    if (!enif_inspect_binary(env, argv[0], &seckey) || seckey.size != 32)
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, seckey.data))
        return make_error(env, "invalid_seckey");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* pubkey_tweak_add_nif(PubKey, Tweak32) -> {ok, PubKey33}             */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_tweak_add_nif(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin, tweak;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin) ||
        !enif_inspect_binary(env, argv[1], &tweak) || tweak.size != 32)
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bin.data, pubkey_bin.size))
        return make_error(env, "invalid_pubkey");

    if (!secp256k1_ec_pubkey_tweak_add(ctx, &pk, tweak.data))
        return make_error(env, "tweak_failed");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* xonly_pubkey_tweak_add_nif(XOnlyPK32, Tweak32)                      */
/*   -> {ok, OutputPK32, Parity} | {error, reason}                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM xonly_pubkey_tweak_add_nif(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin, tweak;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin) || pubkey_bin.size != 32 ||
        !enif_inspect_binary(env, argv[1], &tweak) || tweak.size != 32)
        return enif_make_badarg(env);

    secp256k1_xonly_pubkey xpk;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xpk, pubkey_bin.data))
        return make_error(env, "invalid_pubkey");

    secp256k1_pubkey output_pk;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &output_pk, &xpk, tweak.data))
        return make_error(env, "tweak_failed");

    secp256k1_xonly_pubkey output_xpk;
    int parity;
    int ok = secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xpk, &parity, &output_pk);
    if (!ok) return make_error(env, "xonly_conversion_failed");

    unsigned char out[32];
    secp256k1_xonly_pubkey_serialize(ctx, out, &output_xpk);

    ERL_NIF_TERM out_bin;
    unsigned char *buf = enif_make_new_binary(env, 32, &out_bin);
    memcpy(buf, out, 32);

    return enif_make_tuple3(env,
        enif_make_atom(env, "ok"),
        out_bin,
        enif_make_int(env, parity));
}

/* ------------------------------------------------------------------ */
/* pubkey_compress_nif(PubKey) -> {ok, Compressed33}                   */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_compress_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin))
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bin.data, pubkey_bin.size))
        return make_error(env, "invalid_pubkey");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* pubkey_decompress_nif(PubKey) -> {ok, Uncompressed65}               */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_decompress_nif(ErlNifEnv *env, int argc,
                                           const ERL_NIF_TERM argv[])
{
    ErlNifBinary pubkey_bin;

    if (!enif_inspect_binary(env, argv[0], &pubkey_bin))
        return enif_make_badarg(env);

    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, pubkey_bin.data, pubkey_bin.size))
        return make_error(env, "invalid_pubkey");

    unsigned char out[65];
    size_t out_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pk,
                                  SECP256K1_EC_UNCOMPRESSED);
    return make_ok_binary(env, out, 65);
}

/* ------------------------------------------------------------------ */
/* pubkey_combine_nif([PubKey]) -> {ok, Combined33}                    */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM pubkey_combine_nif(ErlNifEnv *env, int argc,
                                        const ERL_NIF_TERM argv[])
{
    unsigned int list_len;
    if (!enif_get_list_length(env, argv[0], &list_len) ||
        list_len < 2 || list_len > 1024)
        return enif_make_badarg(env);

    secp256k1_pubkey *pubkeys = enif_alloc(list_len * sizeof(secp256k1_pubkey));
    const secp256k1_pubkey **ptrs = enif_alloc(list_len * sizeof(secp256k1_pubkey *));

    ERL_NIF_TERM head, tail = argv[0];
    for (unsigned int i = 0; i < list_len; i++) {
        enif_get_list_cell(env, tail, &head, &tail);
        ErlNifBinary pk_bin;
        if (!enif_inspect_binary(env, head, &pk_bin) ||
            !secp256k1_ec_pubkey_parse(ctx, &pubkeys[i],
                                        pk_bin.data, pk_bin.size)) {
            enif_free(pubkeys);
            enif_free(ptrs);
            return make_error(env, "invalid_pubkey");
        }
        ptrs[i] = &pubkeys[i];
    }

    secp256k1_pubkey combined;
    int ret = secp256k1_ec_pubkey_combine(ctx, &combined, ptrs, list_len);
    enif_free(pubkeys);
    enif_free(ptrs);

    if (!ret)
        return make_error(env, "combine_failed");

    unsigned char out[33];
    size_t out_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &combined,
                                  SECP256K1_EC_COMPRESSED);
    return make_ok_binary(env, out, 33);
}

/* ------------------------------------------------------------------ */
/* ecdsa_sign_nif(Msg32, SecKey32) -> {ok, DerSig} | {error, reason}   */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ecdsa_sign_nif(ErlNifEnv *env, int argc,
                                    const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, seckey;

    if (!enif_inspect_binary(env, argv[0], &msg) || msg.size != 32 ||
        !enif_inspect_binary(env, argv[1], &seckey) || seckey.size != 32)
        return enif_make_badarg(env);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, msg.data, seckey.data, NULL, NULL))
        return make_error(env, "signing_failed");

    unsigned char der[72];
    size_t der_len = 72;
    secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig);

    return make_ok_binary(env, der, der_len);
}

/* ------------------------------------------------------------------ */
/* schnorr_sign_nif(Msg32, SecKey32, AuxRand32)                        */
/*   -> {ok, Sig64} | {error, reason}                                  */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM schnorr_sign_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg, seckey, aux_rand;

    if (!enif_inspect_binary(env, argv[0], &msg) || msg.size != 32 ||
        !enif_inspect_binary(env, argv[1], &seckey) || seckey.size != 32 ||
        !enif_inspect_binary(env, argv[2], &aux_rand) || aux_rand.size != 32)
        return enif_make_badarg(env);

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, seckey.data))
        return make_error(env, "invalid_seckey");

    unsigned char sig[64];
    if (!secp256k1_schnorrsig_sign32(ctx, sig, msg.data, &keypair,
                                      aux_rand.data))
        return make_error(env, "signing_failed");

    return make_ok_binary(env, sig, 64);
}

/* ------------------------------------------------------------------ */
/* seckey_tweak_add_nif(SecKey32, Tweak32)                             */
/*   -> {ok, TweakedKey32} | {error, reason}                           */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM seckey_tweak_add_nif(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[])
{
    ErlNifBinary seckey, tweak;

    if (!enif_inspect_binary(env, argv[0], &seckey) || seckey.size != 32 ||
        !enif_inspect_binary(env, argv[1], &tweak) || tweak.size != 32)
        return enif_make_badarg(env);

    /* copy seckey — secp256k1_ec_seckey_tweak_add modifies in place */
    unsigned char result[32];
    memcpy(result, seckey.data, 32);

    if (!secp256k1_ec_seckey_tweak_add(ctx, result, tweak.data))
        return make_error(env, "tweak_failed");

    return make_ok_binary(env, result, 32);
}

/* ------------------------------------------------------------------ */
/* ellswift_create_nif(SecKey32, AuxRand32)                            */
/*   -> {ok, EllSwift64} | {error, reason}                             */
/* Creates a 64-byte ElligatorSwift-encoded public key from a private  */
/* key. Used for BIP324 v2 transport key exchange.                     */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ellswift_create_nif(ErlNifEnv *env, int argc,
                                         const ERL_NIF_TERM argv[])
{
    ErlNifBinary seckey, auxrand;

    if (!enif_inspect_binary(env, argv[0], &seckey) || seckey.size != 32 ||
        !enif_inspect_binary(env, argv[1], &auxrand) || auxrand.size != 32)
        return enif_make_badarg(env);

    unsigned char ell64[64];
    if (!secp256k1_ellswift_create(ctx, ell64, seckey.data, auxrand.data))
        return make_error(env, "invalid_seckey");

    return make_ok_binary(env, ell64, 64);
}

/* ------------------------------------------------------------------ */
/* ellswift_xdh_nif(EllA64, EllB64, SecKey32, Party)                   */
/*   -> {ok, SharedSecret32} | {error, reason}                         */
/* Computes ECDH shared secret using ElligatorSwift pubkeys.           */
/* Party: 0 if we are party A (initiator), 1 if party B (responder).  */
/* Uses BIP324 hash function for key derivation.                       */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM ellswift_xdh_nif(ErlNifEnv *env, int argc,
                                      const ERL_NIF_TERM argv[])
{
    ErlNifBinary ell_a, ell_b, seckey;
    int party;

    if (!enif_inspect_binary(env, argv[0], &ell_a) || ell_a.size != 64 ||
        !enif_inspect_binary(env, argv[1], &ell_b) || ell_b.size != 64 ||
        !enif_inspect_binary(env, argv[2], &seckey) || seckey.size != 32 ||
        !enif_get_int(env, argv[3], &party))
        return enif_make_badarg(env);

    unsigned char output[32];
    if (!secp256k1_ellswift_xdh(ctx, output,
                                ell_a.data, ell_b.data,
                                seckey.data, party,
                                secp256k1_ellswift_xdh_hash_function_bip324,
                                NULL))
        return make_error(env, "ecdh_failed");

    return make_ok_binary(env, output, 32);
}

/* ------------------------------------------------------------------ */
/* batch_ecdsa_verify_nif([{Msg32, DerSig, PubKey}]) -> [boolean()]    */
/* Batch verify multiple ECDSA signatures in a single NIF call.        */
/* Returns a list of booleans in the same order as input.              */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM batch_ecdsa_verify_nif(ErlNifEnv *env, int argc,
                                            const ERL_NIF_TERM argv[])
{
    unsigned int list_len;
    if (!enif_get_list_length(env, argv[0], &list_len))
        return enif_make_badarg(env);

    if (list_len == 0)
        return enif_make_list(env, 0);

    /* Allocate array for results */
    ERL_NIF_TERM *results = enif_alloc(list_len * sizeof(ERL_NIF_TERM));
    if (!results)
        return make_error(env, "alloc_failed");

    ERL_NIF_TERM head, tail = argv[0];
    unsigned int i;

    for (i = 0; i < list_len; i++) {
        if (!enif_get_list_cell(env, tail, &head, &tail)) {
            enif_free(results);
            return enif_make_badarg(env);
        }

        int arity;
        const ERL_NIF_TERM *tuple;
        if (!enif_get_tuple(env, head, &arity, &tuple) || arity != 3) {
            enif_free(results);
            return enif_make_badarg(env);
        }

        ErlNifBinary msg, sig, pubkey;
        if (!enif_inspect_binary(env, tuple[0], &msg) ||
            !enif_inspect_binary(env, tuple[1], &sig) ||
            !enif_inspect_binary(env, tuple[2], &pubkey)) {
            enif_free(results);
            return enif_make_badarg(env);
        }

        /* Verify this signature */
        int valid = 0;
        if (msg.size == 32) {
            secp256k1_pubkey pk;
            if (secp256k1_ec_pubkey_parse(ctx, &pk, pubkey.data, pubkey.size)) {
                secp256k1_ecdsa_signature ecdsa_sig;
                if (secp256k1_ecdsa_signature_parse_der(ctx, &ecdsa_sig,
                                                         sig.data, sig.size)) {
                    valid = secp256k1_ecdsa_verify(ctx, &ecdsa_sig,
                                                    msg.data, &pk);
                }
            }
        }

        results[i] = enif_make_atom(env, valid ? "true" : "false");
    }

    ERL_NIF_TERM result_list = enif_make_list_from_array(env, results, list_len);
    enif_free(results);

    return result_list;
}

/* ------------------------------------------------------------------ */
/* batch_schnorr_verify_nif([{Msg32, Sig64, XOnlyPK32}]) -> [boolean()] */
/* Batch verify multiple Schnorr signatures in a single NIF call.      */
/* ------------------------------------------------------------------ */

static ERL_NIF_TERM batch_schnorr_verify_nif(ErlNifEnv *env, int argc,
                                              const ERL_NIF_TERM argv[])
{
    unsigned int list_len;
    if (!enif_get_list_length(env, argv[0], &list_len))
        return enif_make_badarg(env);

    if (list_len == 0)
        return enif_make_list(env, 0);

    ERL_NIF_TERM *results = enif_alloc(list_len * sizeof(ERL_NIF_TERM));
    if (!results)
        return make_error(env, "alloc_failed");

    ERL_NIF_TERM head, tail = argv[0];
    unsigned int i;

    for (i = 0; i < list_len; i++) {
        if (!enif_get_list_cell(env, tail, &head, &tail)) {
            enif_free(results);
            return enif_make_badarg(env);
        }

        int arity;
        const ERL_NIF_TERM *tuple;
        if (!enif_get_tuple(env, head, &arity, &tuple) || arity != 3) {
            enif_free(results);
            return enif_make_badarg(env);
        }

        ErlNifBinary msg, sig, pubkey;
        if (!enif_inspect_binary(env, tuple[0], &msg) ||
            !enif_inspect_binary(env, tuple[1], &sig) ||
            !enif_inspect_binary(env, tuple[2], &pubkey)) {
            enif_free(results);
            return enif_make_badarg(env);
        }

        /* Verify this signature */
        int valid = 0;
        if (msg.size == 32 && sig.size == 64 && pubkey.size == 32) {
            secp256k1_xonly_pubkey xpk;
            if (secp256k1_xonly_pubkey_parse(ctx, &xpk, pubkey.data)) {
                valid = secp256k1_schnorrsig_verify(ctx, sig.data,
                                                     msg.data, 32, &xpk);
            }
        }

        results[i] = enif_make_atom(env, valid ? "true" : "false");
    }

    ERL_NIF_TERM result_list = enif_make_list_from_array(env, results, list_len);
    enif_free(results);

    return result_list;
}

/* ------------------------------------------------------------------ */
/* NIF table                                                           */
/* ------------------------------------------------------------------ */

static ErlNifFunc nif_funcs[] = {
    {"sha256_nif",                 1, sha256_nif,
        0},  /* Fast enough for normal scheduler */
    {"double_sha256_nif",          1, double_sha256_nif,
        0},  /* Fast enough for normal scheduler */
    {"sha256_hardware_info_nif",   0, sha256_hardware_info_nif,
        0},  /* Query only, very fast */
    {"batch_ecdsa_verify_nif",     1, batch_ecdsa_verify_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"batch_schnorr_verify_nif",   1, batch_schnorr_verify_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ecdsa_verify_nif",           3, ecdsa_verify_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"schnorr_verify_nif",         3, schnorr_verify_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_create_nif",          1, pubkey_create_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_tweak_add_nif",       2, pubkey_tweak_add_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xonly_pubkey_tweak_add_nif", 2, xonly_pubkey_tweak_add_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_compress_nif",        1, pubkey_compress_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_decompress_nif",      1, pubkey_decompress_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pubkey_combine_nif",         1, pubkey_combine_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ecdsa_sign_nif",             2, ecdsa_sign_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"schnorr_sign_nif",           3, schnorr_sign_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"seckey_tweak_add_nif",       2, seckey_tweak_add_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ellswift_create_nif",        2, ellswift_create_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"ellswift_xdh_nif",           4, ellswift_xdh_nif,
        ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(beamchain_crypto, nif_funcs, load, NULL, NULL, unload)
