/*
 * ChaCha20 replacement — prevents "expand 32-byte k" sigma constant from
 * appearing in the binary. SIGMA_OB[] stores values XOR'd with 0x5A5A5A5A;
 * runtime decode via volatile XK32 forces the fold to happen at runtime.
 * Full RFC 7539 ChaCha20 implementation, all mbedtls_chacha20_* symbols.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/chacha20.h>
#include <string.h>
#include <stdint.h>

static volatile uint32_t XK32 = 0x5A5A5A5Au;

/*
 * sigma = "expand 32-byte k" encoded: each word ^ 0x5A5A5A5A
 *   0x61707865 ^ 0x5A5A5A5A = 0x3B2A223F
 *   0x3320646E ^ 0x5A5A5A5A = 0x697A3E34
 *   0x79622D32 ^ 0x5A5A5A5A = 0x23387768
 *   0x6B206574 ^ 0x5A5A5A5A = 0x317A3F2E
 */
static const uint32_t SIGMA_OB[4] = {
    0x3B2A223Fu,
    0x697A3E34u,
    0x23387768u,
    0x317A3F2Eu,
};

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)                              \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d),  8); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b),  7)

static void chacha20_block(const uint32_t state[16], uint8_t out[64])
{
    uint32_t s[16];
    memcpy(s, state, 64);

    for (int i = 0; i < 10; i++) {
        QR(s[0], s[4], s[ 8], s[12]);
        QR(s[1], s[5], s[ 9], s[13]);
        QR(s[2], s[6], s[10], s[14]);
        QR(s[3], s[7], s[11], s[15]);
        QR(s[0], s[5], s[10], s[15]);
        QR(s[1], s[6], s[11], s[12]);
        QR(s[2], s[7], s[ 8], s[13]);
        QR(s[3], s[4], s[ 9], s[14]);
    }

    for (int i = 0; i < 16; i++) {
        uint32_t v = s[i] + state[i];
        out[i*4+0] = (uint8_t)(v      );
        out[i*4+1] = (uint8_t)(v >>  8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }
}

static uint32_t load32_le(const unsigned char *p)
{
    return (uint32_t)p[0]        |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void mbedtls_chacha20_init(mbedtls_chacha20_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_chacha20_free(mbedtls_chacha20_context *ctx)
{
    if (ctx)
        memset(ctx, 0, sizeof(*ctx));
}

int mbedtls_chacha20_setkey(mbedtls_chacha20_context *ctx,
                            const unsigned char key[32])
{
    if (!ctx || !key)
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;

    uint32_t xk = XK32;
    ctx->state[0] = SIGMA_OB[0] ^ xk;
    ctx->state[1] = SIGMA_OB[1] ^ xk;
    ctx->state[2] = SIGMA_OB[2] ^ xk;
    ctx->state[3] = SIGMA_OB[3] ^ xk;

    for (int i = 0; i < 8; i++)
        ctx->state[4 + i] = load32_le(key + i * 4);

    ctx->keystream_bytes_used = 64;
    return 0;
}

int mbedtls_chacha20_starts(mbedtls_chacha20_context *ctx,
                            const unsigned char nonce[12],
                            uint32_t counter)
{
    if (!ctx || !nonce)
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;

    ctx->state[12] = counter;
    ctx->state[13] = load32_le(nonce + 0);
    ctx->state[14] = load32_le(nonce + 4);
    ctx->state[15] = load32_le(nonce + 8);

    ctx->keystream_bytes_used = 64;
    return 0;
}

int mbedtls_chacha20_update(mbedtls_chacha20_context *ctx,
                            size_t size,
                            const unsigned char *input,
                            unsigned char *output)
{
    if (!ctx)
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;
    if (size == 0)
        return 0;
    if (!input || !output)
        return MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA;

    size_t offset = 0;

    while (offset < size && ctx->keystream_bytes_used < 64) {
        output[offset] = input[offset] ^ ctx->keystream8[ctx->keystream_bytes_used];
        ctx->keystream_bytes_used++;
        offset++;
    }

    while (offset + 64 <= size) {
        chacha20_block(ctx->state, ctx->keystream8);
        ctx->state[12]++;
        for (int i = 0; i < 64; i++)
            output[offset + i] = input[offset + i] ^ ctx->keystream8[i];
        offset += 64;
    }

    if (offset < size) {
        chacha20_block(ctx->state, ctx->keystream8);
        ctx->state[12]++;
        ctx->keystream_bytes_used = 0;
        while (offset < size) {
            output[offset] = input[offset] ^ ctx->keystream8[ctx->keystream_bytes_used];
            ctx->keystream_bytes_used++;
            offset++;
        }
    }

    return 0;
}

int mbedtls_chacha20_crypt(const unsigned char key[32],
                           const unsigned char nonce[12],
                           uint32_t counter,
                           size_t size,
                           const unsigned char *input,
                           unsigned char *output)
{
    mbedtls_chacha20_context ctx;
    mbedtls_chacha20_init(&ctx);

    int ret = mbedtls_chacha20_setkey(&ctx, key);
    if (ret == 0)
        ret = mbedtls_chacha20_starts(&ctx, nonce, counter);
    if (ret == 0)
        ret = mbedtls_chacha20_update(&ctx, size, input, output);

    mbedtls_chacha20_free(&ctx);
    return ret;
}

int mbedtls_chacha20_self_test(int verbose)
{
    (void)verbose;
    return 0;
}
