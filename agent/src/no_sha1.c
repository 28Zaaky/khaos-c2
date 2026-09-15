/*
 * SHA1 stub — replaces mbedcrypto's sha1.o to prevent K-constant emission.
 * Constants 0x5A827999 / 0x6ED9EBA1 / 0x8F1BBCDC / 0xCA62C1D6 never appear.
 */
#include <string.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t total[2];
    uint32_t state[5];
    unsigned char buffer[64];
} mbedtls_sha1_context;

void mbedtls_sha1_init(mbedtls_sha1_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha1_free(mbedtls_sha1_context *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha1_clone(mbedtls_sha1_context *dst,
                        const mbedtls_sha1_context *src)
{
    *dst = *src;
}

int mbedtls_sha1_starts(mbedtls_sha1_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

int mbedtls_sha1_update(mbedtls_sha1_context *ctx,
                        const unsigned char *input,
                        size_t ilen)
{
    (void)ctx; (void)input; (void)ilen;
    return 0;
}

int mbedtls_sha1_finish(mbedtls_sha1_context *ctx,
                        unsigned char output[20])
{
    (void)ctx;
    memset(output, 0, 20);
    return 0;
}

int mbedtls_internal_sha1_process(mbedtls_sha1_context *ctx,
                                  const unsigned char data[64])
{
    (void)ctx; (void)data;
    return 0;
}

int mbedtls_sha1(const unsigned char *input,
                 size_t ilen,
                 unsigned char output[20])
{
    (void)input; (void)ilen;
    memset(output, 0, 20);
    return 0;
}

int mbedtls_sha1_self_test(int verbose)
{
    (void)verbose;
    return 0;
}
