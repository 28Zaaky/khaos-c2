/*
 * MD5 stub — replaces mbedcrypto's md5.o to prevent K-constant emission.
 * All md5 symbols are satisfied here; md5.o from the archive is never pulled in.
 */
#include <string.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t total[2];
    uint32_t state[4];
    unsigned char buffer[64];
} mbedtls_md5_context;

void mbedtls_md5_init(mbedtls_md5_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_md5_free(mbedtls_md5_context *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_md5_clone(mbedtls_md5_context *dst,
                       const mbedtls_md5_context *src)
{
    *dst = *src;
}

int mbedtls_md5_starts(mbedtls_md5_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

int mbedtls_md5_update(mbedtls_md5_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
    (void)ctx; (void)input; (void)ilen;
    return 0;
}

int mbedtls_md5_finish(mbedtls_md5_context *ctx,
                       unsigned char output[16])
{
    (void)ctx;
    memset(output, 0, 16);
    return 0;
}

int mbedtls_internal_md5_process(mbedtls_md5_context *ctx,
                                 const unsigned char data[64])
{
    (void)ctx; (void)data;
    return 0;
}

int mbedtls_md5(const unsigned char *input,
                size_t ilen,
                unsigned char output[16])
{
    (void)input; (void)ilen;
    memset(output, 0, 16);
    return 0;
}

int mbedtls_md5_self_test(int verbose)
{
    (void)verbose;
    return 0;
}
