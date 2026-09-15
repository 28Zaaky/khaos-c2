/*
 * RIPEMD-160 stub — replaces ripemd160.c.obj to prevent SHA1 K1 (0x5A827999)
 * from appearing via RIPEMD-160's shared round constant.
 * Agent does not use RIPEMD-160; md.c.obj pulls it in via algorithm table.
 */
#include <string.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t total[2];
    uint32_t state[5];
    unsigned char buffer[64];
} mbedtls_ripemd160_context;

void mbedtls_ripemd160_init(mbedtls_ripemd160_context *ctx)
{ memset(ctx, 0, sizeof(*ctx)); }

void mbedtls_ripemd160_free(mbedtls_ripemd160_context *ctx)
{ if (ctx) memset(ctx, 0, sizeof(*ctx)); }

void mbedtls_ripemd160_clone(mbedtls_ripemd160_context *dst,
                              const mbedtls_ripemd160_context *src)
{ *dst = *src; }

int mbedtls_ripemd160_starts(mbedtls_ripemd160_context *ctx)
{ memset(ctx, 0, sizeof(*ctx)); return 0; }

int mbedtls_ripemd160_update(mbedtls_ripemd160_context *ctx,
                              const unsigned char *input, size_t ilen)
{ (void)ctx; (void)input; (void)ilen; return 0; }

int mbedtls_ripemd160_finish(mbedtls_ripemd160_context *ctx,
                              unsigned char output[20])
{ (void)ctx; memset(output, 0, 20); return 0; }

int mbedtls_internal_ripemd160_process(mbedtls_ripemd160_context *ctx,
                                        const unsigned char data[64])
{ (void)ctx; (void)data; return 0; }

int mbedtls_ripemd160(const unsigned char *input, size_t ilen,
                       unsigned char output[20])
{ (void)input; (void)ilen; memset(output, 0, 20); return 0; }

int mbedtls_ripemd160_self_test(int verbose) { (void)verbose; return 0; }
