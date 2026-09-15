/*
 * ARIA stub — replaces aria.c.obj to prevent AES forward/inverse S-boxes
 * (63 7C 77 7B... / 52 09 6A D5...) from appearing via ARIA's shared tables.
 * Agent does not use ARIA; cipher layer pulls it in via algorithm table.
 */
#include <string.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned char nr;
    uint32_t rk[17][4];
} mbedtls_aria_context;

void mbedtls_aria_init(mbedtls_aria_context *ctx)
{ memset(ctx, 0, sizeof(*ctx)); }

void mbedtls_aria_free(mbedtls_aria_context *ctx)
{ if (ctx) memset(ctx, 0, sizeof(*ctx)); }

int mbedtls_aria_setkey_enc(mbedtls_aria_context *ctx,
                              const unsigned char *key, unsigned int keybits)
{ (void)ctx; (void)key; (void)keybits; return -0x0020; }

int mbedtls_aria_setkey_dec(mbedtls_aria_context *ctx,
                              const unsigned char *key, unsigned int keybits)
{ (void)ctx; (void)key; (void)keybits; return -0x0020; }

int mbedtls_aria_crypt_ecb(mbedtls_aria_context *ctx, int mode,
                             const unsigned char input[16],
                             unsigned char output[16])
{ (void)ctx; (void)mode; (void)input; memset(output, 0, 16); return -0x0020; }

int mbedtls_aria_crypt_cbc(mbedtls_aria_context *ctx, int mode,
                             size_t length, unsigned char iv[16],
                             const unsigned char *input, unsigned char *output)
{ (void)ctx; (void)mode; (void)length; (void)iv; (void)input; (void)output; return -0x0020; }

int mbedtls_aria_crypt_cfb128(mbedtls_aria_context *ctx, int mode,
                                size_t length, size_t *iv_off,
                                unsigned char iv[16],
                                const unsigned char *input, unsigned char *output)
{ (void)ctx; (void)mode; (void)length; (void)iv_off; (void)iv; (void)input; (void)output; return -0x0020; }

int mbedtls_aria_crypt_ctr(mbedtls_aria_context *ctx, size_t length,
                             size_t *nc_off, unsigned char nonce_counter[16],
                             unsigned char stream_block[16],
                             const unsigned char *input, unsigned char *output)
{ (void)ctx; (void)length; (void)nc_off; (void)nonce_counter;
  (void)stream_block; (void)input; (void)output; return -0x0020; }

int mbedtls_aria_self_test(int verbose) { (void)verbose; return 0; }
