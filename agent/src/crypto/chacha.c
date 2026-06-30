#include "crypto.h"
#include <mbedtls/chachapoly.h>
#include <mbedtls/base64.h>
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include <stdlib.h>

int crypto_rand_bytes(uint8_t *buf, size_t len)
{
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
}

int crypto_init(crypto_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return 0;
}

void crypto_free(crypto_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

/* ChaCha20-Poly1305 encrypt/decrypt */

int chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *ct, uint8_t *tag)
{
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret == 0)
        ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, pt_len, nonce,
                                                 NULL, 0,
                                                 pt, ct, tag);
    mbedtls_chachapoly_free(&ctx);
    return ret;
}

int chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ct, size_t ct_len,
                              const uint8_t *tag, uint8_t *pt)
{
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret == 0)
        ret = mbedtls_chachapoly_auth_decrypt(&ctx, ct_len, nonce,
                                              NULL, 0,
                                              tag, ct, pt);
    mbedtls_chachapoly_free(&ctx);
    return ret;
}

/* ---- Authenticated encryption with session key ---- */

uint8_t *crypto_seal(crypto_ctx_t *ctx,
                     const uint8_t *pt, size_t pt_len,
                     size_t *out_len)
{
    size_t total = CHACHA20_NONCE_SIZE + pt_len + POLY1305_TAG_SIZE;
    uint8_t *buf = malloc(total);
    if (!buf)
        return NULL;

    uint8_t *nonce = buf;
    uint8_t *ct = buf + CHACHA20_NONCE_SIZE;
    uint8_t *tag = buf + CHACHA20_NONCE_SIZE + pt_len;

    /* unmask key, encrypt, re-randomize mask */
    uint8_t tmp_key[CHACHA20_KEY_SIZE];
    for (int i = 0; i < CHACHA20_KEY_SIZE; i++)
        tmp_key[i] = ctx->session_key[i] ^ ctx->key_mask[i];

    int enc_ok = (crypto_rand_bytes(nonce, CHACHA20_NONCE_SIZE) == 0) &&
                 (chacha20_poly1305_encrypt(tmp_key, nonce, pt, pt_len, ct, tag) == 0);

    /* re-randomize mask after use */
    uint8_t new_mask[CHACHA20_KEY_SIZE];
    if (crypto_rand_bytes(new_mask, CHACHA20_KEY_SIZE) == 0)
    {
        for (int i = 0; i < CHACHA20_KEY_SIZE; i++)
        {
            ctx->session_key[i] = tmp_key[i] ^ new_mask[i];
            ctx->key_mask[i] = new_mask[i];
        }
    }
    memset(tmp_key, 0, sizeof(tmp_key));
    memset(new_mask, 0, sizeof(new_mask));

    if (!enc_ok)
    {
        free(buf);
        return NULL;
    }
    *out_len = total;
    return buf;
}

uint8_t *crypto_open(crypto_ctx_t *ctx,
                     const uint8_t *blob, size_t blob_len,
                     size_t *out_len)
{
    if (blob_len < CRYPTO_OVERHEAD)
        return NULL;

    const uint8_t *nonce = blob;
    size_t ct_len = blob_len - CRYPTO_OVERHEAD;
    const uint8_t *ct = blob + CHACHA20_NONCE_SIZE;
    const uint8_t *tag = blob + CHACHA20_NONCE_SIZE + ct_len;

    uint8_t *pt = malloc(ct_len + 1);
    if (!pt)
        return NULL;

    /* unmask key, decrypt, re-randomize mask */
    uint8_t tmp_key[CHACHA20_KEY_SIZE];
    for (int i = 0; i < CHACHA20_KEY_SIZE; i++)
        tmp_key[i] = ctx->session_key[i] ^ ctx->key_mask[i];

    int dec_ok = (chacha20_poly1305_decrypt(tmp_key, nonce, ct, ct_len, tag, pt) == 0);

    uint8_t new_mask[CHACHA20_KEY_SIZE];
    if (crypto_rand_bytes(new_mask, CHACHA20_KEY_SIZE) == 0)
    {
        for (int i = 0; i < CHACHA20_KEY_SIZE; i++)
        {
            ctx->session_key[i] = tmp_key[i] ^ new_mask[i];
            ctx->key_mask[i] = new_mask[i];
        }
    }
    memset(tmp_key, 0, sizeof(tmp_key));
    memset(new_mask, 0, sizeof(new_mask));

    if (!dec_ok)
    {
        free(pt);
        return NULL;
    }
    pt[ct_len] = '\0';
    *out_len = ct_len;
    return pt;
}

/* base64 encode/decode via mbedTLS */

char *base64_encode(const uint8_t *data, size_t len)
{
    size_t out_len = 0;
    mbedtls_base64_encode(NULL, 0, &out_len, data, len);

    char *buf = malloc(out_len + 1);
    if (!buf)
        return NULL;

    if (mbedtls_base64_encode((unsigned char *)buf, out_len + 1,
                              &out_len, data, len) != 0)
    {
        free(buf);
        return NULL;
    }
    buf[out_len] = '\0';
    return buf;
}

uint8_t *base64_decode(const char *str, size_t *out_len)
{
    size_t in_len = strlen(str);
    size_t decoded_len = 0;

    mbedtls_base64_decode(NULL, 0, &decoded_len,
                          (const unsigned char *)str, in_len);

    uint8_t *buf = malloc(decoded_len + 1);
    if (!buf)
        return NULL;

    if (mbedtls_base64_decode(buf, decoded_len + 1, &decoded_len,
                              (const unsigned char *)str, in_len) != 0)
    {
        free(buf);
        return NULL;
    }
    buf[decoded_len] = '\0';
    *out_len = decoded_len;
    return buf;
}
