#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE    32
#define CHACHA20_NONCE_SIZE  12
#define POLY1305_TAG_SIZE    16
#define X25519_KEY_SIZE      32
#define CRYPTO_OVERHEAD      (CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE)

typedef struct {
    uint8_t  session_key[CHACHA20_KEY_SIZE];
    uint8_t  key_mask[CHACHA20_KEY_SIZE];
    uint8_t  agent_privkey[X25519_KEY_SIZE];
    uint8_t  agent_pubkey[X25519_KEY_SIZE];
    int      key_established;
} crypto_ctx_t;

int  crypto_init(crypto_ctx_t *ctx);
void crypto_free(crypto_ctx_t *ctx);

int chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *pt, size_t pt_len,
                               uint8_t *ct, uint8_t *tag);

int chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *tag, uint8_t *pt);

int crypto_gen_keypair(uint8_t *pubkey, uint8_t *privkey);
int crypto_ecdh(const uint8_t *privkey, const uint8_t *peer_pubkey,
                uint8_t *shared_secret);

int crypto_hkdf(const uint8_t *ikm,  size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/* ctx->agent_privkey/pubkey must be set first via crypto_gen_keypair() */
int crypto_do_handshake(crypto_ctx_t *ctx, const uint8_t *server_pubkey);

int crypto_rand_bytes(uint8_t *buf, size_t len);

/* Wire format: nonce(12) | ciphertext(n) | tag(16) — caller free()s result */
uint8_t *crypto_seal(crypto_ctx_t *ctx,
                     const uint8_t *pt, size_t pt_len, size_t *out_len);
uint8_t *crypto_open(crypto_ctx_t *ctx,
                     const uint8_t *blob, size_t blob_len, size_t *out_len);

/* Base64 — caller free()s result */
char    *base64_encode(const uint8_t *data, size_t len);
uint8_t *base64_decode(const char *str, size_t *out_len);

#endif /* CRYPTO_H */
