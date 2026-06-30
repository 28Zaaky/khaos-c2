#include "crypto.h"
#include <mbedtls/ecp.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <string.h>
#include <stdlib.h>

/* shared CSPRNG defined in chacha.c */
int crypto_rand_bytes(uint8_t *buf, size_t len);

/* adapter for mbedTLS f_rng callbacks */
static int _rng_cb(void *p_rng, unsigned char *buf, size_t len)
{
    (void)p_rng;
    return crypto_rand_bytes(buf, len);
}

/* generate an X25519 keypair */

int crypto_gen_keypair(uint8_t *pubkey, uint8_t *privkey)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;
    mbedtls_ecp_point Q;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret) goto out;

    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, _rng_cb, NULL);
    if (ret) goto out;

    ret = mbedtls_mpi_write_binary(&d, privkey, X25519_KEY_SIZE);
    if (ret) goto out;

    /* reverse public key bytes: mbedTLS is big-endian, X25519 wire is little-endian */
    ret = mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), pubkey, X25519_KEY_SIZE);
    if (ret == 0) {
        for (int i = 0; i < X25519_KEY_SIZE / 2; i++) {
            uint8_t tmp = pubkey[i];
            pubkey[i] = pubkey[X25519_KEY_SIZE - 1 - i];
            pubkey[X25519_KEY_SIZE - 1 - i] = tmp;
        }
    }

out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return ret;
}

/* ECDH: compute shared = privkey * peer_pubkey */

int crypto_ecdh(const uint8_t *privkey, const uint8_t *peer_pubkey,
                uint8_t *shared_secret)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;
    mbedtls_ecp_point Qp, R;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Qp);
    mbedtls_ecp_point_init(&R);

    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret) goto out;

    /* load private scalar */
    ret = mbedtls_mpi_read_binary(&d, privkey, X25519_KEY_SIZE);
    if (ret) goto out;

    /* reverse peer pubkey bytes: little-endian wire -> big-endian MPI */
    uint8_t peer_le[X25519_KEY_SIZE];
    for (int i = 0; i < X25519_KEY_SIZE; i++)
        peer_le[i] = peer_pubkey[X25519_KEY_SIZE - 1 - i];
    ret = mbedtls_mpi_read_binary(&Qp.MBEDTLS_PRIVATE(X), peer_le, X25519_KEY_SIZE);
    if (ret) goto out;

    /* Z = 1 for affine representation */
    ret = mbedtls_mpi_lset(&Qp.MBEDTLS_PRIVATE(Z), 1);
    if (ret) goto out;

    /* R = d * Qp */
    ret = mbedtls_ecp_mul(&grp, &R, &d, &Qp, _rng_cb, NULL);
    if (ret) goto out;

    /* shared secret = R.X, reversed to little-endian */
    ret = mbedtls_mpi_write_binary(&R.MBEDTLS_PRIVATE(X), shared_secret, X25519_KEY_SIZE);
    if (ret == 0) {
        for (int i = 0; i < X25519_KEY_SIZE / 2; i++) {
            uint8_t tmp = shared_secret[i];
            shared_secret[i] = shared_secret[X25519_KEY_SIZE - 1 - i];
            shared_secret[X25519_KEY_SIZE - 1 - i] = tmp;
        }
    }

out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Qp);
    mbedtls_ecp_point_free(&R);
    return ret;
}

/* HKDF-SHA256 key derivation */

int crypto_hkdf(const uint8_t *ikm,  size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(md,
                        salt, salt_len,
                        ikm,  ikm_len,
                        info, info_len,
                        okm,  okm_len);
}

/* ECDH + HKDF to establish session key */

int crypto_do_handshake(crypto_ctx_t *ctx, const uint8_t *server_pubkey)
{
    uint8_t shared[X25519_KEY_SIZE];
    int ret;

    ret = crypto_ecdh(ctx->agent_privkey, server_pubkey, shared);
    if (ret) return ret;

    /* HKDF info context label, stored as bytes to avoid string extraction */
    static const uint8_t k_info[] = {
        0x6b,0x64,0x66,0x2d,0x73,0x65,0x73,0x73,
        0x2d,0x76,0x31,0x00
    };

    /* derive session key */
    uint8_t raw_key[CHACHA20_KEY_SIZE];
    ret = crypto_hkdf(shared, sizeof(shared),
                      NULL, 0,
                      k_info, sizeof(k_info) - 1,
                      raw_key, CHACHA20_KEY_SIZE);

    memset(shared, 0, sizeof(shared));

    if (ret == 0) {
        /* store key XOR random mask so it's never plaintext on the heap */
        crypto_rand_bytes(ctx->key_mask, CHACHA20_KEY_SIZE);
        for (int i = 0; i < CHACHA20_KEY_SIZE; i++)
            ctx->session_key[i] = raw_key[i] ^ ctx->key_mask[i];
        ctx->key_established = 1;
    }
    memset(raw_key, 0, sizeof(raw_key));
    return ret;
}
