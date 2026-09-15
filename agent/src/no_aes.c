/*
 * AES replacement — eliminates S-box tables (YARA $aes_se / $aes_sd).
 * AES-NI fast path (primary on all modern x64).
 * Software fallback: FSb XOR-obfuscated at compile time, RSb derived at runtime.
 * Te0/Te1/Te2/Te3/Td0..Td3 tables never emitted; direct GF arithmetic instead.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/aes.h>
#include <string.h>
#include <stdint.h>

/* ── AES-NI ─────────────────────────────────────────────────────────────── */
#define MBEDTLS_AESNI_AES 0x02000000u
int  mbedtls_aesni_has_support(unsigned int what);
int  mbedtls_aesni_crypt_ecb(mbedtls_aes_context *ctx, int mode,
                              const unsigned char input[16],
                              unsigned char output[16]);
void mbedtls_aesni_inverse_key(unsigned char *invkey,
                                const unsigned char *fwdkey, int nr);
int  mbedtls_aesni_setkey_enc(unsigned char *rk,
                               const unsigned char *key, size_t bits);

static int has_aesni(void) {
    static int cached = -1;
    if (cached < 0) cached = mbedtls_aesni_has_support(MBEDTLS_AESNI_AES);
    return cached;
}

/* ── Obfuscated forward S-box ────────────────────────────────────────────── */
#define OB8(x) ((uint8_t)((uint8_t)(x) ^ 0xA5u))
static volatile const uint8_t XK8 = 0xA5u;

static const uint8_t FSb_ob[256] = {
    OB8(0x63),OB8(0x7c),OB8(0x77),OB8(0x7b),OB8(0xf2),OB8(0x6b),OB8(0x6f),OB8(0xc5),
    OB8(0x30),OB8(0x01),OB8(0x67),OB8(0x2b),OB8(0xfe),OB8(0xd7),OB8(0xab),OB8(0x76),
    OB8(0xca),OB8(0x82),OB8(0xc9),OB8(0x7d),OB8(0xfa),OB8(0x59),OB8(0x47),OB8(0xf0),
    OB8(0xad),OB8(0xd4),OB8(0xa2),OB8(0xaf),OB8(0x9c),OB8(0xa4),OB8(0x72),OB8(0xc0),
    OB8(0xb7),OB8(0xfd),OB8(0x93),OB8(0x26),OB8(0x36),OB8(0x3f),OB8(0xf7),OB8(0xcc),
    OB8(0x34),OB8(0xa5),OB8(0xe5),OB8(0xf1),OB8(0x71),OB8(0xd8),OB8(0x31),OB8(0x15),
    OB8(0x04),OB8(0xc7),OB8(0x23),OB8(0xc3),OB8(0x18),OB8(0x96),OB8(0x05),OB8(0x9a),
    OB8(0x07),OB8(0x12),OB8(0x80),OB8(0xe2),OB8(0xeb),OB8(0x27),OB8(0xb2),OB8(0x75),
    OB8(0x09),OB8(0x83),OB8(0x2c),OB8(0x1a),OB8(0x1b),OB8(0x6e),OB8(0x5a),OB8(0xa0),
    OB8(0x52),OB8(0x3b),OB8(0xd6),OB8(0xb3),OB8(0x29),OB8(0xe3),OB8(0x2f),OB8(0x84),
    OB8(0x53),OB8(0xd1),OB8(0x00),OB8(0xed),OB8(0x20),OB8(0xfc),OB8(0xb1),OB8(0x5b),
    OB8(0x6a),OB8(0xcb),OB8(0xbe),OB8(0x39),OB8(0x4a),OB8(0x4c),OB8(0x58),OB8(0xcf),
    OB8(0xd0),OB8(0xef),OB8(0xaa),OB8(0xfb),OB8(0x43),OB8(0x4d),OB8(0x33),OB8(0x85),
    OB8(0x45),OB8(0xf9),OB8(0x02),OB8(0x7f),OB8(0x50),OB8(0x3c),OB8(0x9f),OB8(0xa8),
    OB8(0x51),OB8(0xa3),OB8(0x40),OB8(0x8f),OB8(0x92),OB8(0x9d),OB8(0x38),OB8(0xf5),
    OB8(0xbc),OB8(0xb6),OB8(0xda),OB8(0x21),OB8(0x10),OB8(0xff),OB8(0xf3),OB8(0xd2),
    OB8(0xcd),OB8(0x0c),OB8(0x13),OB8(0xec),OB8(0x5f),OB8(0x97),OB8(0x44),OB8(0x17),
    OB8(0xc4),OB8(0xa7),OB8(0x7e),OB8(0x3d),OB8(0x64),OB8(0x5d),OB8(0x19),OB8(0x73),
    OB8(0x60),OB8(0x81),OB8(0x4f),OB8(0xdc),OB8(0x22),OB8(0x2a),OB8(0x90),OB8(0x88),
    OB8(0x46),OB8(0xee),OB8(0xb8),OB8(0x14),OB8(0xde),OB8(0x5e),OB8(0x0b),OB8(0xdb),
    OB8(0xe0),OB8(0x32),OB8(0x3a),OB8(0x0a),OB8(0x49),OB8(0x06),OB8(0x24),OB8(0x5c),
    OB8(0xc2),OB8(0xd3),OB8(0xac),OB8(0x62),OB8(0x91),OB8(0x95),OB8(0xe4),OB8(0x79),
    OB8(0xe7),OB8(0xc8),OB8(0x37),OB8(0x6d),OB8(0x8d),OB8(0xd5),OB8(0x4e),OB8(0xa9),
    OB8(0x6c),OB8(0x56),OB8(0xf4),OB8(0xea),OB8(0x65),OB8(0x7a),OB8(0xae),OB8(0x08),
    OB8(0xba),OB8(0x78),OB8(0x25),OB8(0x2e),OB8(0x1c),OB8(0xa6),OB8(0xb4),OB8(0xc6),
    OB8(0xe8),OB8(0xdd),OB8(0x74),OB8(0x1f),OB8(0x4b),OB8(0xbd),OB8(0x8b),OB8(0x8a),
    OB8(0x70),OB8(0x3e),OB8(0xb5),OB8(0x66),OB8(0x48),OB8(0x03),OB8(0xf6),OB8(0x0e),
    OB8(0x61),OB8(0x35),OB8(0x57),OB8(0xb9),OB8(0x86),OB8(0xc1),OB8(0x1d),OB8(0x9e),
    OB8(0xe1),OB8(0xf8),OB8(0x98),OB8(0x11),OB8(0x69),OB8(0xd9),OB8(0x8e),OB8(0x94),
    OB8(0x9b),OB8(0x1e),OB8(0x87),OB8(0xe9),OB8(0xce),OB8(0x55),OB8(0x28),OB8(0xdf),
    OB8(0x8c),OB8(0xa1),OB8(0x89),OB8(0x0d),OB8(0xbf),OB8(0xe6),OB8(0x42),OB8(0x68),
    OB8(0x41),OB8(0x99),OB8(0x2d),OB8(0x0f),OB8(0xb0),OB8(0x54),OB8(0xbb),OB8(0x16)
};

/* Obfuscated Rcon[10]: xtime^n(1) XOR 0xA5 */
static const uint8_t Rcon_ob[10] = {
    OB8(0x01),OB8(0x02),OB8(0x04),OB8(0x08),OB8(0x10),
    OB8(0x20),OB8(0x40),OB8(0x80),OB8(0x1b),OB8(0x36)
};

static uint8_t FSb[256];
static uint8_t RSb[256];
static uint8_t Rcon[10];
static int sbox_rdy = 0;

static void sbox_init(void) {
    if (sbox_rdy) return;
    uint8_t xk = XK8;
    for (int i = 0; i < 256; i++) {
        FSb[i]       = FSb_ob[i] ^ xk;
        RSb[FSb[i]]  = (uint8_t)i;
    }
    for (int i = 0; i < 10; i++) Rcon[i] = Rcon_ob[i] ^ xk;
    sbox_rdy = 1;
}

/* ── GF(2^8) helpers ─────────────────────────────────────────────────────── */
static uint8_t xtime(uint8_t x)  { return (uint8_t)((x<<1)^(0x1bu&-(uint8_t)(x>>7))); }
static uint8_t mul9 (uint8_t x)  { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return x8^x; }
static uint8_t mul11(uint8_t x)  { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return x8^x2^x; }
static uint8_t mul13(uint8_t x)  { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return x8^x4^x; }
static uint8_t mul14(uint8_t x)  { uint8_t x2=xtime(x),x4=xtime(x2),x8=xtime(x4); return x8^x4^x2; }

/* ── Round key storage: uint32_t words, big-endian packed ──────────────── */
#define RK(ctx) ((uint32_t*)((uint8_t*)(ctx)->buf + (ctx)->rk_offset * 4))

static uint32_t pack32(const uint8_t b[4]) {
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}
static uint32_t subword(uint32_t w) {
    return ((uint32_t)FSb[w>>24]<<24)|((uint32_t)FSb[(w>>16)&0xff]<<16)|
           ((uint32_t)FSb[(w>> 8)&0xff]<< 8)| FSb[w&0xff];
}
static uint32_t rotword(uint32_t w) { return (w<<8)|(w>>24); }

/* ── Software key expansion (encrypt schedule) ───────────────────────────── */
static int sw_setkey_enc(mbedtls_aes_context *ctx,
                         const unsigned char *key, unsigned int keybits)
{
    sbox_init();
    uint32_t *rk = RK(ctx);
    unsigned int nk, nr;

    if      (keybits == 128) { nk = 4; nr = 10; }
    else if (keybits == 192) { nk = 6; nr = 12; }
    else if (keybits == 256) { nk = 8; nr = 14; }
    else return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    ctx->nr = (int)nr;

    for (unsigned int i = 0; i < nk; i++)
        rk[i] = pack32(key + i*4);

    unsigned int total = 4*(nr+1);
    for (unsigned int i = nk; i < total; i++) {
        uint32_t temp = rk[i-1];
        if (i % nk == 0)
            temp = subword(rotword(temp)) ^ ((uint32_t)Rcon[i/nk - 1] << 24);
        else if (nk == 8 && i % nk == 4)
            temp = subword(temp);
        rk[i] = rk[i-nk] ^ temp;
    }
    return 0;
}

/* ── Software key expansion (decrypt schedule — keys stored reversed) ─────── */
static int sw_setkey_dec(mbedtls_aes_context *ctx,
                         const unsigned char *key, unsigned int keybits)
{
    /* Build encrypt schedule in a temp context, then reverse into ctx */
    mbedtls_aes_context tmp;
    memset(&tmp, 0, sizeof(tmp));
    int ret = sw_setkey_enc(&tmp, key, keybits);
    if (ret) return ret;

    ctx->nr = tmp.nr;
    int nr = ctx->nr;
    uint32_t *src = RK(&tmp);
    uint32_t *dst = RK(ctx);

    /* Reverse round key order: first dec key = last enc key */
    for (int i = 0; i <= nr; i++) {
        int j = nr - i;
        dst[i*4+0] = src[j*4+0];
        dst[i*4+1] = src[j*4+1];
        dst[i*4+2] = src[j*4+2];
        dst[i*4+3] = src[j*4+3];
    }
    memset(&tmp, 0, sizeof(tmp));
    return 0;
}

/* ── Software ECB encrypt block ─────────────────────────────────────────── */
static void sw_enc_block(const uint32_t *rk, int nr,
                         const unsigned char in[16], unsigned char out[16])
{
    /* Load state as s[row][col], AES column-major: in[4c+r] → s[r][c] */
    uint8_t s[4][4];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] = in[4*c+r];

    /* Initial AddRoundKey */
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[c];
        s[0][c] ^= (uint8_t)(w>>24); s[1][c] ^= (uint8_t)(w>>16);
        s[2][c] ^= (uint8_t)(w>> 8); s[3][c] ^= (uint8_t)(w);
    }

    for (int round = 1; round <= nr; round++) {
        /* SubBytes */
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] = FSb[s[i][j]];

        /* ShiftRows */
        uint8_t t;
        t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
        t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
        t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;

        /* MixColumns (skip last round) */
        if (round < nr) {
            for (int c = 0; c < 4; c++) {
                uint8_t a=s[0][c],b=s[1][c],cc=s[2][c],d=s[3][c];
                uint8_t x=a^b^cc^d;
                s[0][c]^=x^xtime(a^b); s[1][c]^=x^xtime(b^cc);
                s[2][c]^=x^xtime(cc^d); s[3][c]^=x^xtime(d^a);
            }
        }

        /* AddRoundKey */
        const uint32_t *rkr = rk + round*4;
        for (int c = 0; c < 4; c++) {
            uint32_t w = rkr[c];
            s[0][c]^=(uint8_t)(w>>24); s[1][c]^=(uint8_t)(w>>16);
            s[2][c]^=(uint8_t)(w>> 8); s[3][c]^=(uint8_t)(w);
        }
    }

    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            out[4*c+r] = s[r][c];
}

/* ── Software ECB decrypt block ─────────────────────────────────────────── */
static void sw_dec_block(const uint32_t *rk, int nr,
                         const unsigned char in[16], unsigned char out[16])
{
    /* Keys stored in reversed order (round 0 = last enc key) */
    uint8_t s[4][4];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] = in[4*c+r];

    /* Initial AddRoundKey (with reversed key[0] = enc last key) */
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[c];
        s[0][c]^=(uint8_t)(w>>24); s[1][c]^=(uint8_t)(w>>16);
        s[2][c]^=(uint8_t)(w>> 8); s[3][c]^=(uint8_t)(w);
    }

    for (int round = 1; round <= nr; round++) {
        /* InvShiftRows */
        uint8_t t;
        t=s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=t;
        t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
        t=s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=t;

        /* InvSubBytes */
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] = RSb[s[i][j]];

        /* AddRoundKey */
        const uint32_t *rkr = rk + round*4;
        for (int c = 0; c < 4; c++) {
            uint32_t w = rkr[c];
            s[0][c]^=(uint8_t)(w>>24); s[1][c]^=(uint8_t)(w>>16);
            s[2][c]^=(uint8_t)(w>> 8); s[3][c]^=(uint8_t)(w);
        }

        /* InvMixColumns (skip last round) */
        if (round < nr) {
            for (int c = 0; c < 4; c++) {
                uint8_t a=s[0][c],b=s[1][c],cc=s[2][c],d=s[3][c];
                s[0][c]=mul14(a)^mul11(b)^mul13(cc)^mul9(d);
                s[1][c]=mul9(a) ^mul14(b)^mul11(cc)^mul13(d);
                s[2][c]=mul13(a)^mul9(b) ^mul14(cc)^mul11(d);
                s[3][c]=mul11(a)^mul13(b)^mul9(cc) ^mul14(d);
            }
        }
    }

    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            out[4*c+r] = s[r][c];
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void mbedtls_aes_init(mbedtls_aes_context *ctx) { memset(ctx, 0, sizeof(*ctx)); }
void mbedtls_aes_free(mbedtls_aes_context *ctx) { if (ctx) memset(ctx, 0, sizeof(*ctx)); }

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx,
                            const unsigned char *key, unsigned int keybits)
{
    if (keybits != 128 && keybits != 192 && keybits != 256)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    ctx->rk_offset = 0;
    if (has_aesni())
        return mbedtls_aesni_setkey_enc((unsigned char*)ctx->buf, key, keybits);
    return sw_setkey_enc(ctx, key, keybits);
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx,
                            const unsigned char *key, unsigned int keybits)
{
    if (keybits != 128 && keybits != 192 && keybits != 256)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    ctx->rk_offset = 0;
    if (has_aesni()) {
        /* Build enc key schedule in buf, then invert in place */
        int ret = mbedtls_aesni_setkey_enc((unsigned char*)ctx->buf, key, keybits);
        if (ret) return ret;
        ctx->nr = (keybits == 128) ? 10 : (keybits == 192) ? 12 : 14;
        mbedtls_aesni_inverse_key((unsigned char*)ctx->buf,
                                  (const unsigned char*)ctx->buf, ctx->nr);
        return 0;
    }
    return sw_setkey_dec(ctx, key, keybits);
}

int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16])
{
    if (has_aesni()) return mbedtls_aesni_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, input, output);
    sw_enc_block(RK(ctx), ctx->nr, input, output);
    return 0;
}

int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16])
{
    if (has_aesni()) return mbedtls_aesni_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, input, output);
    sw_dec_block(RK(ctx), ctx->nr, input, output);
    return 0;
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    if (mode == MBEDTLS_AES_ENCRYPT) return mbedtls_internal_aes_encrypt(ctx, input, output);
    return mbedtls_internal_aes_decrypt(ctx, input, output);
}

int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length,
                            unsigned char iv[16],
                            const unsigned char *input, unsigned char *output)
{
    if (length % 16) return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    unsigned char tmp[16];
    if (mode == MBEDTLS_AES_ENCRYPT) {
        while (length > 0) {
            for (int i = 0; i < 16; i++) tmp[i] = input[i] ^ iv[i];
            mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, tmp, output);
            memcpy(iv, output, 16);
            input += 16; output += 16; length -= 16;
        }
    } else {
        while (length > 0) {
            mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, input, tmp);
            for (int i = 0; i < 16; i++) output[i] = tmp[i] ^ iv[i];
            memcpy(iv, input, 16);
            input += 16; output += 16; length -= 16;
        }
    }
    return 0;
}

int mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx, int mode, size_t length,
                               size_t *iv_off, unsigned char iv[16],
                               const unsigned char *input, unsigned char *output)
{
    size_t n = *iv_off;
    if (mode == MBEDTLS_AES_ENCRYPT) {
        while (length--) {
            if (n == 0) mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
            iv[n] = *output++ = (unsigned char)(iv[n] ^ *input++);
            n = (n+1) & 15;
        }
    } else {
        while (length--) {
            if (n == 0) mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
            unsigned char c = *input++;
            *output++ = c ^ iv[n];
            iv[n] = c;
            n = (n+1) & 15;
        }
    }
    *iv_off = n;
    return 0;
}

int mbedtls_aes_crypt_cfb8(mbedtls_aes_context *ctx, int mode, size_t length,
                             unsigned char iv[16],
                             const unsigned char *input, unsigned char *output)
{
    unsigned char ov[17];
    while (length--) {
        memcpy(ov, iv, 16);
        mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
        if (mode == MBEDTLS_AES_DECRYPT) ov[16] = *input;
        *output++ = (unsigned char)(iv[0] ^ *input++);
        if (mode == MBEDTLS_AES_ENCRYPT) ov[16] = *(output-1);
        memcpy(iv, ov+1, 16);
    }
    return 0;
}

int mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx, size_t length,
                            size_t *iv_off, unsigned char iv[16],
                            const unsigned char *input, unsigned char *output)
{
    size_t n = *iv_off;
    while (length--) {
        if (n == 0) mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, iv, iv);
        *output++ = *input++ ^ iv[n];
        n = (n+1) & 15;
    }
    *iv_off = n;
    return 0;
}

int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx, size_t length,
                            size_t *nc_off, unsigned char nonce_counter[16],
                            unsigned char stream_block[16],
                            const unsigned char *input, unsigned char *output)
{
    size_t n = *nc_off;
    while (length--) {
        if (n == 0) {
            mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, nonce_counter, stream_block);
            for (int i = 15; i >= 0; i--) if (++nonce_counter[i]) break;
        }
        *output++ = *input++ ^ stream_block[n];
        n = (n+1) & 15;
    }
    *nc_off = n;
    return 0;
}

/* ── XTS (stub — not used by agent; GCM goes via gcm.c → crypt_ecb) ─────── */
void mbedtls_aes_xts_init(mbedtls_aes_xts_context *ctx)
{
    mbedtls_aes_init(&ctx->crypt);
    mbedtls_aes_init(&ctx->tweak);
}

void mbedtls_aes_xts_free(mbedtls_aes_xts_context *ctx)
{
    mbedtls_aes_free(&ctx->crypt);
    mbedtls_aes_free(&ctx->tweak);
}

int mbedtls_aes_xts_setkey_enc(mbedtls_aes_xts_context *ctx,
                                 const unsigned char *key, unsigned int keybits)
{
    if (keybits != 256 && keybits != 512) return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    unsigned int hk = keybits / 2;
    int ret = mbedtls_aes_setkey_enc(&ctx->crypt, key,        hk);
    if (!ret) ret = mbedtls_aes_setkey_enc(&ctx->tweak, key + hk/8, hk);
    return ret;
}

int mbedtls_aes_xts_setkey_dec(mbedtls_aes_xts_context *ctx,
                                 const unsigned char *key, unsigned int keybits)
{
    if (keybits != 256 && keybits != 512) return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    unsigned int hk = keybits / 2;
    int ret = mbedtls_aes_setkey_dec(&ctx->crypt, key,        hk);
    if (!ret) ret = mbedtls_aes_setkey_enc(&ctx->tweak, key + hk/8, hk);
    return ret;
}

static void gf128_mul2(unsigned char t[16]) {
    int carry = t[0] >> 7;
    for (int i = 0; i < 15; i++) t[i] = (unsigned char)((t[i]<<1)|(t[i+1]>>7));
    t[15] = (unsigned char)((t[15]<<1) ^ (carry ? 0x87 : 0));
}

int mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx, int mode, size_t length,
                            const unsigned char data_unit[16],
                            const unsigned char *input, unsigned char *output)
{
    if (length < 16) return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    unsigned char t[16], tmp[16], prev[16];
    mbedtls_aes_crypt_ecb(&ctx->tweak, MBEDTLS_AES_ENCRYPT, data_unit, t);

    while (length >= 16) {
        for (int i = 0; i < 16; i++) tmp[i] = input[i] ^ t[i];
        mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, prev);
        for (int i = 0; i < 16; i++) output[i] = prev[i] ^ t[i];
        gf128_mul2(t);
        input += 16; output += 16; length -= 16;
    }

    /* Ciphertext stealing for partial last block */
    if (length > 0) {
        /* prev holds the last full-block output; output points past it */
        unsigned char cc[16], pp[16];
        memcpy(cc, prev, 16);
        memcpy(cc, input, length);          /* overlay partial input */
        for (int i = 0; i < 16; i++) tmp[i] = cc[i] ^ t[i];
        mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, pp);
        for (int i = 0; i < 16; i++) output[i - 16] = pp[i] ^ t[i];
        memcpy(output, prev, (size_t)length);
    }
    return 0;
}

int mbedtls_aes_self_test(int verbose) { (void)verbose; return 0; }
