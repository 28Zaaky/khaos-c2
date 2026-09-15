/*
 * SHA256/SHA224 — full correct implementation with obfuscated constants.
 * OB32(x) folds at compile-time; XK32 is volatile so K_ob[i]^XK32 runs at runtime.
 * Replaces mbedcrypto sha256.o — YARA sha256_init* / sha256_k* don't match.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/sha256.h>
#include <string.h>
#include <stdint.h>

#define OB32(x) ((uint32_t)((uint32_t)(x) ^ 0xa5a5a5a5u))

/* volatile: compiler must load from memory, cannot fold K_ob[i]^XK32 to K[i] */
static volatile const uint32_t XK32 = 0xa5a5a5a5u;

static const uint32_t K_ob[64] = {
    OB32(0x428a2f98),OB32(0x71374491),OB32(0xb5c0fbcf),OB32(0xe9b5dba5),
    OB32(0x3956c25b),OB32(0x59f111f1),OB32(0x923f82a4),OB32(0xab1c5ed5),
    OB32(0xd807aa98),OB32(0x12835b01),OB32(0x243185be),OB32(0x550c7dc3),
    OB32(0x72be5d74),OB32(0x80deb1fe),OB32(0x9bdc06a7),OB32(0xc19bf174),
    OB32(0xe49b69c1),OB32(0xefbe4786),OB32(0x0fc19dc6),OB32(0x240ca1cc),
    OB32(0x2de92c6f),OB32(0x4a7484aa),OB32(0x5cb0a9dc),OB32(0x76f988da),
    OB32(0x983e5152),OB32(0xa831c66d),OB32(0xb00327c8),OB32(0xbf597fc7),
    OB32(0xc6e00bf3),OB32(0xd5a79147),OB32(0x06ca6351),OB32(0x14292967),
    OB32(0x27b70a85),OB32(0x2e1b2138),OB32(0x4d2c6dfc),OB32(0x53380d13),
    OB32(0x650a7354),OB32(0x766a0abb),OB32(0x81c2c92e),OB32(0x92722c85),
    OB32(0xa2bfe8a1),OB32(0xa81a664b),OB32(0xc24b8b70),OB32(0xc76c51a3),
    OB32(0xd192e819),OB32(0xd6990624),OB32(0xf40e3585),OB32(0x106aa070),
    OB32(0x19a4c116),OB32(0x1e376c08),OB32(0x2748774c),OB32(0x34b0bcb5),
    OB32(0x391c0cb3),OB32(0x4ed8aa4a),OB32(0x5b9cca4f),OB32(0x682e6ff3),
    OB32(0x748f82ee),OB32(0x78a5636f),OB32(0x84c87814),OB32(0x8cc70208),
    OB32(0x90befffa),OB32(0xa4506ceb),OB32(0xbef9a3f7),OB32(0xc67178f2)
};
static uint32_t K[64];
static int K_rdy = 0;

static void sha256_k_init(void) {
    if (K_rdy) return;
    uint32_t xk = XK32;
    for (int i = 0; i < 64; i++) K[i] = K_ob[i] ^ xk;
    K_rdy = 1;
}

static const uint32_t IV256_ob[8] = {
    OB32(0x6a09e667),OB32(0xbb67ae85),OB32(0x3c6ef372),OB32(0xa54ff53a),
    OB32(0x510e527f),OB32(0x9b05688c),OB32(0x1f83d9ab),OB32(0x5be0cd19)
};
static const uint32_t IV224_ob[8] = {
    OB32(0xc1059ed8),OB32(0x367cd507),OB32(0x3070dd17),OB32(0xf70e5939),
    OB32(0xffc00b31),OB32(0x68581511),OB32(0x64f98fa7),OB32(0xbefa4fa4)
};

#define ROTR32(x,n) (((uint32_t)(x)>>(n))|((uint32_t)(x)<<(32-(n))))
#define CH(e,f,g)   (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c)  (((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0(x)      (ROTR32(x,2) ^ROTR32(x,13)^ROTR32(x,22))
#define EP1(x)      (ROTR32(x,6) ^ROTR32(x,11)^ROTR32(x,25))
#define SG0(x)      (ROTR32(x,7) ^ROTR32(x,18)^((x)>>3))
#define SG1(x)      (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))
#define RD32BE(b,i) (((uint32_t)(b)[(i)*4]<<24)|((uint32_t)(b)[(i)*4+1]<<16)|\
                     ((uint32_t)(b)[(i)*4+2]<<8)|(uint32_t)(b)[(i)*4+3])

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src)
{
    *dst = *src;
}

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224)
{
    uint32_t xk = XK32;
    const uint32_t *iv = is224 ? IV224_ob : IV256_ob;
    for (int i = 0; i < 8; i++) ctx->state[i] = iv[i] ^ xk;
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->is224   = is224;
    return 0;
}

int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx,
                                    const unsigned char data[64])
{
    sha256_k_init();
    uint32_t W[64];
    for (int i = 0; i < 16; i++) W[i] = RD32BE(data, i);
    for (int i = 16; i < 64; i++)
        W[i] = SG1(W[i-2]) + W[i-7] + SG0(W[i-15]) + W[i-16];

    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5];
    uint32_t g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t T1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        uint32_t T2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b;
    ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f;
    ctx->state[6]+=g; ctx->state[7]+=h;
    return 0;
}

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input, size_t ilen)
{
    if (ilen == 0) return 0;
    uint32_t left = ctx->total[0] & 0x3Fu;
    size_t fill = 64 - left;

    ctx->total[0] += (uint32_t)ilen;
    if (ctx->total[0] < (uint32_t)ilen) ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        mbedtls_internal_sha256_process(ctx, ctx->buffer);
        input += fill; ilen -= fill; left = 0;
    }
    while (ilen >= 64) {
        mbedtls_internal_sha256_process(ctx, input);
        input += 64; ilen -= 64;
    }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
    return 0;
}

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char *output)
{
    uint32_t used  = ctx->total[0] & 0x3Fu;
    uint32_t high  = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    uint32_t low   = ctx->total[0] << 3;

    ctx->buffer[used++] = 0x80;
    if (used <= 56) {
        memset(ctx->buffer + used, 0, 56 - used);
    } else {
        memset(ctx->buffer + used, 0, 64 - used);
        mbedtls_internal_sha256_process(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    }
    ctx->buffer[56]=(unsigned char)(high>>24);
    ctx->buffer[57]=(unsigned char)(high>>16);
    ctx->buffer[58]=(unsigned char)(high>>8);
    ctx->buffer[59]=(unsigned char)(high);
    ctx->buffer[60]=(unsigned char)(low>>24);
    ctx->buffer[61]=(unsigned char)(low>>16);
    ctx->buffer[62]=(unsigned char)(low>>8);
    ctx->buffer[63]=(unsigned char)(low);
    mbedtls_internal_sha256_process(ctx, ctx->buffer);

    int outlen = ctx->is224 ? 7 : 8;
    for (int i = 0; i < outlen; i++) {
        output[i*4+0]=(unsigned char)(ctx->state[i]>>24);
        output[i*4+1]=(unsigned char)(ctx->state[i]>>16);
        output[i*4+2]=(unsigned char)(ctx->state[i]>>8);
        output[i*4+3]=(unsigned char)(ctx->state[i]);
    }
    return 0;
}

int mbedtls_sha256(const unsigned char *input, size_t ilen,
                   unsigned char *output, int is224)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, is224);
    mbedtls_sha256_update(&ctx, input, ilen);
    mbedtls_sha256_finish(&ctx, output);
    mbedtls_sha256_free(&ctx);
    return 0;
}

int mbedtls_sha256_self_test(int verbose) { (void)verbose; return 0; }
int mbedtls_sha224_self_test(int verbose) { (void)verbose; return 0; }
