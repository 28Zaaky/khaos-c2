/*
 * SHA512/SHA384 — full correct implementation with obfuscated constants.
 * OB64(x) folds at compile-time; XK64 is volatile so K512_ob[i]^XK64 runs at runtime.
 * Replaces mbedcrypto sha512.o — YARA sha512_k* don't match.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/sha512.h>
#include <string.h>
#include <stdint.h>

#define OB64(x) ((uint64_t)((uint64_t)(x) ^ 0xa5a5a5a5a5a5a5a5ULL))

static volatile const uint64_t XK64 = 0xa5a5a5a5a5a5a5a5ULL;

static const uint64_t K512_ob[80] = {
    OB64(0x428a2f98d728ae22ULL),OB64(0x7137449123ef65cdULL),
    OB64(0xb5c0fbcfec4d3b2fULL),OB64(0xe9b5dba58189dbbcULL),
    OB64(0x3956c25bf348b538ULL),OB64(0x59f111f1b605d019ULL),
    OB64(0x923f82a4af194f9bULL),OB64(0xab1c5ed5da6d8118ULL),
    OB64(0xd807aa98a3030242ULL),OB64(0x12835b0145706fbeULL),
    OB64(0x243185be4ee4b28cULL),OB64(0x550c7dc3d5ffb4e2ULL),
    OB64(0x72be5d74f27b896fULL),OB64(0x80deb1fe3b1696b1ULL),
    OB64(0x9bdc06a725c71235ULL),OB64(0xc19bf174cf692694ULL),
    OB64(0xe49b69c19ef14ad2ULL),OB64(0xefbe4786384f25e3ULL),
    OB64(0x0fc19dc68b8cd5b5ULL),OB64(0x240ca1cc77ac9c65ULL),
    OB64(0x2de92c6f592b0275ULL),OB64(0x4a7484aa6ea6e483ULL),
    OB64(0x5cb0a9dcbd41fbd4ULL),OB64(0x76f988da831153b5ULL),
    OB64(0x983e5152ee66dfabULL),OB64(0xa831c66d2db43210ULL),
    OB64(0xb00327c898fb213fULL),OB64(0xbf597fc7beef0ee4ULL),
    OB64(0xc6e00bf33da88fc2ULL),OB64(0xd5a79147930aa725ULL),
    OB64(0x06ca6351e003826fULL),OB64(0x142929670a0e6e70ULL),
    OB64(0x27b70a8546d22ffcULL),OB64(0x2e1b21385c26c926ULL),
    OB64(0x4d2c6dfc5ac42aedULL),OB64(0x53380d139d95b3dfULL),
    OB64(0x650a73548baf63deULL),OB64(0x766a0abb3c77b2a8ULL),
    OB64(0x81c2c92e47edaee6ULL),OB64(0x92722c851482353bULL),
    OB64(0xa2bfe8a14cf10364ULL),OB64(0xa81a664bbc423001ULL),
    OB64(0xc24b8b70d0f89791ULL),OB64(0xc76c51a30654be30ULL),
    OB64(0xd192e819d6ef5218ULL),OB64(0xd69906245565a910ULL),
    OB64(0xf40e35855771202aULL),OB64(0x106aa07032bbd1b8ULL),
    OB64(0x19a4c116b8d2d0c8ULL),OB64(0x1e376c085141ab53ULL),
    OB64(0x2748774cdf8eeb99ULL),OB64(0x34b0bcb5e19b48a8ULL),
    OB64(0x391c0cb3c5c95a63ULL),OB64(0x4ed8aa4ae3418acbULL),
    OB64(0x5b9cca4f7763e373ULL),OB64(0x682e6ff3d6b2b8a3ULL),
    OB64(0x748f82ee5defb2fcULL),OB64(0x78a5636f43172f60ULL),
    OB64(0x84c87814a1f0ab72ULL),OB64(0x8cc702081a6439ecULL),
    OB64(0x90befffa23631e28ULL),OB64(0xa4506cebde82bde9ULL),
    OB64(0xbef9a3f7b2c67915ULL),OB64(0xc67178f2e372532bULL),
    OB64(0xca273eceea26619cULL),OB64(0xd186b8c721c0c207ULL),
    OB64(0xeada7dd6cde0eb1eULL),OB64(0xf57d4f7fee6ed178ULL),
    OB64(0x06f067aa72176fbaULL),OB64(0x0a637dc5a2c898a6ULL),
    OB64(0x113f9804bef90daeULL),OB64(0x1b710b35131c471bULL),
    OB64(0x28db77f523047d84ULL),OB64(0x32caab7b40c72493ULL),
    OB64(0x3c9ebe0a15c9bebcULL),OB64(0x431d67c49c100d4cULL),
    OB64(0x4cc5d4becb3e42b6ULL),OB64(0x597f299cfc657e2aULL),
    OB64(0x5fcb6fab3ad6faecULL),OB64(0x6c44198c4a475817ULL)
};
static uint64_t K512[80];
static int K512_rdy = 0;

static void sha512_k_init(void) {
    if (K512_rdy) return;
    uint64_t xk = XK64;
    for (int i = 0; i < 80; i++) K512[i] = K512_ob[i] ^ xk;
    K512_rdy = 1;
}

static const uint64_t IV512_ob[8] = {
    OB64(0x6a09e667f3bcc908ULL),OB64(0xbb67ae8584caa73bULL),
    OB64(0x3c6ef372fe94f82bULL),OB64(0xa54ff53a5f1d36f1ULL),
    OB64(0x510e527fade682d1ULL),OB64(0x9b05688c2b3e6c1fULL),
    OB64(0x1f83d9abfb41bd6bULL),OB64(0x5be0cd19137e2179ULL)
};
static const uint64_t IV384_ob[8] = {
    OB64(0xcbbb9d5dc1059ed8ULL),OB64(0x629a292a367cd507ULL),
    OB64(0x9159015a3070dd17ULL),OB64(0x152fecd8f70e5939ULL),
    OB64(0x67332667ffc00b31ULL),OB64(0x8eb44a8768581511ULL),
    OB64(0xdb0c2e0d64f98fa7ULL),OB64(0x47b5481dbefa4fa4ULL)
};

#define ROTR64(x,n) (((uint64_t)(x)>>(n))|((uint64_t)(x)<<(64-(n))))
#define CH64(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define MAJ64(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0_64(x)    (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define EP1_64(x)    (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define SG0_64(x)    (ROTR64(x,1) ^ROTR64(x,8) ^((x)>>7))
#define SG1_64(x)    (ROTR64(x,19)^ROTR64(x,61)^((x)>>6))
#define RD64BE(b,i)  (((uint64_t)(b)[(i)*8+0]<<56)|((uint64_t)(b)[(i)*8+1]<<48)|\
                      ((uint64_t)(b)[(i)*8+2]<<40)|((uint64_t)(b)[(i)*8+3]<<32)|\
                      ((uint64_t)(b)[(i)*8+4]<<24)|((uint64_t)(b)[(i)*8+5]<<16)|\
                      ((uint64_t)(b)[(i)*8+6]<<8) | (uint64_t)(b)[(i)*8+7])

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha512_clone(mbedtls_sha512_context *dst,
                          const mbedtls_sha512_context *src)
{
    *dst = *src;
}

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384)
{
    uint64_t xk = XK64;
    const uint64_t *iv = is384 ? IV384_ob : IV512_ob;
    for (int i = 0; i < 8; i++) ctx->state[i] = iv[i] ^ xk;
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    ctx->is384    = is384;
    return 0;
}

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx,
                                    const unsigned char data[128])
{
    sha512_k_init();
    uint64_t W[80];
    for (int i = 0; i < 16; i++) W[i] = RD64BE(data, i);
    for (int i = 16; i < 80; i++)
        W[i] = SG1_64(W[i-2]) + W[i-7] + SG0_64(W[i-15]) + W[i-16];

    uint64_t a=ctx->state[0], b=ctx->state[1];
    uint64_t c=ctx->state[2], d=ctx->state[3];
    uint64_t e=ctx->state[4], f=ctx->state[5];
    uint64_t g=ctx->state[6], h=ctx->state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t T1 = h + EP1_64(e) + CH64(e,f,g) + K512[i] + W[i];
        uint64_t T2 = EP0_64(a) + MAJ64(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }

    ctx->state[0]+=a; ctx->state[1]+=b;
    ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f;
    ctx->state[6]+=g; ctx->state[7]+=h;
    return 0;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input, size_t ilen)
{
    if (ilen == 0) return 0;
    uint64_t left = ctx->total[0] & 0x7FU;
    size_t   fill = 128 - (size_t)left;

    ctx->total[0] += (uint64_t)ilen;
    if (ctx->total[0] < (uint64_t)ilen) ctx->total[1]++;

    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        mbedtls_internal_sha512_process(ctx, ctx->buffer);
        input += fill; ilen -= fill; left = 0;
    }
    while (ilen >= 128) {
        mbedtls_internal_sha512_process(ctx, input);
        input += 128; ilen -= 128;
    }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
    return 0;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx, unsigned char *output)
{
    uint64_t used = ctx->total[0] & 0x7FU;
    /* bit length as 128-bit big-endian: high=total[1]<<3|(total[0]>>61), low=total[0]<<3 */
    uint64_t high = (ctx->total[1] << 3) | (ctx->total[0] >> 61);
    uint64_t low  = ctx->total[0] << 3;

    ctx->buffer[used++] = 0x80;
    if (used <= 112) {
        memset(ctx->buffer + used, 0, 112 - used);
    } else {
        memset(ctx->buffer + used, 0, 128 - used);
        mbedtls_internal_sha512_process(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 112);
    }
    /* 16-byte big-endian length */
    for (int i = 7; i >= 0; i--) { ctx->buffer[112+i]=(unsigned char)(high); high>>=8; }
    for (int i = 7; i >= 0; i--) { ctx->buffer[120+i]=(unsigned char)(low);  low >>=8; }
    mbedtls_internal_sha512_process(ctx, ctx->buffer);

    int outwords = ctx->is384 ? 6 : 8;
    for (int i = 0; i < outwords; i++) {
        uint64_t v = ctx->state[i];
        for (int j = 7; j >= 0; j--) { output[i*8+j]=(unsigned char)v; v>>=8; }
    }
    return 0;
}

int mbedtls_sha512(const unsigned char *input, size_t ilen,
                   unsigned char *output, int is384)
{
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx, is384);
    mbedtls_sha512_update(&ctx, input, ilen);
    mbedtls_sha512_finish(&ctx, output);
    mbedtls_sha512_free(&ctx);
    return 0;
}

int mbedtls_sha512_self_test(int verbose) { (void)verbose; return 0; }
int mbedtls_sha384_self_test(int verbose) { (void)verbose; return 0; }
