#include "util.h"
#include <stdlib.h>

#ifndef HTTP_ONLY
#include <curl/curl.h>
#ifndef CURLSSLOPT_NATIVE_CA
#define CURLSSLOPT_NATIVE_CA (1<<4)
#endif
#endif /* HTTP_ONLY */

/* ---- User-Agent rotation ---- */

static const char *k_ua[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
};

#define UA_COUNT (sizeof(k_ua) / sizeof(k_ua[0]))

const char *random_ua(void)
{
    return k_ua[rand() % UA_COUNT];
}

#ifndef HTTP_ONLY
/* ---- JA3 hardening ---- */

void curl_apply_opsec(CURL *curl)
{
    /* TLS 1.3 ciphers — Chrome order */
    curl_easy_setopt(curl, CURLOPT_TLS13_CIPHERS,
        "TLS_AES_128_GCM_SHA256:"
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256");

    /* TLS 1.2 ciphers — Chrome order */
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:"
        "AES128-GCM-SHA256:"
        "AES256-GCM-SHA384:"
        "AES128-SHA:"
        "AES256-SHA");

    /* Windows native cert store — no curl-ca-bundle.crt on disk */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS,    (long)CURLSSLOPT_NATIVE_CA);
}
#endif /* HTTP_ONLY */
