#ifdef _REFLECTIVE_DLL

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdint.h>

/* Silence MinGW warning about DllMain not being declared */
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);

/* full LDR_DATA_TABLE_ENTRY layout, MinGW winternl.h only exposes FullDllName */
typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY;

typedef struct _MY_PEB_LDR {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} MY_PEB_LDR;

typedef struct _MY_PEB {
    BYTE       Reserved[2];
    BYTE       BeingDebugged;
    BYTE       Reserved2[1];
    PVOID      Reserved3[2];
    MY_PEB_LDR *Ldr;
} MY_PEB;

typedef HMODULE  (WINAPI *pLoadLibraryA_t)(LPCSTR);
typedef FARPROC  (WINAPI *pGetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID   (WINAPI *pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (WINAPI *pFlushInstructionCache_t)(HANDLE, LPCVOID, SIZE_T);
typedef BOOL     (WINAPI *pVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE   (WINAPI *pGetCurrentProcess_t)(void);
typedef BOOL     (WINAPI *pDllMain_t)(HINSTANCE, DWORD, LPVOID);

static int _eqstr(const char *a, const char *b)
{
    while (*a && *b && (*a | 0x20) == (*b | 0x20)) { a++; b++; }
    return (*a == '\0' && *b == '\0');
}

static int _weq12(const WCHAR *w, const char *s)
{
    for (int i = 0; i < 12; i++) {
        if (!w[i] && !s[i]) return 1;
        if (!w[i] || !s[i]) return 0;
        if ((w[i] | 0x20) != (s[i] | 0x20)) return 0;
    }
    return 1;
}

/* find kernel32 base via PEB walk */

static ULONG_PTR _find_kernel32(void)
{
#ifdef _WIN64
    MY_PEB *peb = (MY_PEB *)__readgsqword(0x60);
#else
    MY_PEB *peb = (MY_PEB *)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur  = head->Flink;
    while (cur != head) {
        MY_LDR_ENTRY *e = CONTAINING_RECORD(cur, MY_LDR_ENTRY, InMemoryOrderLinks);
        if (e->BaseDllName.Length >= 24 &&
            _weq12(e->BaseDllName.Buffer, "kernel32.dll"))
            return (ULONG_PTR)e->DllBase;
        cur = cur->Flink;
    }
    return 0;
}

/* find export by name via EAT walk */

static ULONG_PTR _get_proc(ULONG_PTR mod, const char *name)
{
    PIMAGE_DOS_HEADER       dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS       nt  = (PIMAGE_NT_HEADERS)(mod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD rva = nt->OptionalHeader
                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                   .VirtualAddress;
    if (!rva) return 0;
    exp = (PIMAGE_EXPORT_DIRECTORY)(mod + rva);

    DWORD *names = (DWORD *)(mod + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(mod + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(mod + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (_eqstr((char *)(mod + names[i]), name))
            return mod + funcs[ords[i]];
    }
    return 0;
}

/* find own PE base by scanning backwards from current IP */

static ULONG_PTR _find_own_base(void)
{
    ULONG_PTR ip = (ULONG_PTR)_find_own_base & ~0xFFFUL;
    for (int i = 0; i < 4096; i++, ip -= 0x1000) {
        if (*(WORD *)ip != IMAGE_DOS_SIGNATURE) continue;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ip;
        if ((ULONG_PTR)dos->e_lfanew > 0x400) continue;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ip + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE &&
            nt->OptionalHeader.SizeOfImage > 0)
            return ip;
    }
    return 0;
}

/* reflective loader entry point */

__declspec(dllexport)
ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{
    (void)lpParameter;

    /* 1. bootstrap: resolve needed kernel32 functions */
    ULONG_PTR k32 = _find_kernel32();
    if (!k32) return 0;

    pLoadLibraryA_t          fLoadLibraryA    = (pLoadLibraryA_t         )_get_proc(k32, "LoadLibraryA");
    pGetProcAddress_t        fGetProcAddress  = (pGetProcAddress_t       )_get_proc(k32, "GetProcAddress");
    pVirtualAlloc_t          fVirtualAlloc    = (pVirtualAlloc_t         )_get_proc(k32, "VirtualAlloc");
    pFlushInstructionCache_t fFlushIC         = (pFlushInstructionCache_t)_get_proc(k32, "FlushInstructionCache");
    pGetCurrentProcess_t     fGetCurrentProc  = (pGetCurrentProcess_t    )_get_proc(k32, "GetCurrentProcess");

    if (!fLoadLibraryA || !fGetProcAddress || !fVirtualAlloc) return 0;

    /* 2. find own raw PE base */
    ULONG_PTR src = _find_own_base();
    if (!src) return 0;

    PIMAGE_DOS_HEADER srcDos = (PIMAGE_DOS_HEADER)src;
    PIMAGE_NT_HEADERS srcNt  = (PIMAGE_NT_HEADERS)(src + srcDos->e_lfanew);
    DWORD imgSz = srcNt->OptionalHeader.SizeOfImage;
    DWORD hdrSz = srcNt->OptionalHeader.SizeOfHeaders;

    /* 3. allocate target image, try preferred base first */
    ULONG_PTR dst = (ULONG_PTR)fVirtualAlloc(
        (LPVOID)srcNt->OptionalHeader.ImageBase,
        imgSz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!dst)
        dst = (ULONG_PTR)fVirtualAlloc(
            NULL, imgSz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!dst) return 0;

    /* 4. copy PE headers */
    {
        uint8_t *s = (uint8_t *)src;
        uint8_t *d = (uint8_t *)dst;
        for (DWORD i = 0; i < hdrSz; i++) d[i] = s[i];
    }

    /* 5. copy sections */
    {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(srcNt);
        for (WORD i = 0; i < srcNt->FileHeader.NumberOfSections; i++, sec++) {
            uint8_t *secSrc = (uint8_t *)(src + sec->VirtualAddress);
            uint8_t *secDst = (uint8_t *)(dst + sec->VirtualAddress);
            DWORD sz = sec->SizeOfRawData ? sec->SizeOfRawData : sec->Misc.VirtualSize;
            for (DWORD j = 0; j < sz; j++) secDst[j] = secSrc[j];
        }
    }

    /* 6. apply base relocations */
    PIMAGE_NT_HEADERS dstNt = (PIMAGE_NT_HEADERS)(dst + ((PIMAGE_DOS_HEADER)dst)->e_lfanew);
    LONG_PTR delta = (LONG_PTR)(dst - srcNt->OptionalHeader.ImageBase);

    {
        DWORD rva = dstNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD sz  = dstNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (delta && rva && sz) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(dst + rva);
            while (reloc->VirtualAddress && reloc->SizeOfBlock) {
                ULONG_PTR page = dst + reloc->VirtualAddress;
                WORD *entry    = (WORD *)((uint8_t *)reloc + sizeof(IMAGE_BASE_RELOCATION));
                DWORD cnt      = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                for (DWORD i = 0; i < cnt; i++) {
                    int   type = entry[i] >> 12;
                    DWORD off  = entry[i] & 0x0FFF;
#ifdef _WIN64
                    if (type == IMAGE_REL_BASED_DIR64)
                        *(ULONG_PTR *)(page + off) += (ULONG_PTR)delta;
#endif
                    if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD *)(page + off) += (DWORD)delta;
                }
                reloc = (PIMAGE_BASE_RELOCATION)((uint8_t *)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* 7. resolve imports */
    {
        DWORD rva = dstNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (rva) {
            PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(dst + rva);
            for (; imp->Name; imp++) {
                char    *dllName = (char *)(dst + imp->Name);
                HMODULE  hLib   = fLoadLibraryA(dllName);
                if (!hLib) continue;
                IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA *)(dst + imp->FirstThunk);
                IMAGE_THUNK_DATA *ont = imp->OriginalFirstThunk
                    ? (IMAGE_THUNK_DATA *)(dst + imp->OriginalFirstThunk)
                    : iat;
                for (; ont->u1.AddressOfData; ont++, iat++) {
                    FARPROC proc;
                    if (IMAGE_SNAP_BY_ORDINAL(ont->u1.Ordinal))
                        proc = fGetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(ont->u1.Ordinal));
                    else {
                        PIMAGE_IMPORT_BY_NAME ibn =
                            (PIMAGE_IMPORT_BY_NAME)(dst + (DWORD)ont->u1.AddressOfData);
                        proc = fGetProcAddress(hLib, (LPCSTR)ibn->Name);
                    }
                    iat->u1.Function = (ULONG_PTR)proc;
                }
            }
        }
    }

    /* 8. flush instruction cache */
    if (fFlushIC && fGetCurrentProc)
        fFlushIC(fGetCurrentProc(), (LPVOID)dst, imgSz);

    /* 9. Call DllMain */
    pDllMain_t fDllMain = (pDllMain_t)(dst + dstNt->OptionalHeader.AddressOfEntryPoint);
    fDllMain((HINSTANCE)dst, DLL_PROCESS_ATTACH, NULL);

    return dst;
}
#endif /* _REFLECTIVE_DLL */
