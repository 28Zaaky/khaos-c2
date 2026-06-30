// debug_loader.c: a verbose step-by-step version of ReflectiveLoader.
// This program runs with normal IAT resolution and prints each stage.

#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// case-insensitive compare for ascii strings
static int _eq(const char *a, const char *b)
{
    while (*a && *b && (*a | 0x20) == (*b | 0x20))
    {
        a++;
        b++;
    }
    return !*a && !*b;
}

// compare wide string and ascii string for n characters
static int _weq(const WCHAR *w, const char *s, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (!w[i] && !s[i])
            return 1;
        if (!w[i] || !s[i])
            return 0;
        if ((w[i] | 0x20) != ((unsigned char)s[i] | 0x20))
            return 0;
    }
    return 1;
}

static uint8_t *buf = NULL;
static size_t bufsz = 0;

// convert a raw RVA into a file offset inside the raw buffer
static DWORD rva2off(DWORD rva)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
    {
        if (rva >= s->VirtualAddress && rva < s->VirtualAddress + s->SizeOfRawData)
            return rva - s->VirtualAddress + s->PointerToRawData;
    }
    return 0;
}

// read an entire file into memory
static uint8_t *read_file(const char *path, size_t *out)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;

    DWORD sz = GetFileSize(h, NULL);
    uint8_t *b = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, sz);
    DWORD rd;
    ReadFile(h, b, sz, &rd, NULL);
    CloseHandle(h);
    *out = sz;
    return b;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "build\\example.dll";

    printf("[*] reading %s\n", path);
    buf = read_file(path, &bufsz);
    if (!buf)
    {
        fprintf(stderr, "[!] read failed %lu\n", GetLastError());
        return 1;
    }
    printf("[+] %zu bytes\n", bufsz);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    printf("[+] ImageBase=0x%llx SizeOfImage=0x%lx SizeOfHeaders=0x%lx\n",
           (unsigned long long)nt->OptionalHeader.ImageBase,
           (unsigned long)nt->OptionalHeader.SizeOfImage,
           (unsigned long)nt->OptionalHeader.SizeOfHeaders);

    // STEP 1: find ReflectiveLoader export in the raw file
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD expOff = rva2off(expRva);
    if (!expOff)
    {
        fprintf(stderr, "[!] no export dir\n");
        return 1;
    }

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(buf + expOff);
    DWORD *names = (DWORD *)(buf + rva2off(exp->AddressOfNames));
    WORD *ords = (WORD *)(buf + rva2off(exp->AddressOfNameOrdinals));
    DWORD *funcs = (DWORD *)(buf + rva2off(exp->AddressOfFunctions));

    DWORD rl_rva = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        const char *n = (const char *)(buf + rva2off(names[i]));
        if (strcmp(n, "ReflectiveLoader") == 0)
        {
            rl_rva = funcs[ords[i]];
            break;
        }
    }

    DWORD rl_off = rva2off(rl_rva);
    printf("[+] ReflectiveLoader: RVA=0x%lx rawOff=0x%lx\n", (unsigned long)rl_rva, (unsigned long)rl_off);

    // STEP 2: copy the raw DLL into RWX memory
    uint8_t *mem = (uint8_t *)VirtualAlloc(NULL, bufsz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, buf, bufsz);
    printf("[+] raw copy at %p\n", (void *)mem);

    // STEP 3: print section info
    printf("[*] sections:\n");
    IMAGE_NT_HEADERS *mnt = (IMAGE_NT_HEADERS *)(mem + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(mnt);
    for (WORD i = 0; i < mnt->FileHeader.NumberOfSections; i++, sec++)
    {
        char name[9] = {0};
        memcpy(name, sec->Name, 8);
        printf("    [%d] %-8s VA=0x%08lx raw=0x%08lx sz=0x%lx\n", i, name,
               (unsigned long)sec->VirtualAddress,
               (unsigned long)sec->PointerToRawData,
               (unsigned long)sec->SizeOfRawData);
    }

    // STEP 4: simulate finding the module base from the function address
    ULONG_PTR fn_addr = (ULONG_PTR)(mem + rl_off);
    ULONG_PTR scan = fn_addr & ~0xFFFUL;
    int found_mz = 0;
    ULONG_PTR found_base = 0;
    for (int i = 0; i < 4096; i++, scan -= 0x1000)
    {
        if (!IsBadReadPtr((void *)scan, 2) && *(WORD *)scan == 0x5A4D)
        {
            IMAGE_DOS_HEADER *d = (IMAGE_DOS_HEADER *)scan;
            if ((ULONG_PTR)d->e_lfanew <= 0x400)
            {
                IMAGE_NT_HEADERS *n2 = (IMAGE_NT_HEADERS *)(scan + d->e_lfanew);
                if (n2->Signature == 0x00004550 && n2->OptionalHeader.SizeOfImage > 0)
                {
                    found_base = scan;
                    found_mz = 1;
                    break;
                }
            }
        }
    }
    printf("[+] _rl_find_own_base scan: found=%d base=0x%llx expected=0x%llx %s\n",
           found_mz,
           (unsigned long long)found_base,
           (unsigned long long)(uintptr_t)mem,
           (found_base == (ULONG_PTR)mem) ? "OK" : "MISMATCH");

    // STEP 5: allocate memory for the mapped image
    DWORD imgSz = nt->OptionalHeader.SizeOfImage;
    uint8_t *dst = (uint8_t *)VirtualAlloc(NULL, imgSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] dst alloc: %p (0x%lx bytes)\n", (void *)dst, (unsigned long)imgSz);

    // STEP 6: copy headers from the raw file to the mapped image
    memcpy(dst, mem, nt->OptionalHeader.SizeOfHeaders);
    printf("[+] headers copied\n");

    // STEP 7: copy each section from raw file to its virtual address
    IMAGE_NT_HEADERS *snt = (IMAGE_NT_HEADERS *)(mem + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(snt);
    for (WORD i = 0; i < snt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!sec->PointerToRawData || !sec->SizeOfRawData)
            continue;
        uint8_t *ss = mem + sec->PointerToRawData;
        uint8_t *dd = dst + sec->VirtualAddress;
        if (sec->VirtualAddress + sec->SizeOfRawData > imgSz)
        {
            printf("[!] sec[%d] out of bounds!\n", i);
            continue;
        }
        memcpy(dd, ss, sec->SizeOfRawData);
    }
    printf("[+] sections copied\n");

    // STEP 8: apply relocations if needed
    IMAGE_NT_HEADERS *dnt = (IMAGE_NT_HEADERS *)(dst + dos->e_lfanew);
    LONG_PTR delta = (LONG_PTR)((uintptr_t)dst - nt->OptionalHeader.ImageBase);
    printf("[*] reloc delta=0x%llx\n", (long long)delta);
    {
        DWORD rv = dnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD rs = dnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        printf("[*] reloc dir RVA=0x%lx sz=0x%lx\n", (unsigned long)rv, (unsigned long)rs);
        if (delta && rv && rs)
        {
            IMAGE_BASE_RELOCATION *r = (IMAGE_BASE_RELOCATION *)(dst + rv);
            int cnt = 0;
            while (r->VirtualAddress && r->SizeOfBlock)
            {
                ULONG_PTR pg = (ULONG_PTR)dst + r->VirtualAddress;
                WORD *e = (WORD *)((uint8_t *)r + sizeof(*r));
                DWORD n = (r->SizeOfBlock - sizeof(*r)) / sizeof(WORD);
                for (DWORD j = 0; j < n; j++)
                {
                    int t = e[j] >> 12;
                    DWORD o = e[j] & 0xFFF;
                    if (t == IMAGE_REL_BASED_DIR64)
                    {
                        *(ULONG_PTR *)(pg + o) += (ULONG_PTR)delta;
                        cnt++;
                    }
                    if (t == IMAGE_REL_BASED_HIGHLOW)
                    {
                        *(DWORD *)(pg + o) += (DWORD)delta;
                        cnt++;
                    }
                }
                r = (IMAGE_BASE_RELOCATION *)((uint8_t *)r + r->SizeOfBlock);
            }
            printf("[+] %d relocations applied\n", cnt);
        }
    }

    // STEP 9: resolve imports for the mapped image
    {
        DWORD iv = dnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        printf("[*] import dir RVA=0x%lx\n", (unsigned long)iv);
        if (iv)
        {
            IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(dst + iv);
            for (; imp->Name; imp++)
            {
                char *dn = (char *)(dst + imp->Name);
                HMODULE h = LoadLibraryA(dn);
                printf("  [%s] -> %p\n", dn, (void *)h);
                if (!h)
                    continue;
                IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA *)(dst + imp->FirstThunk);
                IMAGE_THUNK_DATA *ont = imp->OriginalFirstThunk ? (IMAGE_THUNK_DATA *)(dst + imp->OriginalFirstThunk) : iat;
                for (; ont->u1.AddressOfData; ont++, iat++)
                {
                    FARPROC p;
                    if (IMAGE_SNAP_BY_ORDINAL(ont->u1.Ordinal))
                        p = GetProcAddress(h, (LPCSTR)IMAGE_ORDINAL(ont->u1.Ordinal));
                    else
                    {
                        IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME *)(dst + (DWORD)ont->u1.AddressOfData);
                        p = GetProcAddress(h, (LPCSTR)ibn->Name);
                    }
                    iat->u1.Function = (ULONG_PTR)p;
                }
            }
        }
    }
    printf("[+] imports resolved\n");

    // STEP 10: flush cache and call the DLL entry point
    FlushInstructionCache(GetCurrentProcess(), dst, imgSz);
    typedef BOOL(WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
    DllMain_t fm = (DllMain_t)(dst + dnt->OptionalHeader.AddressOfEntryPoint);
    printf("[*] calling DllMain at %p (OEP RVA=0x%lx)\n", (void *)fm,
           (unsigned long)dnt->OptionalHeader.AddressOfEntryPoint);
    BOOL ok = fm((HINSTANCE)dst, DLL_PROCESS_ATTACH, NULL);
    printf("[+] DllMain returned %d\n", (int)ok);
}

    /* verify marker */
    char marker[MAX_PATH];
    DWORD n=GetEnvironmentVariableA("TEMP",marker,MAX_PATH-20);
    if(n){const char*s="\\reflect_demo.txt";for(int i=0;s[i];i++)marker[n++]=s[i];marker[n]=0;
        if(GetFileAttributesA(marker)!=INVALID_FILE_ATTRIBUTES)printf("[+] marker: %s\n",marker);
        else printf("[-] no marker file\n");}

    VirtualFree(dst,0,MEM_RELEASE);
    VirtualFree(mem,0,MEM_RELEASE);
    HeapFree(GetProcessHeap(),0,buf);
    return 0;
}
