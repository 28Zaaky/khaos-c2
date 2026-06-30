// Example loader for the reflective DLL.
// It reads the raw DLL from disk, copies it into RWX memory,
// finds ReflectiveLoader in the raw image, and calls it.

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// convert a raw RVA to a raw file offset
static DWORD rva_to_off(const uint8_t *buf, const IMAGE_NT_HEADERS *nt, DWORD rva)
{
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < nsec; i++)
    {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
    }
    return 0;
    (void)buf;
}

// find an export in the raw DLL buffer and return the function address in memory
static LPVOID find_export_in_raw(const uint8_t *buf, size_t bufsz,
                                 const uint8_t *mem, const char *name)
{
    if (bufsz < sizeof(IMAGE_DOS_HEADER))
        return NULL;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    DWORD expRva = nt->OptionalHeader
                       .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                       .VirtualAddress;
    if (!expRva)
        return NULL;

    DWORD expOff = rva_to_off(buf, nt, expRva);
    if (!expOff)
        return NULL;

    const IMAGE_EXPORT_DIRECTORY *exp = (const IMAGE_EXPORT_DIRECTORY *)(buf + expOff);

    DWORD namesOff = rva_to_off(buf, nt, exp->AddressOfNames);
    DWORD ordsOff = rva_to_off(buf, nt, exp->AddressOfNameOrdinals);
    DWORD funcsOff = rva_to_off(buf, nt, exp->AddressOfFunctions);
    if (!namesOff || !ordsOff || !funcsOff)
        return NULL;

    DWORD *names = (DWORD *)(buf + namesOff);
    WORD *ords = (WORD *)(buf + ordsOff);
    DWORD *funcs = (DWORD *)(buf + funcsOff);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        DWORD nameOff = rva_to_off(buf, nt, names[i]);
        if (!nameOff)
            continue;
        const char *n = (const char *)(buf + nameOff);
        if (strcmp(n, name) == 0)
        {
            DWORD fnRva = funcs[ords[i]];
            DWORD fnOff = rva_to_off(buf, nt, fnRva);
            return fnOff ? (LPVOID)(mem + fnOff) : NULL;
        }
    }
    return NULL;
}

// read the raw DLL file into memory
static uint8_t *read_file(const char *path, size_t *out_size)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return NULL;

    DWORD sz = GetFileSize(hf, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0)
    {
        CloseHandle(hf);
        return NULL;
    }

    uint8_t *b = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!b)
    {
        CloseHandle(hf);
        return NULL;
    }

    DWORD rd;
    if (!ReadFile(hf, b, sz, &rd, NULL) || rd != sz)
    {
        HeapFree(GetProcessHeap(), 0, b);
        CloseHandle(hf);
        return NULL;
    }
    CloseHandle(hf);
    *out_size = sz;
    return b;
}

int main(int argc, char **argv)
{
    char dll_path[MAX_PATH];

    if (argc > 1)
    {
        strncpy(dll_path, argv[1], MAX_PATH - 1);
        dll_path[MAX_PATH - 1] = '\0';
    }
    else
    {
        char exe_path[MAX_PATH];
        DWORD len = GetModuleFileNameA(NULL, exe_path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
            return 1;

        // build default path in the same directory as loader.exe
        char *sep = strrchr(exe_path, '\\');
        if (sep)
            *(sep + 1) = '\0';
        else
            exe_path[0] = '\0';

        snprintf(dll_path, MAX_PATH, "%sexample.dll", exe_path);
    }

    printf("[*] reading %s\n", dll_path);
    size_t sz = 0;
    uint8_t *buf = read_file(dll_path, &sz);
    if (!buf)
    {
        fprintf(stderr, "[!] read failed (error %lu)\n", GetLastError());
        return 1;
    }
    printf("[+] %zu bytes read\n", sz);

    // allocate RWX memory for the raw DLL image
    uint8_t *mem = (uint8_t *)VirtualAlloc(NULL, sz,
                                           MEM_RESERVE | MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE);
    if (!mem)
    {
        fprintf(stderr, "[!] VirtualAlloc failed (%lu)\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, buf);
        return 1;
    }
    memcpy(mem, buf, sz);
    printf("[+] raw DLL at %p (RWX, %zu bytes)\n", (void *)mem, sz);

    // locate ReflectiveLoader in the raw image and call it
    typedef ULONG_PTR(WINAPI *RL_t)(LPVOID);
    RL_t fn = (RL_t)find_export_in_raw(buf, sz, mem, "ReflectiveLoader");
    HeapFree(GetProcessHeap(), 0, buf);

    if (!fn)
    {
        fprintf(stderr, "[!] ReflectiveLoader export not found\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] ReflectiveLoader at %p\n", (void *)fn);

    printf("[*] calling ReflectiveLoader...\n");
    ULONG_PTR base = fn(mem);
    if (!base)
    {
        fprintf(stderr, "[!] ReflectiveLoader returned 0\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }
    printf("[+] DLL mapped at 0x%llx\n", (unsigned long long)base);

    // read debug telemetry written into mem[] by ReflectiveLoader before section copy
    typedef struct { uint16_t ssn_alloc; uint16_t ssn_protect; uint32_t alloc_method; } RL_DBG;
    RL_DBG *dbg = (RL_DBG *)find_export_in_raw(mem, sz, mem, "_rl_dbg");
    if (dbg)
    {
        const char *method = dbg->alloc_method == 1 ? "Hell's Gate (NtAllocateVirtualMemory syscall)"
                           : dbg->alloc_method == 2 ? "VirtualAlloc (fallback)"
                           :                          "unknown";
        printf("[*] alloc method : %s\n", method);
        if (dbg->ssn_alloc != 0xFFFF)
            printf("[*] ssn NtAllocateVirtualMemory  : 0x%04x\n", dbg->ssn_alloc);
        else
            printf("[*] ssn NtAllocateVirtualMemory  : not found (ntdll hooked?)\n");
        if (dbg->ssn_protect != 0xFFFF)
            printf("[*] ssn NtProtectVirtualMemory   : 0x%04x\n", dbg->ssn_protect);
        else
            printf("[*] ssn NtProtectVirtualMemory   : not found (ntdll hooked?)\n");
    }

    // check if the marker file was created
    char marker[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("TEMP", marker, MAX_PATH - 20);
    if (n && n < MAX_PATH - 20)
    {
        // DllMain marker
        const char *s = "\\reflect_demo.txt";
        int i = 0;
        for (i = 0; s[i]; i++) marker[n + i] = s[i];
        marker[n + i] = '\0';
        printf("[%c] DllMain marker  : %s\n",
               GetFileAttributesA(marker) != INVALID_FILE_ATTRIBUTES ? '+' : '!', marker);

        // TLS callback marker
        s = "\\reflect_tls.txt";
        for (i = 0; s[i]; i++) marker[n + i] = s[i];
        marker[n + i] = '\0';
        printf("[%c] TLS callback    : %s\n",
               GetFileAttributesA(marker) != INVALID_FILE_ATTRIBUTES ? '+' : '!', marker);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}