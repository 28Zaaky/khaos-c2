#ifndef PEB_WALK_H
#define PEB_WALK_H

#include <windows.h>
#include <string.h>

/*
 * _peb_module(name_lower) — get module base via PEB InMemoryOrderModuleList.
 * No imports: no GetModuleHandleA in IAT when used exclusively.
 * name_lower must be lowercase (e.g. "kernel32.dll").
 *
 * Inline LDR_DATA_TABLE_ENTRY (x64 offsets — no winternl.h dependency):
 *   +0x00  InLoadOrderLinks        (LIST_ENTRY, 16 B)
 *   +0x10  InMemoryOrderLinks      (LIST_ENTRY, 16 B)  ← list head flinks here
 *   +0x20  InInitOrderLinks        (LIST_ENTRY, 16 B)
 *   +0x30  DllBase                 (PVOID,       8 B)
 *   +0x38  EntryPoint              (PVOID,       8 B)
 *   +0x40  SizeOfImage             (ULONG,       4 B)
 *   +0x44  _pad1                   (ULONG,       4 B)
 *   +0x48  FullDllName.Length      (USHORT,      2 B)
 *   +0x4A  FullDllName.MaxLength   (USHORT,      2 B)
 *   +0x4C  _pad2                   (USHORT[2],   4 B)
 *   +0x50  FullDllName.Buffer      (WCHAR*,      8 B)
 *   +0x58  BaseDllName.Length      (USHORT,      2 B)
 *   +0x5A  BaseDllName.MaxLength   (USHORT,      2 B)
 *   +0x5C  _pad3                   (USHORT[2],   4 B)
 *   +0x60  BaseDllName.Buffer      (WCHAR*,      8 B)
 */
static inline HMODULE _peb_module(const char *name_lower)
{
#ifdef _WIN64
    typedef struct {
        LIST_ENTRY _load;
        LIST_ENTRY _mem;
        LIST_ENTRY _init;
        void      *DllBase;
        void      *EntryPoint;
        ULONG      SizeOfImage;
        ULONG      _pad1;
        USHORT     FullLen;
        USHORT     FullMaxLen;
        USHORT     _pad2[2];
        WCHAR     *FullBuf;
        USHORT     BaseLen;
        USHORT     BaseMaxLen;
        USHORT     _pad3[2];
        WCHAR     *BaseBuf;
    } _ldr_e;

    BYTE *peb  = (BYTE *)__readgsqword(0x60);
    BYTE *ldr  = *(BYTE **)(peb + 0x18);
    LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x20); /* InMemoryOrderModuleList */
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        /* e points to _mem (+0x10 from struct base) */
        _ldr_e *en = (_ldr_e *)((BYTE *)e - 0x10);
        if (!en->BaseBuf || en->BaseLen == 0) continue;
        char tmp[64]; int n = en->BaseLen / 2;
        if (n >= 64) continue;
        for (int i = 0; i < n; i++) {
            WCHAR c = en->BaseBuf[i];
            tmp[i] = (char)((c >= L'A' && c <= L'Z') ? c + 32 : c);
        }
        tmp[n] = '\0';
        if (strcmp(tmp, name_lower) == 0) return (HMODULE)en->DllBase;
    }
#else
    (void)name_lower;
#endif
    return NULL;
}

/*
 * _peb_self_base() — own image base via PEB.ImageBaseAddress (offset 0x10 x64).
 * Replaces GetModuleHandleA(NULL) — removes it from IAT.
 */
static inline void *_peb_self_base(void)
{
#ifdef _WIN64
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    return *(void **)(peb + 0x10);
#else
    return NULL;
#endif
}

#endif /* PEB_WALK_H */
