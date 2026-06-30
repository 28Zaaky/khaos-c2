#pragma once
#include <windows.h>
#include <stdint.h>
#include <intrin.h>

/* Minimal LDR structures — offsets validated against Win10/11 x64 */

typedef struct { USHORT Len, MaxLen; PWSTR Buf; } _USTR;

typedef struct _LDRE {
    LIST_ENTRY LoadOrd;   /* 0x00 */
    LIST_ENTRY MemOrd;    /* 0x10 */
    LIST_ENTRY InitOrd;   /* 0x20 */
    PVOID      Base;      /* 0x30 */
    PVOID      EntryPt;   /* 0x38 */
    ULONG      ImgSz;     /* 0x40 */
    /* 4 bytes padding here (compiler-inserted) */
    _USTR      FullName;  /* 0x48 */
    _USTR      BaseName;  /* 0x58 */
} _LDRE;

typedef struct {
    ULONG      Len;          /* 0x00 */
    BOOLEAN    Init;         /* 0x04 */
    /* 3 bytes padding */
    PVOID      SsHandle;     /* 0x08 */
    LIST_ENTRY LoadOrdList;  /* 0x10 */
    LIST_ENTRY MemOrdList;   /* 0x20 */
} _LDRD;

/* Find loaded module by name (case-insensitive ASCII) */
static inline HMODULE _peb_mod(const wchar_t *name) {
    ULONG_PTR peb;
#ifdef _WIN64
    peb = __readgsqword(0x60);
#else
    peb = __readfsdword(0x30);
#endif
    _LDRD *ldr = *(_LDRD **)(peb + 0x18);
    LIST_ENTRY *h = &ldr->MemOrdList, *c = h->Flink;
    while (c != h) {
        _LDRE *e = CONTAINING_RECORD(c, _LDRE, MemOrd);
        if (e->BaseName.Buf) {
            const wchar_t *a = e->BaseName.Buf, *b = name;
            int ok = 1;
            while (*a && *b) {
                wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (*a | 0x20) : *a;
                wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (*b | 0x20) : *b;
                if (ca != cb) { ok = 0; break; }
                a++; b++;
            }
            if (ok && !*a && !*b)
                return (HMODULE)e->Base;
        }
        c = c->Flink;
    }
    return NULL;
}

/* Resolve export by name from a loaded module */
static inline FARPROC _peb_proc(HMODULE mod, const char *name) {
    uint8_t *b = (uint8_t *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)b;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(b + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *d =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d->VirtualAddress) return NULL;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(b + d->VirtualAddress);
    DWORD *nms = (DWORD *)(b + exp->AddressOfNames);
    WORD  *ord = (WORD  *)(b + exp->AddressOfNameOrdinals);
    DWORD *fns = (DWORD *)(b + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *n = (const char *)(b + nms[i]), *p = name;
        while (*n && *p && *n == *p) { n++; p++; }
        if (!*n && !*p)
            return (FARPROC)(b + fns[ord[i]]);
    }
    return NULL;
}
