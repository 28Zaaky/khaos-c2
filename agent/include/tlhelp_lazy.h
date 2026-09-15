#ifndef TLHELP_LAZY_H
#define TLHELP_LAZY_H

/*
 * Lazy Toolhelp32 resolver — removes CreateToolhelp32Snapshot + Process32*
 * from the IAT. Include before tlhelp32.h in any TU that uses these APIs.
 */

#include <windows.h>
#include <tlhelp32.h>
#include "evs_strings.h"
#include "peb_walk.h"

typedef HANDLE (WINAPI *_tCTH_t) (DWORD, DWORD);
typedef BOOL   (WINAPI *_tP32F_t) (HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *_tP32FW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL   (WINAPI *_tP32N_t) (HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *_tP32NW_t)(HANDLE, LPPROCESSENTRY32W);
typedef BOOL   (WINAPI *_tT32F_t) (HANDLE, LPTHREADENTRY32);
typedef BOOL   (WINAPI *_tT32N_t) (HANDLE, LPTHREADENTRY32);

static _tCTH_t   _tl_cth  = NULL;
static _tP32F_t  _tl_p32f = NULL;
static _tP32FW_t _tl_p32fw = NULL;
static _tP32N_t  _tl_p32n = NULL;
static _tP32NW_t _tl_p32nw = NULL;
static _tT32F_t  _tl_t32f = NULL;
static _tT32N_t  _tl_t32n = NULL;

static void _tlhelp_init(void) {
    if (_tl_cth) return;
    char ks[14], fs[26];
    EVS_D(ks, EVS_dll_kernel32);
    HMODULE k = _peb_module(ks);
    SecureZeroMemory(ks, sizeof(ks));
    if (!k) return;
    EVS_D(fs, EVS_fn_CreateToolhelp32Snapshot);
    _tl_cth   = (_tCTH_t) (void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
    EVS_D(fs, EVS_fn_Process32First);
    _tl_p32f  = (_tP32F_t)(void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
    EVS_D(fs, EVS_fn_Process32FirstW);
    _tl_p32fw = (_tP32FW_t)(void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
    EVS_D(fs, EVS_fn_Process32Next);
    _tl_p32n  = (_tP32N_t)(void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
    EVS_D(fs, EVS_fn_Process32NextW);
    _tl_p32nw = (_tP32NW_t)(void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
    EVS_D(fs, EVS_fn_Thread32First);
    _tl_t32f  = (_tT32F_t)(void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
    EVS_D(fs, EVS_fn_Thread32Next);
    _tl_t32n  = (_tT32N_t)(void*)GetProcAddress(k, fs); SecureZeroMemory(fs, sizeof(fs));
}

#define CreateToolhelp32Snapshot(f,p)  (_tlhelp_init(), _tl_cth  ? _tl_cth(f,p)  : INVALID_HANDLE_VALUE)
#define Process32First(h,pe)           (_tl_p32f  ? _tl_p32f(h,pe)   : FALSE)
#define Process32FirstW(h,pe)          (_tl_p32fw ? _tl_p32fw(h,pe)  : FALSE)
#define Process32Next(h,pe)            (_tl_p32n  ? _tl_p32n(h,pe)   : FALSE)
#define Process32NextW(h,pe)           (_tl_p32nw ? _tl_p32nw(h,pe)  : FALSE)
#define Thread32First(h,te)            (_tl_t32f  ? _tl_t32f(h,te)   : FALSE)
#define Thread32Next(h,te)             (_tl_t32n  ? _tl_t32n(h,te)   : FALSE)

#endif /* TLHELP_LAZY_H */
