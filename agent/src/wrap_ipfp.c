/*
 * wrap_ipfp.c — Remove IsProcessorFeaturePresent from IAT.
 *
 * MinGW's libgcc calls IsProcessorFeaturePresent for CPU feature detection.
 * Defining __imp_IsProcessorFeaturePresent locally prevents the linker from
 * pulling the import stub from libkernel32.a, eliminating the IAT entry.
 * The real function is resolved at runtime via EVS-encoded string.
 */

#include "peb_walk.h"
#include "evs_strings.h"
#include <windows.h>

typedef BOOL (WINAPI *_IPFP_t)(DWORD);

static BOOL WINAPI _ipfp_impl(DWORD Feature)
{
    static _IPFP_t fn = NULL;
    if (!fn) {
        char kn[14], fname[26];
        EVS_D(kn, EVS_dll_kernel32);
        HMODULE k = _peb_module(kn);
        SecureZeroMemory(kn, sizeof(kn));
        EVS_D(fname, EVS_fn_IsProcessorFeaturePresent);
        if (k) fn = (_IPFP_t)(void*)GetProcAddress(k, fname);
        SecureZeroMemory(fname, sizeof(fname));
    }
    return fn ? fn(Feature) : TRUE;
}

BOOL WINAPI __wrap_IsProcessorFeaturePresent(DWORD Feature)
{
    return _ipfp_impl(Feature);
}

_IPFP_t __imp_IsProcessorFeaturePresent = _ipfp_impl;
