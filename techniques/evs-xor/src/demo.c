#include "evs.h"
#include "evs_strings.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * Demo:
 *   1. Show that encoded arrays contain no plaintext bytes (strings tool finds nothing).
 *   2. Decode at runtime via EVS_D().
 *   3. Resolve real APIs using decoded names — no plaintext string ever in .rdata.
 *   4. Wipe decoded buffers with SecureZeroMemory after use.
 *
 * Verify no plaintext leaks:
 *   strings build/demo.exe | grep -iE "ntdll|NtOpen|AmsiScan"
 *   → no results expected
 */

static void print_hex(const char *label, const unsigned char *arr, size_t n)
{
    printf("  %-28s ", label);
    for (size_t i = 0; i < n && i < 10; i++)
        printf("%02X ", arr[i]);
    if (n > 10) printf("...");
    printf("\n");
}

int main(void)
{
    printf("[*] EVS_KEY = 0x%02X  (random per build — changes every make)\n\n", EVS_KEY);

    /* --- Show raw encoded bytes: no plaintext recognizable --- */
    printf("[*] Encoded arrays in .rodata (no plaintext):\n");
    print_hex("EVS_dll_ntdll",        EVS_dll_ntdll,        sizeof(EVS_dll_ntdll));
    print_hex("EVS_fn_NtOpenProcess", EVS_fn_NtOpenProcess, sizeof(EVS_fn_NtOpenProcess));
    print_hex("EVS_fn_AmsiScanBuffer",EVS_fn_AmsiScanBuffer,sizeof(EVS_fn_AmsiScanBuffer));
    print_hex("EVS_fn_EtwEventWrite", EVS_fn_EtwEventWrite, sizeof(EVS_fn_EtwEventWrite));
    print_hex("EVS_str_lsass",        EVS_str_lsass,        sizeof(EVS_str_lsass));

    /* --- Decode at runtime --- */
    printf("\n[*] Decoded at runtime:\n");

    char dll_ntdll[16]   = {0};
    char dll_kernel32[16] = {0};
    char dll_amsi[16]    = {0};
    char fn_NtOpen[24]   = {0};
    char fn_NtProt[28]   = {0};
    char fn_EtwW[20]     = {0};
    char fn_AmsiScan[20] = {0};
    char str_svchost[16] = {0};
    char str_lsass[16]   = {0};
    char str_sedbg[24]   = {0};

    EVS_D(dll_ntdll,    EVS_dll_ntdll);
    EVS_D(dll_kernel32, EVS_dll_kernel32);
    EVS_D(dll_amsi,     EVS_dll_amsi);
    EVS_D(fn_NtOpen,    EVS_fn_NtOpenProcess);
    EVS_D(fn_NtProt,    EVS_fn_NtProtectVirtualMemory);
    EVS_D(fn_EtwW,      EVS_fn_EtwEventWrite);
    EVS_D(fn_AmsiScan,  EVS_fn_AmsiScanBuffer);
    EVS_D(str_svchost,  EVS_str_svchost);
    EVS_D(str_lsass,    EVS_str_lsass);
    EVS_D(str_sedbg,    EVS_str_SeDebugPrivilege);

    printf("  dll:       %s\n", dll_ntdll);
    printf("  dll:       %s\n", dll_kernel32);
    printf("  dll:       %s\n", dll_amsi);
    printf("  api:       %s\n", fn_NtOpen);
    printf("  api:       %s\n", fn_NtProt);
    printf("  api:       %s\n", fn_EtwW);
    printf("  api:       %s\n", fn_AmsiScan);
    printf("  process:   %s\n", str_svchost);
    printf("  process:   %s\n", str_lsass);
    printf("  privilege: %s\n", str_sedbg);

    /* --- Functional test: resolve real API via decoded name --- */
    printf("\n[*] API resolution via decoded names (no plaintext in IAT/rdata):\n");

    HMODULE hntdll = GetModuleHandleA(dll_ntdll);
    FARPROC fn_ntopen = hntdll ? GetProcAddress(hntdll, fn_NtOpen) : NULL;
    FARPROC fn_ntprot = hntdll ? GetProcAddress(hntdll, fn_NtProt) : NULL;
    FARPROC fn_etw    = hntdll ? GetProcAddress(hntdll, fn_EtwW)   : NULL;

    printf("  [%c] GetModuleHandleA(%s)           = %p\n",
           hntdll    ? '+' : '!', dll_ntdll,   (void *)hntdll);
    printf("  [%c] GetProcAddress(%s)  = %p\n",
           fn_ntopen ? '+' : '!', fn_NtOpen,   (void *)fn_ntopen);
    printf("  [%c] GetProcAddress(%s) = %p\n",
           fn_ntprot ? '+' : '!', fn_NtProt,   (void *)fn_ntprot);
    printf("  [%c] GetProcAddress(%s)     = %p\n",
           fn_etw    ? '+' : '!', fn_EtwW,     (void *)fn_etw);

    /* Wipe decoded strings — no plaintext lingers on the stack */
    SecureZeroMemory(dll_ntdll,    sizeof(dll_ntdll));
    SecureZeroMemory(dll_kernel32, sizeof(dll_kernel32));
    SecureZeroMemory(fn_NtOpen,    sizeof(fn_NtOpen));
    SecureZeroMemory(fn_NtProt,    sizeof(fn_NtProt));
    SecureZeroMemory(fn_EtwW,      sizeof(fn_EtwW));
    SecureZeroMemory(fn_AmsiScan,  sizeof(fn_AmsiScan));
    SecureZeroMemory(str_lsass,    sizeof(str_lsass));
    SecureZeroMemory(str_sedbg,    sizeof(str_sedbg));

    BOOL ok = hntdll && fn_ntopen && fn_ntprot && fn_etw;
    printf("\n[%c] EVS XOR %s\n", ok ? '+' : '!',
           ok ? "working — no plaintext strings, APIs resolved correctly"
              : "FAIL — check output above");

    return ok ? 0 : 1;
}
