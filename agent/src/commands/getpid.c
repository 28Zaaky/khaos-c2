#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

int cmd_getpid(const char *name, char *out, size_t sz)
{
    if (!name || !name[0]) {
        snprintf(out, sz, "[getpid] usage: getpid <process_name>\n");
        return -1;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        snprintf(out, sz, "[getpid] snapshot failed: %lu\n", GetLastError());
        return -1;
    }

    PROCESSENTRY32 pe = { sizeof(pe) };
    size_t off = 0;
    int found = 0;

    /* build name_exe: append .exe if not already present */
    char name_exe[MAX_PATH];
    strncpy(name_exe, name, sizeof(name_exe) - 5);
    name_exe[sizeof(name_exe) - 5] = '\0';
    size_t nlen = strlen(name_exe);
    if (nlen < 4 || _stricmp(name_exe + nlen - 4, ".exe") != 0)
        strcat(name_exe, ".exe");

    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, name) == 0 ||
            _stricmp(pe.szExeFile, name_exe) == 0) {
            int n = snprintf(out + off, sz - off, "%lu\t%s\n",
                             (unsigned long)pe.th32ProcessID, pe.szExeFile);
            if (n > 0) off += (size_t)n;
            found++;
        }
    } while (Process32Next(snap, &pe) && off < sz - 1);

    CloseHandle(snap);

    if (!found) {
        snprintf(out, sz, "[getpid] no process named '%s'\n", name);
        return -1;
    }
    return 0;
}
