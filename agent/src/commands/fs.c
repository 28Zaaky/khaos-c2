/*
 * fs.c — filesystem commands: ls, mkdir, rm, cp, mv
 */
#include "commands.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* internal helpers */

static void _ftime_str(const FILETIME *ft, char *buf, size_t sz)
{
    SYSTEMTIME st;
    FILETIME   local;
    FileTimeToLocalFileTime(ft, &local);
    FileTimeToSystemTime(&local, &st);
    snprintf(buf, sz, "%04u-%02u-%02u %02u:%02u",
             (unsigned)st.wYear, (unsigned)st.wMonth,
             (unsigned)st.wDay,  (unsigned)st.wHour,
             (unsigned)st.wMinute);
}

/* return 1 if path is an existing directory */
static int _is_dir(const char *path)
{
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES) &&
           (attr & FILE_ATTRIBUTE_DIRECTORY);
}

/* list directory contents */

int cmd_ls(const char *path, char *output_buf, size_t output_size)
{
    char pattern[MAX_PATH];

    if (!path || !path[0])
        path = ".";

    /* append \* if path is a directory with no wildcard */
    if (!strchr(path, '*') && !strchr(path, '?') && _is_dir(path)) {
        size_t plen = strlen(path);
        if (plen + 3 >= sizeof(pattern)) {
            snprintf(output_buf, output_size, "[ls] path too long\n");
            return -1;
        }
        memcpy(pattern, path, plen);
        pattern[plen]   = '\\';
        pattern[plen+1] = '*';
        pattern[plen+2] = '\0';
    } else {
        strncpy(pattern, path, sizeof(pattern) - 1);
        pattern[sizeof(pattern) - 1] = '\0';
    }

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        snprintf(output_buf, output_size,
                 "[ls] %s: %lu\n", path, GetLastError());
        return -1;
    }

    /* column header */
    size_t pos = 0;
    int n = snprintf(output_buf + pos, output_size - pos,
                     "%-1s  %-16s  %12s  %s\n",
                     "T", "Date modified", "Size", "Name");
    if (n > 0) pos += (size_t)n;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;

        int   is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        char  date[32];
        _ftime_str(&fd.ftLastWriteTime, date, sizeof(date));

        ULONGLONG size_bytes = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

        if (is_dir)
            n = snprintf(output_buf + pos, output_size - pos,
                         "d  %-16s  %12s  %s\n",
                         date, "<DIR>", fd.cFileName);
        else
            n = snprintf(output_buf + pos, output_size - pos,
                         "f  %-16s  %12llu  %s\n",
                         date, size_bytes, fd.cFileName);

        if (n > 0 && (size_t)n < output_size - pos)
            pos += (size_t)n;
        else
            break; /* buffer full */

    } while (FindNextFileA(h, &fd));

    FindClose(h);
    return 0;
}

/* create a directory */

int cmd_mkdir(const char *path, char *output_buf, size_t output_size)
{
    if (!path || !path[0]) {
        snprintf(output_buf, output_size, "[mkdir] usage: mkdir <path>\n");
        return -1;
    }
    if (CreateDirectoryA(path, NULL)) {
        snprintf(output_buf, output_size, "[mkdir] created: %s\n", path);
        return 0;
    }
    DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS) {
        snprintf(output_buf, output_size, "[mkdir] already exists: %s\n", path);
        return 0;
    }
    snprintf(output_buf, output_size,
             "[mkdir] failed: %s  err=%lu\n", path, err);
    return -1;
}

/* delete a file or empty directory */

int cmd_rm(const char *path, char *output_buf, size_t output_size)
{
    if (!path || !path[0]) {
        snprintf(output_buf, output_size, "[rm] usage: rm <path>\n");
        return -1;
    }
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        snprintf(output_buf, output_size,
                 "[rm] not found: %s\n", path);
        return -1;
    }

    BOOL ok;
    if (attr & FILE_ATTRIBUTE_DIRECTORY)
        ok = RemoveDirectoryA(path);
    else
        ok = DeleteFileA(path);

    if (ok) {
        snprintf(output_buf, output_size, "[rm] deleted: %s\n", path);
        return 0;
    }
    snprintf(output_buf, output_size,
             "[rm] failed: %s  err=%lu\n", path, GetLastError());
    return -1;
}

/* ---- cp ---- */

int cmd_cp(const char *src, const char *dst, char *output_buf, size_t output_size)
{
    if (!src || !src[0] || !dst || !dst[0]) {
        snprintf(output_buf, output_size, "[cp] usage: cp <src> <dst>\n");
        return -1;
    }
    if (CopyFileA(src, dst, FALSE)) {
        snprintf(output_buf, output_size, "[cp] %s -> %s\n", src, dst);
        return 0;
    }
    snprintf(output_buf, output_size,
             "[cp] failed: %s -> %s  err=%lu\n", src, dst, GetLastError());
    return -1;
}

/* ---- mv ---- */

int cmd_mv(const char *src, const char *dst, char *output_buf, size_t output_size)
{
    if (!src || !src[0] || !dst || !dst[0]) {
        snprintf(output_buf, output_size, "[mv] usage: mv <src> <dst>\n");
        return -1;
    }
    if (MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        snprintf(output_buf, output_size, "[mv] %s -> %s\n", src, dst);
        return 0;
    }
    snprintf(output_buf, output_size,
             "[mv] failed: %s -> %s  err=%lu\n", src, dst, GetLastError());
    return -1;
}
