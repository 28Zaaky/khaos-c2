#pragma once
#include <windows.h>

/*
 * ntdll_unhook()
 *
 * Restores the live ntdll.dll .text section from a fresh copy mapped
 * directly from disk using SEC_IMAGE (bypasses filesystem hooks).
 * Overwrites any userland inline hooks (e.g. EDR trampolines) with
 * clean bytes from the on-disk image.
 *
 * Returns 0 on success, -1 on failure.
 *
 * ntdll_patch_etw_ti()
 *
 * Patches EtwTiLogOpenProcess, EtwTiLogReadWriteVm, EtwTiLogDuplicateHandle
 * with a single RET byte via NtProtectVirtualMemory, silencing ETW-TI
 * telemetry for process open / memory read-write / handle dup events.
 *
 * Returns number of functions patched (0-3).
 */
int ntdll_unhook(void);
int ntdll_patch_etw_ti(void);
