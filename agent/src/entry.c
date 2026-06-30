#include <windows.h>
#include <bcrypt.h>
#include <errno.h>

/* Forward declaration — defined in main.c */
extern int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int);

void WinMainCRTStartup(void)
{
    int ret = WinMain(NULL, NULL, NULL, SW_SHOWDEFAULT);
    ExitProcess((UINT)ret);
}

/* Stubs for CRT functions that -nostartfiles leaves undefined */

/* atexit: called by libmingwex dtoa/snprintf internals; we ExitProcess so
 * registered handlers will never run — stub is safe. */
int atexit(void (*fn)(void)) { (void)fn; return 0; }

/* __main: called by some MinGW ctor chains; no C++ ctors in this binary. */
void __main(void) {}

/*
 * getntptimeofday — normally defined in libmingwex gettimeofday.o, which calls
 * GetModuleHandleA("kernel32") + GetProcAddress to probe GetSystemTimePreciseAsFileTime.
 * Our version uses GetSystemTimeAsFileTime directly (already in IAT) — eliminates
 * the GetModuleHandleA import that gettimeofday.o would add.
 */
#include <time.h>
int getntptimeofday(struct timespec *tp, const void *tz)
{
    (void)tz;
    if (tp) {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULONGLONG t = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        t -= 116444736000000000ULL; /* FILETIME to Unix epoch (100ns units) */
        tp->tv_sec  = (time_t)(t / 10000000ULL);
        tp->tv_nsec = (long)((t % 10000000ULL) * 100);
    }
    return 0;
}

/*
 * rand_s / __imp_rand_s stubs — prevent libmsvcrt.a(rand_s.o) from linking.
 * rand_s.o imports GetModuleHandleA+GetProcAddress to find RtlGenRandom.
 * libmingwex stack_chk_guard.o (pulled by mbedTLS) references __imp_rand_s.
 * Defining both here satisfies the reference without the GetModuleHandleA dep.
 */
static errno_t _rand_s_impl(unsigned int *r)
{
    if (!r) return EINVAL;
    BCryptGenRandom(NULL, (PUCHAR)r, sizeof(*r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return 0;
}
errno_t rand_s(unsigned int *r) { return _rand_s_impl(r); }
errno_t (*__imp_rand_s)(unsigned int *) = _rand_s_impl;

/*
 * _gmtime64_s stub — mbedTLS platform_util.c.obj calls _gmtime64_s which is
 * provided by libmsvcrt.a(_gmtime64_s.o), another GetModuleHandleA importer.
 * Stub with gmtime() (same semantics, no GetModuleHandleA).
 */
#include <time.h>
errno_t _gmtime64_s(struct tm *_Tm, const __int64 *_Time)
{
    if (!_Tm || !_Time) return EINVAL;
    time_t t = (time_t)*_Time;
    struct tm *r = gmtime(&t);
    if (!r) return EINVAL;
    *_Tm = *r;
    return 0;
}
errno_t (*__imp__gmtime64_s)(struct tm *, const __int64 *) = _gmtime64_s;

/* Override __imp_GetModuleHandleA — strong data symbol prevents IAT import.
 * Library callers (libpthread misc.o etc.) use result for optional feature
 * detection; returning NULL causes them to use built-in fallbacks. */
static HMODULE WINAPI _gmha_impl(LPCSTR n) { (void)n; return NULL; }
HMODULE (WINAPI *__imp_GetModuleHandleA)(LPCSTR) = _gmha_impl;
