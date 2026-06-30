#include "inject.h"

/* Lean-build stubs — inject capability excluded via -DLEAN.
 * inject_nt_open_process is still called by getsystem/spawn/token;
 * returning NULL causes those callers to fail gracefully. */

DWORD  inject_find_target(void)                                              { return 0; }
HANDLE inject_nt_open_process(DWORD pid, DWORD access)                       { (void)pid; (void)access; return NULL; }
int    inject_remote(DWORD pid, const BYTE *sc, SIZE_T n)                    { (void)pid; (void)sc; (void)n; return -1; }
int    inject_thread_hijack(DWORD pid, const BYTE *sc, SIZE_T n)             { (void)pid; (void)sc; (void)n; return -1; }
int    inject_earlybird(const BYTE *sc, SIZE_T n)                            { (void)sc; (void)n; return -1; }
int    inject_self(const BYTE *sc, SIZE_T n)                                 { (void)sc; (void)n; return -1; }
int    inject_stomp(DWORD pid, const BYTE *sc, SIZE_T n, const char *dll)   { (void)pid; (void)sc; (void)n; (void)dll; return -1; }
