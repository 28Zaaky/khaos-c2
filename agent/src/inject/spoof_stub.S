
    .text
    .extern inj_sc_gadget
    .extern inj_frame1
    .extern inj_frame2

    .global inj_sc
inj_sc:
    movq    0x30(%rsp), %r10
    movq    0x38(%rsp), %r11

    subq    $0x10, %rsp

    movq    inj_frame2(%rip), %rax
    movq    %rax, 0x08(%rsp)
    movq    inj_frame1(%rip), %rax
    movq    %rax, 0x00(%rsp)

    movq    %r10, 0x28(%rsp)
    movq    %r11, 0x30(%rsp)

    movq    %rdx, %r10
    movq    %r8,  %rdx
    movq    %r9,  %r8
    movq    0x38(%rsp), %r9

    movq    0x50(%rsp), %r11 ;  movq %r11, 0x38(%rsp)
    movq    0x58(%rsp), %r11 ;  movq %r11, 0x40(%rsp)
    movq    0x60(%rsp), %r11 ;  movq %r11, 0x48(%rsp)
    movq    0x68(%rsp), %r11 ;  movq %r11, 0x50(%rsp)
    movq    0x70(%rsp), %r11 ;  movq %r11, 0x58(%rsp)

    movzwl  %cx, %eax
    jmpq    *inj_sc_gadget(%rip)
