;++
;
; Copyright (c) Alex Ionescu.  All rights reserved.
;
; Module:
;
;    shvosx64.asm
;
; Abstract:
;
;    This module implements AMD64-specific routines for the Simple Hyper Visor.
;
; Author:
;
;    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version
;
; Environment:
;
;    Kernel mode only.
;
;--

    .code

    _str PROC
        str word ptr [rcx]          ; Store TR value
        ret                         ; Return
    _str ENDP

    _sldt PROC
        sldt word ptr [rcx]         ; Store LDTR value
        ret                         ; Return
    _sldt ENDP

    ShvVmxCleanup PROC
        mov     ds, cx              ; set DS to parameter 1
        mov     es, cx              ; set ES to parameter 1
        mov     fs, dx              ; set FS to parameter 2
        ret                         ; return
    ShvVmxCleanup ENDP

    __lgdt PROC
        lgdt    fword ptr [rcx]     ; load the GDTR with the value in parameter 1
        ret                         ; return
    __lgdt ENDP
    
    _ltr PROC
    ltr     cx
    _ltr ENDP

    ShvOsCaptureContext PROC
    pushfq
    mov     [rcx+78h], rax
    mov     [rcx+80h], rcx
    mov     [rcx+88h], rdx
    mov     [rcx+0B8h], r8
    mov     [rcx+0C0h], r9
    mov     [rcx+0C8h], r10
    mov     [rcx+0D0h], r11

    mov     word ptr [rcx+38h], cs
    mov     word ptr [rcx+3Ah], ds
    mov     word ptr [rcx+3Ch], es
    mov     word ptr [rcx+42h], ss
    mov     word ptr [rcx+3Eh], fs
    mov     word ptr [rcx+40h], gs

    mov     [rcx+90h], rbx
    mov     [rcx+0A0h], rbp
    mov     [rcx+0A8h], rsi
    mov     [rcx+0B0h], rdi
    mov     [rcx+0D8h], r12
    mov     [rcx+0E0h], r13
    mov     [rcx+0E8h], r14
    mov     [rcx+0F0h], r15

    movdqu  [rcx+0198h], xmm0
    movdqu  [rcx+01a8h], xmm1
    movdqu  [rcx+01b8h], xmm2
    movdqu  [rcx+01c8h], xmm3
    movdqu  [rcx+01d8h], xmm4
    movdqu  [rcx+01e8h], xmm5


    lea     rax, [rsp+10h]
    mov     [rcx+98h], rax
    mov     rax, [rsp+8]
    mov     [rcx+0F8h], rax
    mov     eax, [rsp]
    mov     [rcx+44h], eax

    add     rsp, 8
    ret
    ShvOsCaptureContext ENDP

    ShvOsRestoreContext PROC
    mov     ax, [rcx+42h]
    mov     [rsp+20h], ax
    mov     rax, [rcx+98h]
    mov     [rsp+18h], rax
    mov     eax, [rcx+44h]
    mov     [rsp+10h], eax
    mov     ax, [rcx+38h]
    mov     [rsp+8], ax
    mov     rax, [rcx+0F8h]
    mov     [rsp], rax

    mov     rax, [rcx+78h]
    mov     rdx, [rcx+88h]
    mov     r8, [rcx+0B8h]
    mov     r9, [rcx+0C0h]
    mov     r10, [rcx+0C8h]
    mov     r11, [rcx+0D0h]

    movdqu  xmm0, [rcx+0198h] 
    movdqu  xmm1, [rcx+01a8h] 
    movdqu  xmm2, [rcx+01b8h] 
    movdqu  xmm3, [rcx+01c8h] 
    movdqu  xmm4, [rcx+01d8h] 
    movdqu  xmm5, [rcx+01e8h] 
    cli

    mov     rbx, [rcx+90h]
    mov     rsi, [rcx+0A8h]
    mov     rdi, [rcx+0B0h]
    mov     rbp, [rcx+0A0h]
    mov     r12, [rcx+0D8h]
    mov     r13, [rcx+0E0h]
    mov     r14, [rcx+0E8h]
    mov     r15, [rcx+0F0h]
    mov     rcx, [rcx+80h]

    iretq
    ShvOsRestoreContext ENDP

    end
