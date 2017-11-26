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
