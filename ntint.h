/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    ntint.h

Abstract:

    This header contains selected NT structures and functions from ntosp.h

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once
#pragma pack(push, 1)
#pragma warning(disable:4201)
#pragma warning(disable:4214)

#define VOID                void
#define DECLSPEC_ALIGN(x)   __declspec(align(x))
#define DECLSPEC_NORETURN   __declspec(noreturn)
#define FORCEINLINE         __forceinline
#define C_ASSERT(x)         static_assert(x, "Error")
#define UNREFERENCED_PARAMETER(x)   (x)

#ifndef TRUE
#define TRUE                1
#define FALSE               0
#endif

#define KERNEL_STACK_SIZE   24 * 1024

typedef struct DECLSPEC_ALIGN(16) _M128A
{
    UINT64 Low;
    INT64 High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT
{
    UINT16 ControlWord;
    UINT16 StatusWord;
    UINT8 TagWord;
    UINT8 Reserved1;
    UINT16 ErrorOpcode;
    UINT32 ErrorOffset;
    UINT16 ErrorSelector;
    UINT16 Reserved2;
    UINT32 DataOffset;
    UINT16 DataSelector;
    UINT16 Reserved3;
    UINT32 MxCsr;
    UINT32 MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    UINT8 Reserved4[96];
} XSAVE_FORMAT, *PXSAVE_FORMAT;
typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT
{
    UINT64 P1Home;
    UINT64 P2Home;
    UINT64 P3Home;
    UINT64 P4Home;
    UINT64 P5Home;
    UINT64 P6Home;
    UINT32 ContextFlags;
    UINT32 MxCsr;
    UINT16 SegCs;
    UINT16 SegDs;
    UINT16 SegEs;
    UINT16 SegFs;
    UINT16 SegGs;
    UINT16 SegSs;
    UINT32 EFlags;
    UINT64 Dr0;
    UINT64 Dr1;
    UINT64 Dr2;
    UINT64 Dr3;
    UINT64 Dr6;
    UINT64 Dr7;
    UINT64 Rax;
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT64 Rsp;
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
    UINT64 Rip;
    union
    {
        XMM_SAVE_AREA32 FltSave;
        struct
        {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        };
    };
    M128A VectorRegister[26];
    UINT64 VectorControl;
    UINT64 DebugControl;
    UINT64 LastBranchToRip;
    UINT64 LastBranchFromRip;
    UINT64 LastExceptionToRip;
    UINT64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

typedef union _LARGE_INTEGER
{
    struct
    {
        UINT32 LowPart;
        INT32 HighPart;
    };
    UINT64 QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

#pragma pack(pop)