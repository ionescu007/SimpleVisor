/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shv.h

Abstract:

    This header defines the structures and functions of the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 14-Mar-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once
#pragma warning(disable:4201)
#pragma warning(disable:4214)

#ifndef __BASE_H__
#include <basetsd.h>
#define MAX_UINT32 0xFFFFFFFF
#define MAX_UINT64 0xFFFFFFFFFFFFFFFF
#endif
#define _INC_MALLOC
#include <intrin.h>
#include "ntint.h"
#include "shv_x.h"

typedef struct _SHV_VP_STATE
{
    PCONTEXT VpRegs;
    uintptr_t GuestRip;
    uintptr_t GuestRsp;
    uintptr_t GuestEFlags;
    UINT16 ExitReason;
    UINT8 ExitVm;
} SHV_VP_STATE, *PSHV_VP_STATE;

typedef struct _SHV_CALLBACK_CONTEXT
{
    UINT64 Cr3;
    volatile long InitCount;
    INT32 FailedCpu;
    INT32 FailureStatus;
} SHV_CALLBACK_CONTEXT, *PSHV_CALLBACK_CONTEXT;

SHV_CPU_CALLBACK ShvVpLoadCallback;
SHV_CPU_CALLBACK ShvVpUnloadCallback;

VOID
ShvVmxEntry (
    VOID
    );

INT32
ShvVmxLaunchOnVp (
    _In_ PSHV_VP_DATA VpData
    );

VOID
ShvUtilConvertGdtEntry (
    _In_ VOID* GdtBase,
    _In_ UINT16 Offset,
    _Out_ PVMX_GDTENTRY64 VmxGdtEntry
    );

UINT32
ShvUtilAdjustMsr (
    _In_ LARGE_INTEGER ControlValue,
    _In_ UINT32 DesiredValue
    );

PSHV_VP_DATA
ShvVpAllocateData (
    _In_ UINT32 CpuCount
    );

VOID
ShvVpFreeData  (
    _In_ PSHV_VP_DATA Data,
    _In_ UINT32 CpuCount
    );

INT32
ShvVmxLaunch (
    VOID
    );

UINT8
ShvVmxProbe (
    VOID
    );

VOID
ShvVmxEptInitialize (
    _In_ PSHV_VP_DATA VpData
    );

DECLSPEC_NORETURN
VOID
ShvVpRestoreAfterLaunch (
    VOID
    );

//
// OS Layer
//
DECLSPEC_NORETURN
VOID
__cdecl
ShvOsRestoreContext (
    _In_ PCONTEXT ContextRecord
    );

VOID
ShvOsCaptureContext (
    _In_ PCONTEXT ContextRecord
    );

VOID
ShvOsUnprepareProcessor (
    _In_ PSHV_VP_DATA VpData
    );

INT32
ShvOsPrepareProcessor (
    _In_ PSHV_VP_DATA VpData
    );

INT32
ShvOsGetActiveProcessorCount (
    VOID
    );

INT32
ShvOsGetCurrentProcessorNumber (
    VOID
    );

VOID
ShvOsFreeContiguousAlignedMemory (
    _In_ VOID* BaseAddress,
    _In_ size_t Size
    );

VOID*
ShvOsAllocateContigousAlignedMemory (
    _In_ size_t Size
    );

UINT64
ShvOsGetPhysicalAddress (
    _In_ VOID* BaseAddress
    );

#ifndef __BASE_H__
VOID
ShvOsDebugPrint (
    _In_ const char* Format,
    ...
    );
#else
VOID
ShvOsDebugPrintWide (
    _In_ const CHAR16* Format,
    ...
    );
#define ShvOsDebugPrint(format, ...) ShvOsDebugPrintWide(_CRT_WIDE(format), __VA_ARGS__)
#endif

VOID
ShvOsRunCallbackOnProcessors (
    _In_ PSHV_CPU_CALLBACK Routine,
    _In_opt_ VOID* Context
    );

unsigned long long
ShvSelectEffectiveRegister (
    _In_ PCONTEXT guestContext,
    _In_ UINT64 registerIndex
	);

UINT64
ShvAdjustCr0 (
    _In_ UINT64 cr0
	);

UINT64
ShvAdjustCr4(
    _In_ UINT64 cr4
	);

extern PSHV_VP_DATA* ShvGlobalData;