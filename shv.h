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
typedef const SHV_VP_STATE *PCSHV_VP_STATE;

typedef struct _SHV_CALLBACK_CONTEXT
{
    UINT64 Cr3;
    _Field_range_(>=, 0) volatile long InitCount;
    _Field_range_(>=, -1) INT32 FailedCpu;
    _Field_range_(SHV_STATUS_NOT_PRESENT, SHV_STATUS_SUCCESS) INT32 FailureStatus;
} SHV_CALLBACK_CONTEXT, *PSHV_CALLBACK_CONTEXT;

SHV_CPU_CALLBACK ShvVpLoadCallback;
SHV_CPU_CALLBACK ShvVpUnloadCallback;

VOID
ShvVmxEntry (
    VOID
    );

INT32
ShvVmxLaunchOnVp (
    _Inout_ PSHV_VP_DATA CONST VpData
    );

VOID
ShvUtilConvertGdtEntry (
    _In_ VOID* CONST GdtBase,
    _In_ CONST UINT16 Offset,
    _Out_ PVMX_GDTENTRY64 CONST VmxGdtEntry
    );

UINT32
ShvUtilAdjustMsr (
    _In_ CONST LARGE_INTEGER ControlValue,
    _In_ UINT32 DesiredValue
    );

_Ret_maybenull_
_When_ (return != NULL, _Post_writable_size_(CpuCount))
PSHV_VP_DATA
ShvVpAllocateData (
    _In_ UINT32 CpuCount
    );

VOID
ShvVpFreeData  (
    _In_ _Frees_ptr_ PSHV_VP_DATA Data,
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
    _Inout_ PSHV_VP_DATA CONST VpData
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
    _Out_ PCONTEXT ContextRecord
    );

VOID
ShvOsUnprepareProcessor (
    _In_ PCSHV_VP_DATA CONST VpData
    );

INT32
ShvOsPrepareProcessor (
    _In_ PCSHV_VP_DATA CONST VpData
    );

_Ret_range_(>=, 0)
INT32
ShvOsGetActiveProcessorCount (
    VOID
    );

_Ret_range_(>=, 0)
INT32
ShvOsGetCurrentProcessorNumber (
    VOID
    );

VOID
ShvOsFreeContiguousAlignedMemory (
    _In_ _Frees_ptr_ VOID* CONST BaseAddress,
    _In_ CONST size_t Size
    );

_Ret_maybenull_
_When_ (return != NULL, _Post_writable_byte_size_ (Size))
VOID*
ShvOsAllocateContigousAlignedMemory (
    _In_ size_t Size
    );

UINT64
ShvOsGetPhysicalAddress (
    _In_ VOID *BaseAddress
    );

#ifndef __BASE_H__
VOID
ShvOsDebugPrint (
    _In_z_ _Printf_format_string_ PCCH CONST Format,
    ...
    );
#else
VOID
ShvOsDebugPrintWide (
    _In_z_ _Printf_format_string_ CONST CHAR16* CONST Format,
    ...
    );
#define ShvOsDebugPrint(format, ...) ShvOsDebugPrintWide(_CRT_WIDE(format), __VA_ARGS__)
#endif

VOID
ShvOsRunCallbackOnProcessors (
    _In_ PSHV_CPU_CALLBACK Routine,
    _Inout_opt_ VOID* Context
    );

extern PSHV_VP_DATA* ShvGlobalData;

