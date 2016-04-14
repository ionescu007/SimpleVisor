/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

	shv.h

Abstract:

	This header defines the structures and functions of the Simple Hyper Visor.

Author:

	Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

	Kernel mode only.

--*/

#pragma once
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#include <ntifs.h>
#include <intrin.h>
#include "ntint.h"
#include "vmx.h"

typedef struct _VMX_GDTENTRY64
{
	ULONG_PTR Base;
	ULONG Limit;
	union
	{
		struct
		{
			UCHAR Flags1;
			UCHAR Flags2;
			UCHAR Flags3;
			UCHAR Flags4;
		} Bytes;
		struct
		{
			USHORT SegmentType : 4;
			USHORT DescriptorType : 1;
			USHORT Dpl : 2;
			USHORT Present : 1;

			USHORT Reserved : 4;
			USHORT System : 1;
			USHORT LongMode : 1;
			USHORT DefaultBig : 1;
			USHORT Granularity : 1;

			USHORT Unusable : 1;
			USHORT Reserved2 : 15;
		} Bits;
		ULONG AccessRights;
	};
	USHORT Selector;
} VMX_GDTENTRY64, *PVMX_GDTENTRY64;

typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VMX_VMCS
{
	ULONG RevisionId;
	ULONG AbortIndicator;
	UCHAR Data[PAGE_SIZE - 8];
} VMX_VMCS, *PVMX_VMCS;

typedef struct _SHV_VP_DATA
{
	KPROCESSOR_STATE HostState;
	ULONG VpIndex;
	volatile ULONG VmxEnabled;
	ULONG64 SystemDirectoryTableBase;
	LARGE_INTEGER MsrData[17];
	ULONGLONG VmxOnPhysicalAddress;
	ULONGLONG VmcsPhysicalAddress;
	ULONGLONG MsrBitmapPhysicalAddress;

	DECLSPEC_ALIGN(PAGE_SIZE) UCHAR ShvStackLimit[KERNEL_STACK_SIZE];
	VMX_VMCS VmxOn;
	VMX_VMCS Vmcs;
} SHV_VP_DATA, *PSHV_VP_DATA;

C_ASSERT(sizeof(SHV_VP_DATA) == (KERNEL_STACK_SIZE + 3 * PAGE_SIZE));

typedef struct _SHV_GLOBAL_DATA
{
	UCHAR MsrBitmap[PAGE_SIZE];
	SHV_VP_DATA VpData[ANYSIZE_ARRAY];
} SHV_GLOBAL_DATA, *PSHV_GLOBAL_DATA;

typedef struct _SHV_VP_STATE
{
	PCONTEXT VpRegs;
	ULONG_PTR GuestRip;
	ULONG_PTR GuestRsp;
	ULONG_PTR GuestEFlags;
	USHORT ExitReason;
	KIRQL GuestIrql;
	BOOLEAN ExitVm;
} SHV_VP_STATE, *PSHV_VP_STATE;

VOID
ShvVmxEntry(
	VOID
);

VOID
ShvVmxCleanup(
	_In_ USHORT Data,
	_In_ USHORT Teb
);

VOID
__lgdt(
	_In_ PVOID Gdtr
);

VOID
ShvVmxLaunchOnVp(
	_In_ PSHV_VP_DATA VpData
);

VOID
ShvUtilConvertGdtEntry(
	_In_ PVOID GdtBase,
	_In_ USHORT Offset,
	_Out_ PVMX_GDTENTRY64 VmxGdtEntry
);

ULONG
ShvUtilAdjustMsr(
	_In_ LARGE_INTEGER ControlValue,
	_In_ ULONG DesiredValue
);

PVOID
ShUtilvAllocateContiguousMemory(
	_In_ SIZE_T NumberOfBytes
);

PSHV_GLOBAL_DATA
ShvVpAllocateGlobalData(
	VOID
);

BOOLEAN
ShvVmxProbe(
	VOID
);

KDEFERRED_ROUTINE ShvVpCallbackDpc;

extern PSHV_GLOBAL_DATA ShvGlobalData;
