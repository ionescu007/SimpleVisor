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

//
// Define pseudo descriptor structures for both 64- and 32-bit mode.
//

typedef struct _KDESCRIPTOR {
	USHORT Pad[3];
	USHORT Limit;
	PVOID Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

typedef struct _KDESCRIPTOR32 {
	USHORT Pad[3];
	USHORT Limit;
	ULONG Base;
} KDESCRIPTOR32, *PKDESCRIPTOR32;

//
// Define special kernel registers and the initial MXCSR value.
//

typedef struct _KSPECIAL_REGISTERS {
	ULONG64 Cr0;
	ULONG64 Cr2;
	ULONG64 Cr3;
	ULONG64 Cr4;
	ULONG64 KernelDr0;
	ULONG64 KernelDr1;
	ULONG64 KernelDr2;
	ULONG64 KernelDr3;
	ULONG64 KernelDr6;
	ULONG64 KernelDr7;
	KDESCRIPTOR Gdtr;
	KDESCRIPTOR Idtr;
	USHORT Tr;
	USHORT Ldtr;
	ULONG MxCsr;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
	ULONG64 Cr8;
	ULONG64 MsrGsBase;
	ULONG64 MsrGsSwap;
	ULONG64 MsrStar;
	ULONG64 MsrLStar;
	ULONG64 MsrCStar;
	ULONG64 MsrSyscallMask;
	ULONG64 Xcr0;
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

//
// Define processor state structure.
//

typedef struct _KPROCESSOR_STATE {
	KSPECIAL_REGISTERS SpecialRegisters;
	CONTEXT ContextFrame;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

//
// Define descriptor privilege levels for user and system.
//

#define DPL_USER 3
#define DPL_SYSTEM 0

//
// Define limit granularity.
//

#define GRANULARITY_BYTE 0
#define GRANULARITY_PAGE 1

//
// Define processor number packing constants.
//
// The compatibility processor number is encoded in the FS segment descriptor.
//
// Bits 19:14 of the segment limit encode the compatible processor number.
// Bits 13:10 are set to ones to ensure that segment limit is at least 15360.
// Bits 9:0 of the segment limit encode the extended processor number.
//

#define KGDT_LEGACY_LIMIT_SHIFT 14
#define KGDT_LIMIT_ENCODE_MASK (0xf << 10)

#define SELECTOR_TABLE_INDEX 0x04

#define KGDT64_NULL         0x00
#define KGDT64_R0_CODE      0x10
#define KGDT64_R0_DATA      0x18
#define KGDT64_R3_CMCODE    0x20
#define KGDT64_R3_DATA      0x28
#define KGDT64_R3_CODE      0x30
#define KGDT64_SYS_TSS      0x40
#define KGDT64_R3_CMTEB     0x50
#define KGDT64_R0_LDT       0x60

#define RPL_MASK 3

#define MTRR_TYPE_WB 6

typedef union _KGDTENTRY64 {
	struct {
		USHORT LimitLow;
		USHORT BaseLow;
		union {
			struct {
				UCHAR BaseMiddle;
				UCHAR Flags1;
				UCHAR Flags2;
				UCHAR BaseHigh;
			} Bytes;

			struct {
				ULONG BaseMiddle : 8;
				ULONG Type : 5;
				ULONG Dpl : 2;
				ULONG Present : 1;
				ULONG LimitHigh : 4;
				ULONG System : 1;
				ULONG LongMode : 1;
				ULONG DefaultBig : 1;
				ULONG Granularity : 1;
				ULONG BaseHigh : 8;
			} Bits;
		};

		ULONG BaseUpper;
		ULONG MustBeZero;
	};

	struct {
		LONG64 DataLow;
		LONG64 DataHigh;
	};

} KGDTENTRY64, *PKGDTENTRY64;

NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
	_In_ PKDEFERRED_ROUTINE Routine,
	_In_opt_ PVOID Context
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
	_In_ PVOID SystemArgument1
);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
	_In_ PVOID SystemArgument2
);

DECLSPEC_NORETURN
NTSYSAPI
VOID
__cdecl
RtlRestoreContext(
	_In_ PCONTEXT ContextRecord,
	_In_opt_ struct _EXCEPTION_RECORD * ExceptionRecord
);

NTKERNELAPI
VOID
__cdecl
KeSaveStateForHibernate(
	_In_ PKPROCESSOR_STATE State
);

#if (NTDDI_VERSION < NTDDI_WINTHRESHOLD)
BOOLEAN
FORCEINLINE
HviIsAnyHypervisorPresent(
	VOID
)
{
	INT cpuInfo[4];

	__cpuid(cpuInfo, 1);

	if (cpuInfo[2] & 0x80000000)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
#else
NTKERNELAPI
BOOLEAN
HviIsAnyHypervisorPresent(
	VOID
);
#endif
