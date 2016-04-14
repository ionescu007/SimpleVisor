/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

	shvutil.c

Abstract:

	This module implements utility functions for the Simple Hyper Visor.

Author:

	Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

	Kernel mode only.

--*/

#include "shv.h"

VOID
ShvUtilConvertGdtEntry(
	_In_ PVOID GdtBase,
	_In_ USHORT Selector,
	_Out_ PVMX_GDTENTRY64 VmxGdtEntry
)
{
	PKGDTENTRY64 gdtEntry;

	//
	// Read the GDT entry at the given selector, masking out the RPL bits. x64
	// Windows does not use an LDT for these selectors in kernel, so the TI bit
	// should never be set.
	//
	NT_ASSERT((Selector & SELECTOR_TABLE_INDEX) == 0);
	gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Selector & ~RPL_MASK));

	//
	// Write the selector directly 
	//
	VmxGdtEntry->Selector = Selector;

	//
	// Use the LSL intrinsic to read the segment limit
	//
	VmxGdtEntry->Limit = __segmentlimit(Selector);

	//
	// Build the full 64-bit effective address, keeping in mind that only when
	// the System bit is unset, should this be done.
	//
	// NOTE: The Windows definition of KGDTENTRY64 is WRONG. The "System" field
	// is incorrectly defined at the position of where the AVL bit should be.
	// The actual location of the SYSTEM bit is encoded as the highest bit in
	// the "Type" field.
	//
	VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) |
		(gdtEntry->Bytes.BaseMiddle << 16) |
		(gdtEntry->BaseLow)) & MAXULONG;
	VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ?
		((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;

	//
	// Load the access rights
	//
	VmxGdtEntry->AccessRights = 0;
	VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
	VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

	//
	// Finally, handle the VMX-specific bits
	//
	VmxGdtEntry->Bits.Reserved = 0;
	VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

ULONG
ShvUtilAdjustMsr(
	_In_ LARGE_INTEGER ControlValue,
	_In_ ULONG DesiredValue
)
{
	//
	// VMX feature/capability MSRs encode the "must be 0" bits in the high word
	// of their value, and the "must be 1" bits in the low word of their value.
	// Adjust any requested capability/feature based on these requirements.
	//
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;
	return DesiredValue;
}

PVOID
ShUtilvAllocateContiguousMemory(
	_In_ SIZE_T NumberOfBytes
)
{
	PHYSICAL_ADDRESS lowest, highest;
	//
	// The entire address range is OK for this allocation
	//
	lowest.QuadPart = 0;
	highest.QuadPart = _UI64_MAX;

	//
	// Starting in Windows 8 we can make sure that our allocation
	// is RW and not RWX using the new API. There is no good way
	// to accomplish the same on Windows 7.
	//
	if (RtlIsNtDdiVersionAvailable(NTDDI_WIN8)) {
		typedef PVOID(*PMACNM) (MmAllocateContiguousNodeMemory);

		PMACNM MmAllocateContiguousNodeMemory;
		UNICODE_STRING funcName;

		RtlInitUnicodeString(&funcName, L"MmAllocateContiguousNodeMemory");

#pragma warning(suppress: 4055)
		MmAllocateContiguousNodeMemory = (PMACNM)MmGetSystemRoutineAddress(&funcName);

		if (MmAllocateContiguousNodeMemory != NULL) {
			return MmAllocateContiguousNodeMemory(
				NumberOfBytes,
				lowest,
				highest,
				lowest,
				PAGE_READWRITE,
				MM_ANY_NODE_OK
			);
		}
	}

	//
	// If we're here then we'll just fall back to using executable
	// memory.
	//
#pragma warning(suppress: 30029)
	return MmAllocateContiguousMemorySpecifyCache(
		NumberOfBytes,
		lowest,
		highest,
		lowest,
		MmCached
	);
}

