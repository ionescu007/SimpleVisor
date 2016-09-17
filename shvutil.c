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
ShvUtilConvertGdtEntry (
    _In_ VOID* const GdtBase,
    _In_ const UINT16 Selector,
    _Out_ PVMX_GDTENTRY64 const VmxGdtEntry
    )
{
    PKGDTENTRY64 gdtEntry;

    //
    // Reject LDT or NULL entries
    //
    if ((Selector == 0) ||
        (Selector & SELECTOR_TABLE_INDEX) != 0)
    {
        VmxGdtEntry->Limit = VmxGdtEntry->AccessRights = 0;
        VmxGdtEntry->Base = 0;
        VmxGdtEntry->Selector = 0;
        VmxGdtEntry->Bits.Unusable = TRUE;
        return;
    }

    //
    // Read the GDT entry at the given selector, masking out the RPL bits.
    //
    gdtEntry = (PKGDTENTRY64)((uintptr_t)GdtBase + (Selector & ~RPL_MASK));

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
                         (gdtEntry->BaseLow)) & 0xFFFFFFFF;
    VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ?
                         ((uintptr_t)gdtEntry->BaseUpper << 32) : 0;

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

UINT32
ShvUtilAdjustMsr (
    _In_ const LARGE_INTEGER ControlValue,
    _In_ UINT32 DesiredValue
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

