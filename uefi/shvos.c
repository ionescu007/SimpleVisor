/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvos.c

Abstract:

    This module implements the OS-facing UEFI stubs for SimpleVisor.

Author:

    Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

    Kernel mode only.

--*/

//
// Basic UEFI Libraries
//
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

//
// Boot and Runtime Services
//
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

//
// Multi-Processor Service
//
#include <Pi/PiDxeCis.h>
#include <Protocol/MpService.h>

//
// Variable Arguments (CRT)
//
#include <varargs.h>

//
// External SimpleVisor Headers
//
#include "..\ntint.h"
#include "..\shv_x.h"

//
// We run on any UEFI Specification
//
extern CONST UINT32 _gUefiDriverRevision = 0;

//
// We support unload
//
const UINT8 _gDriverUnloadImageCount = 1;

//
// Our name
//
CHAR8 *gEfiCallerBaseName = "SimpleVisor";

//
// PI Multi Processor Services Protocol
//
EFI_MP_SERVICES_PROTOCOL* _gPiMpService;

//
// TSS Segment we will use
//
#define KGDT64_SYS_TSS          0x60

EFI_STATUS
__forceinline
ShvOsErrorToError (
    INT32 Error
    )
{
    //
    // Convert the possible SimpleVisor errors into NT Hyper-V Errors
    //
    if (Error == SHV_STATUS_NOT_AVAILABLE)
    {
        return EFI_NOT_AVAILABLE_YET;
    }
    if (Error == SHV_STATUS_NO_RESOURCES)
    {
        return EFI_OUT_OF_RESOURCES;
    }
    if (Error == SHV_STATUS_NOT_PRESENT)
    {
        return EFI_NOT_FOUND;
    }
    if (Error == SHV_STATUS_SUCCESS)
    {
        return EFI_SUCCESS;
    }

    //
    // Unknown/unexpected error
    //
    return EFI_LOAD_ERROR;
}

VOID
_str (
    _In_ UINT16* Tr
    )
{
    //
    // Use the UEFI framework function
    //
    *Tr = AsmReadTr();
}

VOID
_sldt (
    _In_ UINT16* Ldtr
    )
{
    //
    // Use the UEFI framework function
    //
    *Ldtr = AsmReadLdtr();
}

VOID
__lgdt (
    _In_ IA32_DESCRIPTOR* Gdtr
    )
{
    //
    // Use the UEFI framework function
    //
    AsmWriteGdtr(Gdtr);
}

VOID
ShvOsUnprepareProcessor (
    _In_ PSHV_VP_DATA VpData
    )
{
    UNREFERENCED_PARAMETER(VpData);

    //
    // Nothing to do
    //
}

INT32
ShvOsPrepareProcessor (
    _In_ PSHV_VP_DATA VpData
    )
{
    PKGDTENTRY64 TssEntry, NewGdt;
    PKTSS64 Tss;
    KDESCRIPTOR Gdtr;

    //
    // Clear AC in case it's not been reset yet
    //
    __writeeflags(__readeflags() & ~EFLAGS_ALIGN_CHECK);

    //
    // Capture the current GDT
    //
    _sgdt(&Gdtr.Limit);

    //
    // Allocate a new GDT as big as the old one, or to cover selector 0x60
    //
    NewGdt = AllocateRuntimeZeroPool(MAX(Gdtr.Limit + 1,
                                     KGDT64_SYS_TSS + sizeof(*TssEntry)));
    if (NewGdt == NULL)
    {
        return SHV_STATUS_NO_RESOURCES;
    }

    //
    // Copy the old GDT
    //
    CopyMem(NewGdt, Gdtr.Base, Gdtr.Limit + 1);

    //
    // Allocate a TSS
    //
    Tss = AllocateRuntimeZeroPool(sizeof(*Tss));
    if (Tss == NULL)
    {
        FreePool(NewGdt);
        return SHV_STATUS_NO_RESOURCES;
    }

    //
    // Fill out the TSS Entry
    //
    TssEntry = (PKGDTENTRY64)((uintptr_t)NewGdt + KGDT64_SYS_TSS);
    TssEntry->BaseLow = (uintptr_t)Tss & 0xffff;
    TssEntry->Bits.BaseMiddle = ((uintptr_t)Tss >> 16) & 0xff;
    TssEntry->Bits.BaseHigh = ((uintptr_t)Tss >> 24) & 0xff;
    TssEntry->BaseUpper = (uintptr_t)Tss >> 32;
    TssEntry->LimitLow = sizeof(KTSS64) - 1;
    TssEntry->Bits.Type = AMD64_TSS;
    TssEntry->Bits.Dpl = 0;
    TssEntry->Bits.Present = 1;
    TssEntry->Bits.System = 0;
    TssEntry->Bits.LongMode = 0;
    TssEntry->Bits.DefaultBig = 0;
    TssEntry->Bits.Granularity = 0;
    TssEntry->MustBeZero = 0;

    //
    // Load the new GDT
    //
    Gdtr.Base = NewGdt;
    Gdtr.Limit = KGDT64_SYS_TSS + sizeof(*TssEntry) - 1;
    _lgdt(&Gdtr.Limit);

    //
    // Load the task register
    //
    _ltr(KGDT64_SYS_TSS);
    return SHV_STATUS_SUCCESS;
}

VOID
ShvOsRunCallbackOnProcessors (
    _In_ PSHV_CPU_CALLBACK Routine,
    _In_ VOID* Context
    )
{
    //
    // Call the routine on the current CPU
    //
    Routine(Context);

    //
    // And then on all other processors
    //
    _gPiMpService->StartupAllAPs(_gPiMpService,
                                 Routine,
                                 TRUE,
                                 NULL,
                                 0,
                                 Context,
                                 NULL);
}

VOID
ShvOsFreeContiguousAlignedMemory (
    _In_ VOID* BaseAddress,
    _In_ size_t Size
    )
{
    //
    // Free the memory
    //
    FreeAlignedPages(BaseAddress, EFI_SIZE_TO_PAGES(Size));
}

VOID*
ShvOsAllocateContigousAlignedMemory (
    _In_ size_t Size
    )
{
    //
    // Allocate a contiguous chunk of RAM to back this allocation.
    //
    return AllocateAlignedRuntimePages(EFI_SIZE_TO_PAGES(Size), EFI_PAGE_SIZE);
}

UINT64
ShvOsGetPhysicalAddress (
    _In_ VOID* BaseAddress
    )
{
    //
    // UEFI runs with paging disabled
    //
    return (UINT64)BaseAddress;
}

INT32
ShvOsGetCurrentProcessorNumber (
    VOID
    )
{
    EFI_STATUS efiStatus;
    UINTN cpuIndex;

    //
    // Ask PI MP Services for the CPU index
    //
    efiStatus = _gPiMpService->WhoAmI(_gPiMpService, &cpuIndex);
    if (efiStatus != EFI_SUCCESS)
    {
        cpuIndex = ~0ULL;
    }

    //
    // Return the index
    //
    return (INT32)cpuIndex;
}

INT32
ShvOsGetActiveProcessorCount (
    VOID
    )
{
    EFI_STATUS efiStatus;
    UINTN cpuCount, enabledCpuCount;

    //
    // Ask PI MP Services for how many CPUs there are
    //
    efiStatus = _gPiMpService->GetNumberOfProcessors(_gPiMpService,
                                                     &cpuCount,
                                                     &enabledCpuCount);
    if (efiStatus != EFI_SUCCESS)
    {
        enabledCpuCount = 0;
    }

    //
    // Return the count
    //
    return (INT32)enabledCpuCount;
}

VOID
ShvOsDebugPrintWide (
    _In_ CHAR16* Format,
    ...
    )
{
    VA_LIST arglist;
    CHAR16* debugString;

    //
    // Call the debugger API
    //
    VA_START(arglist, Format);
    debugString = CatVSPrint(NULL, Format, arglist);
    Print(debugString);
    FreePool(debugString);
    VA_END(arglist);
}

EFI_STATUS
EFIAPI
UefiUnload (
    IN EFI_HANDLE ImageHandle
    )
{
    //
    // Call the hypervisor unloadpoint
    //
    ShvUnload();
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    EFI_STATUS efiStatus;

    //
    // Find the PI MpService protocol used for multi-processor startup
    //
    efiStatus = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                    NULL,
                                    &_gPiMpService);
    if (EFI_ERROR(efiStatus))
    {
        Print(L"Unable to locate the MpServices protocol: %r\n", efiStatus);
        return efiStatus;
    }

    //
    // Call the hypervisor entrypoint
    //
    return ShvOsErrorToError(ShvLoad());
}

