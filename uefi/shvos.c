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
#include <Library/PrintLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>

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
#include <intrin.h>

//
// External SimpleVisor Headers
//

#include "..\shv.h"
#include "..\ntint.h"
#include "..\shv_x.h"
#include "..\ia32.h"

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

//
// COM1
//
#define PORT 0x3f8

#define MAX_MESSAGE_SIZE 0x200

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
    // Execution of the XSETBV instruction requires the host CR4 OSXSAVE bit to be set.
    //
    CR4 cr4;
    cr4.AsUInt = __readcr4();
    cr4.OsXsave = TRUE;
    __writecr4(cr4.AsUInt);

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
    NewGdt = ShvOsAllocateContigousAlignedMemory(MAX(Gdtr.Limit + 1, KGDT64_SYS_TSS + sizeof(*TssEntry)));
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
    Tss = ShvOsAllocateContigousAlignedMemory(sizeof(*Tss));
    if (Tss == NULL)
    {
        ShvOsFreeContiguousAlignedMemory(NewGdt, MAX(Gdtr.Limit + 1, KGDT64_SYS_TSS + sizeof(*TssEntry)));
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
    gBS->FreePages((EFI_PHYSICAL_ADDRESS)BaseAddress, EFI_SIZE_TO_PAGES(Size));
}

VOID*
ShvOsAllocateContigousAlignedMemory (
    _In_ size_t Size
    )
{
    //
    // Allocate a contiguous chunk of RAM to back this allocation.
    //
    EFI_PHYSICAL_ADDRESS address = MAX_UINT64;
    gBS->AllocatePages(AllocateMaxAddress, EfiRuntimeServicesData, EFI_SIZE_TO_PAGES(Size), &address);
    __stosb((unsigned char*)address, 0, Size);
    return (void*)address;
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

VOID
SerialPortInit(
    VOID
	)
{
   __outbyte(PORT + 1, 0x00);
   __outbyte(PORT + 3, 0x80);
   __outbyte(PORT + 0, 0x03);
   __outbyte(PORT + 1, 0x00);
   __outbyte(PORT + 3, 0x03);
   __outbyte(PORT + 2, 0xC7);
   __outbyte(PORT + 4, 0x0B);
   __outbyte(PORT + 4, 0x1E);
   __outbyte(PORT + 4, 0x0F);
}

VOID
SerialPortWrite(
    CHAR8* string,
    size_t size
	)
{
    __outbytestring(PORT, (unsigned char*)string, (unsigned long)size);
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
    _In_ const CHAR16* Format,
    ...
    )
{
    VA_LIST arglist;
    CHAR8 message[MAX_MESSAGE_SIZE];
    //
    // Call the debugger API
    //
    VA_START(arglist, Format);
    size_t size = AsciiVSPrintUnicodeFormat(message, MAX_MESSAGE_SIZE, Format, arglist);
    VA_END(arglist);
    SerialPortWrite(message, size);
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

INTN ShvCreateNewPageTableIdentityMap()
{
    PML4E_64* pml4 = ShvOsAllocateContigousAlignedMemory(sizeof(PML4E_64) * PML4E_ENTRY_COUNT);
	PDPTE_64* pdpt = ShvOsAllocateContigousAlignedMemory(sizeof(PDPTE_64) * PDPTE_ENTRY_COUNT);
    PDE_2MB_64 (*pde)[PDE_ENTRY_COUNT] = ShvOsAllocateContigousAlignedMemory(sizeof(PDE_2MB_64) * PDPTE_ENTRY_COUNT * PDE_ENTRY_COUNT);
	
	//
    // Fill out the PML4E which covers the first 512GB of RAM
    //
    pml4->AsUInt = 0;
	pml4->Present = 1;
    pml4->Write = 1;
    pml4->PageFrameNumber = ShvOsGetPhysicalAddress(pdpt) / PAGE_SIZE;

    //
    // Fill out a RWX PDPTE
    //
    pdpt->AsUInt = 0;
    pdpt->Present = 1;
    pdpt->Write = 1;
    __stosq((UINT64*)pdpt, pdpt->AsUInt, PDPTE_ENTRY_COUNT);
    for (size_t i = 0; i < PDPTE_ENTRY_COUNT; i++)
    {
        //
        // Set the page frame number of the PDE table
        //
        pdpt[i].PageFrameNumber = ShvOsGetPhysicalAddress(&pde[i][0]) / PAGE_SIZE;
    }
	
    PDE_2MB_64 tempPde;
    tempPde.AsUInt = 0;
    tempPde.Present = 1;
    tempPde.Write = 1;
    tempPde.LargePage = 1;
    __stosq((UINT64*)pde, tempPde.AsUInt, PDPTE_ENTRY_COUNT * PDE_ENTRY_COUNT);
    for (size_t i = 0; i < PDPTE_ENTRY_COUNT; i++) {
        // Construct EPT identity map for every 2MB of RAM
        for (size_t j = 0; j < PDE_ENTRY_COUNT; j++) {
            pde[i][j].PageFrameNumber = (i * 512) + j;
        }
    }
    return (INTN)pml4;
}

void ShvLoadAndStartFile(EFI_HANDLE currentImage, CHAR16* filePath)
{
    size_t numberOfFileSystemHandles;
    EFI_HANDLE* fileSystems;
    gBS->LocateHandleBuffer(ByProtocol,
							&gEfiSimpleFileSystemProtocolGuid,
							NULL,
							&numberOfFileSystemHandles,
							&fileSystems);
	
    // Iterate all file systems.
    for (size_t i = 0; i < numberOfFileSystemHandles; ++i) {
    	EFI_DEVICE_PATH* devicePath = FileDevicePath(fileSystems[i], filePath);
        if (NULL == devicePath) {
            continue;
        }
    	
        // Load the image from the specified path.
        EFI_HANDLE newImage;
        EFI_STATUS status = gBS->LoadImage(FALSE,
										   currentImage,
										   devicePath,
										   NULL,
										   0,
										   &newImage);

        // If failed, continue to another file system.
        if (EFI_ERROR(status)) {
        	FreePool(devicePath);
            continue;
        }

        // Start the image.
        gBS->StartImage(newImage, NULL, NULL);
        FreePool(devicePath);
    }
    FreePool(fileSystems);
}

EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
    SerialPortInit();

    EFI_LOADED_IMAGE_PROTOCOL* imageInfo;
    EFI_STATUS efiStatus = gBS->OpenProtocol(gImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID**)&imageInfo,
        gImageHandle,
        NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    ShvOsDebugPrintWide(L"Loaded image base address is: %llx\n", imageInfo->ImageBase);
	
    Print(L"Create new page tables\n");
    CR3 cr3;
    cr3.AsUInt = AsmReadCr3();
    cr3.AddressOfPageDirectory = (UINT64)ShvCreateNewPageTableIdentityMap() / PAGE_SIZE;
    AsmWriteCr3(cr3.AsUInt);
    
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

    // Call the hypervisor entrypoint
    ShvOsErrorToError(ShvLoad());

    // Load windows
    ShvLoadAndStartFile(ImageHandle, L"\\EFI\\Boot\\bootx64.efi");
	return EFI_LOAD_ERROR;
}