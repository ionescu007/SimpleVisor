/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvvp.c

Abstract:

    This module implements Virtual Processor (VP) management for the Simple Hyper Visor.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only, IRQL DISPATCH_LEVEL.

--*/

#include "shv.h"

UINT8
ShvIsOurHypervisorPresent (
    VOID
    )
{
    INT32 cpuInfo[4];

    //
    // Check if ECX[31h] ("Hypervisor Present Bit") is set in CPUID 1h
    //
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & HYPERV_HYPERVISOR_PRESENT_BIT)
    {
        //
        // Next, check if this is a compatible Hypervisor, and if it has the
        // SimpleVisor signature
        //
        __cpuid(cpuInfo, HYPERV_CPUID_INTERFACE);
        if (cpuInfo[0] == ' vhS')
        {
            //
            // It's us!
            //
            return TRUE;
        }
    }

    //
    // No Hypervisor, or someone else's
    //
    return FALSE;
}

VOID
ShvCaptureSpecialRegisters (
    _In_ PSHV_SPECIAL_REGISTERS SpecialRegisters
    )
{
    //
    // Use compiler intrinsics to get the data we need
    //
    SpecialRegisters->Cr0 = __readcr0();
    SpecialRegisters->Cr3 = __readcr3();
    SpecialRegisters->Cr4 = __readcr4();
    SpecialRegisters->DebugControl = __readmsr(MSR_DEBUG_CTL);
    SpecialRegisters->MsrGsBase = __readmsr(MSR_GS_BASE);
    SpecialRegisters->KernelDr7 = __readdr(7);
    _sgdt(&SpecialRegisters->Gdtr.Limit);
    __sidt(&SpecialRegisters->Idtr.Limit);

    //
    // Use OS-specific functions to get these two
    //
    _str(&SpecialRegisters->Tr);
    _sldt(&SpecialRegisters->Ldtr);
}

DECLSPEC_NORETURN
VOID
ShvVpRestoreAfterLaunch (
    VOID
    )
{
    PSHV_VP_DATA vpData;

    //
    // Get the per-processor data. This routine temporarily executes on the
    // same stack as the hypervisor (using no real stack space except the home
    // registers), so we can retrieve the VP the same way the hypervisor does.
    //
    vpData = (PSHV_VP_DATA)((uintptr_t)_AddressOfReturnAddress() +
                            sizeof(CONTEXT) -
                            KERNEL_STACK_SIZE);

    //
    // Record that VMX is now enabled by returning back to ShvVpInitialize with
    // the Alignment Check (AC) bit set.
    //
    vpData->ContextFrame.EFlags |= EFLAGS_ALIGN_CHECK;

    //
    // And finally, restore the context, so that all register and stack
    // state is finally restored.
    //
    ShvOsRestoreContext(&vpData->ContextFrame);
}

INT32
ShvVpInitialize (
    _In_ PSHV_VP_DATA Data
    )
{
    INT32 status;

    //
    // Prepare any OS-specific CPU data
    //
    status = ShvOsPrepareProcessor(Data);
    if (status != SHV_STATUS_SUCCESS)
    {
        return status;
    }

    // Read the special control registers for this processor
    // Note: KeSaveStateForHibernate(&Data->HostState) can be used as a Windows
    // specific undocumented function that can also get this data.
    //
    ShvCaptureSpecialRegisters(&Data->SpecialRegisters);

    //
    // Then, capture the entire register state. We will need this, as once we
    // launch the VM, it will begin execution at the defined guest instruction
    // pointer, which we set to ShvVpRestoreAfterLaunch, with the registers set
    // to whatever value they were deep inside the VMCS/VMX initialization code.
    // By using RtlRestoreContext, that function sets the AC flag in EFLAGS and
    // returns here with our registers restored.
    //
    ShvOsCaptureContext(&Data->ContextFrame);
    if ((__readeflags() & EFLAGS_ALIGN_CHECK) == 0)
    {
        //
        // If the AC bit is not set in EFLAGS, it means that we have not yet
        // launched the VM. Attempt to initialize VMX on this processor.
        //
        status = ShvVmxLaunchOnVp(Data);
    }

    //
    // If we got here, the hypervisor is running :-)
    //
    return status;
}

VOID
ShvVpUnloadCallback (
    _In_ PSHV_CALLBACK_CONTEXT Context
    )
{
    INT32 cpuInfo[4];
    PSHV_VP_DATA vpData;
    UNREFERENCED_PARAMETER(Context);

    //
    // Send the magic shutdown instruction sequence. It will return in EAX:EBX
    // the VP data for the current CPU, which we must free.
    //
    cpuInfo[0] = cpuInfo[1] = 0;
    __cpuidex(cpuInfo, 0x41414141, 0x42424242);

    //
    // If SimpleVisor is disabled for some reason, CPUID will return the values
    // of the highest valid CPUID. We use a magic value to make sure we really
    // are loaded and returned something valid.
    //
    if (cpuInfo[2] == 0x43434343)
    {
        __analysis_assume((cpuInfo[0] != 0) && (cpuInfo[1] != 0));
        vpData = (PSHV_VP_DATA)((UINT64)cpuInfo[0] << 32 | (UINT32)cpuInfo[1]);
        ShvOsFreeContiguousAlignedMemory(vpData, sizeof(*vpData));
    }
}

PSHV_VP_DATA
ShvVpAllocateData (
    _In_ UINT32 CpuCount
    )
{
    PSHV_VP_DATA data;

    //
    // Allocate a contiguous chunk of RAM to back this allocation
    //
    data = ShvOsAllocateContigousAlignedMemory(sizeof(*data) * CpuCount);
    if (data != NULL)
    {
        //
        // Zero out the entire data region
        //
        __stosq((UINT64*)data, 0, (sizeof(*data) / sizeof(UINT64)) * CpuCount);
    }

    //
    // Return what is hopefully a valid pointer, otherwise NULL.
    //
    return data;
}

VOID
ShvVpFreeData (
    _In_ PSHV_VP_DATA Data,
    _In_ UINT32 CpuCount
    )
{
    //
    // Free the contiguous chunk of RAM
    //
    ShvOsFreeContiguousAlignedMemory(Data, sizeof(*Data) * CpuCount);
}

VOID
ShvVpLoadCallback (
    _In_ PSHV_CALLBACK_CONTEXT Context
    )
{
    PSHV_VP_DATA vpData;
    INT32 status;

    vpData = NULL;

    //
    // Detect if the hardware appears to support VMX root mode to start.
    // No attempts are made to enable this if it is lacking or disabled.
    //
    if (!ShvVmxProbe())
    {
        status = SHV_STATUS_NOT_AVAILABLE;
        goto Failure;
    }

    //
    // Allocate the per-VP data for this logical processor
    //
    vpData = ShvVpAllocateData(1);
    if (vpData == NULL)
    {
        status = SHV_STATUS_NO_RESOURCES;
        goto Failure;
    }

    //
    // First, capture the value of the PML4 for the SYSTEM process, so that all
    // virtual processors, regardless of which process the current LP has
    // interrupted, can share the correct kernel address space.
    //
    vpData->SystemDirectoryTableBase = Context->Cr3;

    //
    // Initialize the virtual processor
    //
    status = ShvVpInitialize(vpData);
    if (status != SHV_STATUS_SUCCESS)
    {
        //
        // Bail out, free the allocated per-processor data
        //
        goto Failure;
    }

    //
    // Our hypervisor should now be seen as present on this LP, as the SHV
    // correctly handles CPUID ECX features register.
    //
    if (ShvIsOurHypervisorPresent() == FALSE)
    {
        //
        // Free the per-processor data
        //
        status = SHV_STATUS_NOT_PRESENT;
        goto Failure;
    }

    //
    // This CPU is hyperjacked!
    //
    _InterlockedIncrement((volatile long*)&Context->InitCount);
    return;

Failure:
    //
    // Return failure
    //
    if (vpData != NULL)
    {
        ShvVpFreeData(vpData, 1);
    }
    Context->FailedCpu = ShvOsGetCurrentProcessorNumber();
    Context->FailureStatus = status;
    return;
}
