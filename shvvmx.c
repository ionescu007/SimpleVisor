/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvvmx.c

Abstract:

    This module implements Intel VMX (Vanderpool/VT-x)-specific routines.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Kernel mode only, IRQL DISPATCH_LEVEL.

--*/

#include "shv.h"

VOID
ShvVmxEptInitialize (
    _Inout_ PSHV_VP_DATA CONST VpData
    )
{
    UINT64 i;
    VMX_HUGE_PDPTE tempEpdpte;

    //
    // Fill out the EPML4E which covers the first 512GB of RAM
    //
    VpData->Epml4[0].Read = 1;
    VpData->Epml4[0].Write = 1;
    VpData->Epml4[0].Execute = 1;
    VpData->Epml4[0].PageFrameNumber = ShvOsGetPhysicalAddress(&VpData->Epdpt) / PAGE_SIZE;

    //
    // Fill out a RWX Write-back 1GB EPDPTE
    //
    tempEpdpte.AsUlonglong = 0;
    tempEpdpte.Read = tempEpdpte.Write = tempEpdpte.Execute = 1;
    tempEpdpte.Type = MTRR_TYPE_WB;
    tempEpdpte.Large = 1;

    //
    // Construct EPT identity map for every 1GB of RAM
    //
    __stosq((UINT64*)VpData->Epdpt, tempEpdpte.AsUlonglong, PDPTE_ENTRY_COUNT);
    for (i = 0; i < PDPTE_ENTRY_COUNT; i++) VpData->Epdpt[i].PageFrameNumber = i;
}

UINT8
ShvVmxEnterRootModeOnVp (
    _Inout_ PSHV_VP_DATA CONST VpData
    )
{
    PSHV_SPECIAL_REGISTERS CONST Registers = &VpData->SpecialRegisters;

    //
    // Ensure the the VMCS can fit into a single page
    //
    if (((VpData->MsrData[0].QuadPart & VMX_BASIC_VMCS_SIZE_MASK) >> 32) > PAGE_SIZE)
    {
        return FALSE;
    }

    //
    // Ensure that the VMCS is supported in writeback memory
    //
    if (((VpData->MsrData[0].QuadPart & VMX_BASIC_MEMORY_TYPE_MASK) >> 50) != MTRR_TYPE_WB)
    {
        return FALSE;
    }

    //
    // Ensure that true MSRs can be used for capabilities
    //
    if (((VpData->MsrData[0].QuadPart) & VMX_BASIC_DEFAULT1_ZERO) == 0)
    {
        return FALSE;
    }

    //
    // Ensure that EPT is available with the needed features SimpleVisor uses
    //
    if (((VpData->MsrData[12].QuadPart & VMX_EPT_PAGE_WALK_4_BIT) != 0) &&
        ((VpData->MsrData[12].QuadPart & VMX_EPTP_WB_BIT) != 0) &&
        ((VpData->MsrData[12].QuadPart & VMX_EPT_1GB_PAGE_BIT) != 0))
    {
        //
        // Enable EPT if these features are supported
        //
        VpData->EptControls = SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID;
    }

    //
    // Capture the revision ID for the VMXON and VMCS region
    //
    VpData->VmxOn.RevisionId = VpData->MsrData[0].LowPart;
    VpData->Vmcs.RevisionId = VpData->MsrData[0].LowPart;

    //
    // Store the physical addresses of all per-LP structures allocated
    //
    VpData->VmxOnPhysicalAddress = ShvOsGetPhysicalAddress(&VpData->VmxOn);
    VpData->VmcsPhysicalAddress = ShvOsGetPhysicalAddress(&VpData->Vmcs);
    VpData->MsrBitmapPhysicalAddress = ShvOsGetPhysicalAddress(VpData->MsrBitmap);
    VpData->EptPml4PhysicalAddress = ShvOsGetPhysicalAddress(&VpData->Epml4);

    //
    // Update CR0 with the must-be-zero and must-be-one requirements
    //
    Registers->Cr0 &= VpData->MsrData[7].LowPart;
    Registers->Cr0 |= VpData->MsrData[6].LowPart;

    //
    // Do the same for CR4
    //
    Registers->Cr4 &= VpData->MsrData[9].LowPart;
    Registers->Cr4 |= VpData->MsrData[8].LowPart;

    //
    // Update host CR0 and CR4 based on the requirements above
    //
    __writecr0(Registers->Cr0);
    __writecr4(Registers->Cr4);

    //
    // Enable VMX Root Mode
    //
    if (__vmx_on(&VpData->VmxOnPhysicalAddress))
    {
        return FALSE;
    }
 
    //
    // Clear the state of the VMCS, setting it to Inactive
    //
    if (__vmx_vmclear(&VpData->VmcsPhysicalAddress))
    {
        return FALSE;
    }

    //
    // Load the VMCS, setting its state to Active
    //
    if (__vmx_vmptrld(&VpData->VmcsPhysicalAddress))
    {
        return FALSE;
    }

    //
    // VMX Root Mode is enabled, with an active VMCS.
    //
    return TRUE;
}

VOID
ShvVmxSetupVmcsForVp (
    _In_ PCSHV_VP_DATA CONST VpData
    )
{
    PCSHV_SPECIAL_REGISTERS CONST state = &VpData->SpecialRegisters;
    CONST CONTEXT *CONST context = &VpData->ContextFrame;
    VMX_GDTENTRY64 vmxGdtEntry;

    //
    // Begin by setting the link pointer to the required value for 4KB VMCS.
    //
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    //
    // Enable EPT features if supported
    //
    if (VpData->EptControls != 0)
    {
        //
        // Configure the EPTP
        //
        VMX_EPTP vmxEptp;
        vmxEptp.AsUlonglong = 0;
        vmxEptp.PageWalkLength = 3;
        vmxEptp.Type = MTRR_TYPE_WB;
        vmxEptp.PageFrameNumber = VpData->EptPml4PhysicalAddress / PAGE_SIZE;

        //
        // Load EPT Root Pointer
        //
        __vmx_vmwrite(EPT_POINTER, vmxEptp.AsUlonglong);

        //
        // Set VPID to one
        //
        __vmx_vmwrite(VIRTUAL_PROCESSOR_ID, 1);
    }

    //
    // Load the MSR bitmap. Unlike other bitmaps, not having an MSR bitmap will
    // trap all MSRs, so we allocated an empty one.
    //
    __vmx_vmwrite(MSR_BITMAP, VpData->MsrBitmapPhysicalAddress);

    //
    // Enable support for RDTSCP and XSAVES/XRESTORES in the guest. Windows 10
    // makes use of both of these instructions if the CPU supports it. By using
    // ShvUtilAdjustMsr, these options will be ignored if this processor does
    // not actully support the instructions to begin with.
    //
    // Also enable EPT support, for additional performance and ability to trap
    // memory access efficiently.
    //
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL,
                           ShvUtilAdjustMsr(VpData->MsrData[11],
                                            SECONDARY_EXEC_ENABLE_RDTSCP |
                                            SECONDARY_EXEC_XSAVES |
                                            VpData->EptControls));

    //
    // Enable no pin-based options ourselves, but there may be some required by
    // the processor. Use ShvUtilAdjustMsr to add those in.
    //
    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL,
                           ShvUtilAdjustMsr(VpData->MsrData[13], 0));

    //
    // In order for our choice of supporting RDTSCP and XSAVE/RESTORES above to
    // actually mean something, we have to request secondary controls. We also
    // want to activate the MSR bitmap in order to keep them from being caught.
    //
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL,
                           ShvUtilAdjustMsr(VpData->MsrData[14],
                                            CPU_BASED_ACTIVATE_MSR_BITMAP |
                                            CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));

    //
    // If any interrupts were pending upon entering the hypervisor, acknowledge
    // them when we're done. And make sure to enter us in x64 mode at all times
    //
    __vmx_vmwrite(VM_EXIT_CONTROLS,
                           ShvUtilAdjustMsr(VpData->MsrData[15],
                                            VM_EXIT_ACK_INTR_ON_EXIT |
                                            VM_EXIT_IA32E_MODE));

    //
    // As we exit back into the guest, make sure to exist in x64 mode as well.
    //
    __vmx_vmwrite(VM_ENTRY_CONTROLS,
                           ShvUtilAdjustMsr(VpData->MsrData[16],
                                            VM_ENTRY_IA32E_MODE));

    //
    // Load the CS Segment (Ring 0 Code)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, context->SegCs, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_CS_SELECTOR, context->SegCs & ~RPL_MASK);

    //
    // Load the SS Segment (Ring 0 Data)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, context->SegSs, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_SS_SELECTOR, context->SegSs & ~RPL_MASK);

    //
    // Load the DS Segment (Ring 3 Data)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, context->SegDs, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_DS_SELECTOR, context->SegDs & ~RPL_MASK);

    //
    // Load the ES Segment (Ring 3 Data)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, context->SegEs, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_ES_SELECTOR, context->SegEs & ~RPL_MASK);

    //
    // Load the FS Segment (Ring 3 Compatibility-Mode TEB)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, context->SegFs, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_FS_SELECTOR, context->SegFs & ~RPL_MASK);

    //
    // Load the GS Segment (Ring 3 Data if in Compatibility-Mode, MSR-based in Long Mode)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, context->SegGs, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_GS_BASE, state->MsrGsBase);
    __vmx_vmwrite(HOST_GS_BASE, state->MsrGsBase);
    __vmx_vmwrite(HOST_GS_SELECTOR, context->SegGs & ~RPL_MASK);

    //
    // Load the Task Register (Ring 0 TSS)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, state->Tr, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_TR_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_TR_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_TR_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_TR_BASE, vmxGdtEntry.Base);
    __vmx_vmwrite(HOST_TR_SELECTOR, state->Tr & ~RPL_MASK);

    //
    // Load the Local Descriptor Table (Ring 0 LDT on Redstone)
    //
    ShvUtilConvertGdtEntry(state->Gdtr.Base, state->Ldtr, &vmxGdtEntry);
    __vmx_vmwrite(GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector);
    __vmx_vmwrite(GUEST_LDTR_LIMIT, vmxGdtEntry.Limit);
    __vmx_vmwrite(GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights);
    __vmx_vmwrite(GUEST_LDTR_BASE, vmxGdtEntry.Base);

    //
    // Now load the GDT itself
    //
    __vmx_vmwrite(GUEST_GDTR_BASE, (uintptr_t)state->Gdtr.Base);
    __vmx_vmwrite(GUEST_GDTR_LIMIT, state->Gdtr.Limit);
    __vmx_vmwrite(HOST_GDTR_BASE, (uintptr_t)state->Gdtr.Base);

    //
    // And then the IDT
    //
    __vmx_vmwrite(GUEST_IDTR_BASE, (uintptr_t)state->Idtr.Base);
    __vmx_vmwrite(GUEST_IDTR_LIMIT, state->Idtr.Limit);
    __vmx_vmwrite(HOST_IDTR_BASE, (uintptr_t)state->Idtr.Base);

    //
    // Load CR0
    //
    __vmx_vmwrite(CR0_READ_SHADOW, state->Cr0);
    __vmx_vmwrite(HOST_CR0, state->Cr0);
    __vmx_vmwrite(GUEST_CR0, state->Cr0);

    //
    // Load CR3 -- do not use the current process' address space for the host,
    // because we may be executing in an arbitrary user-mode process right now
    // as part of the DPC interrupt we execute in.
    //
    __vmx_vmwrite(HOST_CR3, VpData->SystemDirectoryTableBase);
    __vmx_vmwrite(GUEST_CR3, state->Cr3);

    //
    // Load CR4
    //
    __vmx_vmwrite(HOST_CR4, state->Cr4);
    __vmx_vmwrite(GUEST_CR4, state->Cr4);
    __vmx_vmwrite(CR4_READ_SHADOW, state->Cr4);

    //
    // Load debug MSR and register (DR7)
    //
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->DebugControl);
    __vmx_vmwrite(GUEST_DR7, state->KernelDr7);

    //
    // Finally, load the guest stack, instruction pointer, and rflags, which
    // corresponds exactly to the location where RtlCaptureContext will return
    // to inside of ShvVpInitialize.
    //
    __vmx_vmwrite(GUEST_RSP, (uintptr_t)VpData->ShvStackLimit + KERNEL_STACK_SIZE - sizeof(CONTEXT));
    __vmx_vmwrite(GUEST_RIP, (uintptr_t)ShvVpRestoreAfterLaunch);
    __vmx_vmwrite(GUEST_RFLAGS, context->EFlags);

    //
    // Load the hypervisor entrypoint and stack. We give ourselves a standard
    // size kernel stack (24KB) and bias for the context structure that the
    // hypervisor entrypoint will push on the stack, avoiding the need for RSP
    // modifying instructions in the entrypoint. Note that the CONTEXT pointer
    // and thus the stack itself, must be 16-byte aligned for ABI compatibility
    // with AMD64 -- specifically, XMM operations will fail otherwise, such as
    // the ones that RtlCaptureContext will perform.
    //
    C_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
    __vmx_vmwrite(HOST_RSP, (uintptr_t)VpData->ShvStackLimit + KERNEL_STACK_SIZE - sizeof(CONTEXT));
    __vmx_vmwrite(HOST_RIP, (uintptr_t)ShvVmxEntry);
}

UINT8
ShvVmxProbe (
    VOID
    )
{
    INT32 cpu_info[4];
    UINT64 featureControl;

    //
    // Check the Hypervisor Present-bit
    //
    __cpuid(cpu_info, 1);
    if ((cpu_info[2] & 0x20) == FALSE)
    {
        return FALSE;
    }

    //
    // Check if the Feature Control MSR is locked. If it isn't, this means that
    // BIOS/UEFI firmware screwed up, and we could go around locking it, but
    // we'd rather not mess with it.
    //
    featureControl = __readmsr(IA32_FEATURE_CONTROL_MSR);
    if (!(featureControl & IA32_FEATURE_CONTROL_MSR_LOCK))
    {
        return FALSE;
    }

    //
    // The Feature Control MSR is locked-in (valid). Is VMX enabled in normal
    // operation mode?
    //
    if (!(featureControl & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX))
    {
        return FALSE;
    }

    //
    // Both the hardware and the firmware are allowing us to enter VMX mode.
    //
    return TRUE;
}

INT32
ShvVmxLaunchOnVp (
    _Inout_ PSHV_VP_DATA CONST VpData
    )
{
    UINT32 i;

    //
    // Initialize all the VMX-related MSRs by reading their value
    //
    for (i = 0; i < sizeof(VpData->MsrData) / sizeof(VpData->MsrData[0]); i++)
    {
        VpData->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);
    }

    //
    // Initialize the EPT structures
    //
    ShvVmxEptInitialize(VpData);

    //
    // Attempt to enter VMX root mode on this processor.
    //
    if (ShvVmxEnterRootModeOnVp(VpData) == FALSE)
    {
        //
        // We could not enter VMX Root mode
        //
        return SHV_STATUS_NOT_AVAILABLE;
    }

    //
    // Initialize the VMCS, both guest and host state.
    //
    ShvVmxSetupVmcsForVp(VpData);

    //
    // Launch the VMCS, based on the guest data that was loaded into the
    // various VMCS fields by ShvVmxSetupVmcsForVp. This will cause the
    // processor to jump to ShvVpRestoreAfterLaunch on success, or return
    // back to the caller on failure.
    //
    return ShvVmxLaunch();
}
