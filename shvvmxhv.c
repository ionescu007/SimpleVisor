/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

    shvvmxhv.c

Abstract:

    This module implements the Simple Hyper Visor itself.

Author:

    Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

    Hypervisor mode only, IRQL MAX_IRQL

--*/

#include "ia32.h"
#include "shv.h"

DECLSPEC_NORETURN
VOID
ShvVmxResume (
    VOID
    )
{
    //
    // Issue a VMXRESUME. The reason that we've defined an entire function for
    // this sole instruction is both so that we can use it as the target of the
    // VMCS when re-entering the VM After a VM-Exit, as well as so that we can
    // decorate it with the DECLSPEC_NORETURN marker, which is not set on the
    // intrinsic (as it can fail in case of an error).
    //
    __vmx_vmresume();
}

uintptr_t
FORCEINLINE
ShvVmxRead (
    _In_ UINT32 VmcsFieldId
    )
{
    size_t FieldData;

    //
    // Because VMXREAD returns an error code, and not the data, it is painful
    // to use in most circumstances. This simple function simplifies it use.
    //
    __vmx_vmread(VmcsFieldId, &FieldData);
    return FieldData;
}

INT32
ShvVmxLaunch (
    VOID
    )
{
    INT32 failureCode;

    //
    // Launch the VMCS
    //
    __vmx_vmlaunch();

    //
    // If we got here, either VMCS setup failed in some way, or the launch
    // did not proceed as planned.
    //
    failureCode = (INT32)ShvVmxRead(VM_INSTRUCTION_ERROR);
    __vmx_off();

    //
    // Return the error back to the caller
    //
    return failureCode;
}

VOID
ShvVmxHandleInvd (
    VOID
    )
{
    //
    // This is the handler for the INVD instruction. Technically it may be more
    // correct to use __invd instead of __wbinvd, but that intrinsic doesn't
    // actually exist. Additionally, the Windows kernel (or HAL) don't contain
    // any example of INVD actually ever being used. Finally, Hyper-V itself
    // handles INVD by issuing WBINVD as well, so we'll just do that here too.
    //
    __wbinvd();
}

VOID
ShvVmxHandleCpuid (
    _In_ PSHV_VP_STATE VpState
    )
{
    INT32 cpu_info[4];

    //
    // Check for the magic CPUID sequence, and check that it is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point.
    //
    if ((VpState->VpRegs->Rax == 0x41414141) &&
        (VpState->VpRegs->Rcx == 0x42424242) &&
        ((ShvVmxRead(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM))
    {
        VpState->ExitVm = TRUE;
        return;
    }

    //
    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs.
    //
    __cpuidex(cpu_info, (INT32)VpState->VpRegs->Rax, (INT32)VpState->VpRegs->Rcx);

    //
    // Check if this was CPUID 1h, which is the features request.
    //
    if (VpState->VpRegs->Rax == 1)
    {
        ((CPUID_EAX_01*)&cpu_info)->CpuidFeatureInformationEcx.VirtualMachineExtensions = FALSE;
    }
    else if (VpState->VpRegs->Rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // Return our interface identifier
        //
        cpu_info[0] = ' vhS';
    }

    //
    // Copy the values from the logical processor registers into the VP GPRs.
    //
    VpState->VpRegs->Rax = cpu_info[0];
    VpState->VpRegs->Rbx = cpu_info[1];
    VpState->VpRegs->Rcx = cpu_info[2];
    VpState->VpRegs->Rdx = cpu_info[3];
}

VOID
ShvVmxHandleXsetbv (
    _In_ PSHV_VP_STATE VpState
    )
{
	
	//
    // Simply issue the XSETBV instruction on the native logical processor.
    //

    _xsetbv((UINT32)VpState->VpRegs->Rcx,
            VpState->VpRegs->Rdx << 32 |
            VpState->VpRegs->Rax);
}

VOID
ShvVmxHandleVmx (
    _In_ PSHV_VP_STATE VpState
    )
{
    //
    // Set the CF flag, which is how VMX instructions indicate failure
    //
    VpState->GuestEFlags |= 0x1; // VM_FAIL_INVALID

    //
    // RFLAGs is actually restored from the VMCS, so update it here
    //
    __vmx_vmwrite(GUEST_RFLAGS, VpState->GuestEFlags);
}

VOID
ShvSwitchGuestMode(UINT64 isPagingEnabled)
{
    IA32_EFER_REGISTER guestEfer;
	guestEfer.AsUInt = ShvVmxRead(VMCS_GUEST_EFER);
    guestEfer.Ia32EModeActive = isPagingEnabled;
    __vmx_vmwrite(VMCS_GUEST_EFER, guestEfer.AsUInt);

    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;
    vmEntryControls.AsUInt = ShvVmxRead(VMCS_CTRL_VMENTRY_CONTROLS);
    vmEntryControls.Ia32EModeGuest = guestEfer.Ia32EModeActive;
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, vmEntryControls.AsUInt);
}

VOID
ShvVmxHandleCrAccess (
    _In_ PSHV_VP_STATE VpState
)
{
    VMX_EXIT_QUALIFICATION_MOV_CR qualification;
    qualification.AsUInt = ShvVmxRead(VMCS_EXIT_QUALIFICATION);
    UINT64 newCrValue = ShvSelectEffectiveRegister(VpState->VpRegs, qualification.GeneralPurposeRegister);

    if (VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR != qualification.AccessType) {
        return;
    }
	
    switch (qualification.ControlRegister)
    {
		case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, newCrValue);
            CR0 wantedCr0;
            wantedCr0.AsUInt = newCrValue;
            CR0 currentCr0;
            currentCr0.AsUInt = ShvVmxRead(VMCS_GUEST_CR0);
            if (wantedCr0.PagingEnable != currentCr0.PagingEnable || !wantedCr0.PagingEnable) {
                CR0 tempCr0;
                tempCr0.AsUInt = wantedCr0.AsUInt;
                wantedCr0.AsUInt = ShvAdjustCr0(wantedCr0.AsUInt);

            	wantedCr0.PagingEnable = tempCr0.PagingEnable;
                wantedCr0.ProtectionEnable = tempCr0.ProtectionEnable;
            	
                ShvSwitchGuestMode(wantedCr0.PagingEnable);
                __vmx_vmwrite(VMCS_GUEST_CR0, wantedCr0.AsUInt);

            } else {
                __vmx_vmwrite(VMCS_GUEST_CR0, ShvAdjustCr0(newCrValue));
            }
    		break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
            __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, newCrValue);
            __vmx_vmwrite(VMCS_GUEST_CR4, ShvAdjustCr4(newCrValue));
            break;
        default:
            break;
    }
}

VOID
ShvVmxHandleMsrRead(
    _In_ PSHV_VP_STATE VpState
)
{
    UINT64 msr = VpState->VpRegs->Rcx;
    UINT64 msrData = __readmsr((UINT32)msr);
    VpState->VpRegs->Rax = msrData & MAX_UINT32;
    VpState->VpRegs->Rdx = (msrData >> 32) & MAX_UINT32;
}

VOID
ShvVmxHandleMsrWrite(
    _In_ PSHV_VP_STATE VpState
)
{
    UINT64 msr = VpState->VpRegs->Rcx;
    UINT64 msrData = (VpState->VpRegs->Rax & MAX_UINT32) | ((VpState->VpRegs->Rdx >> 32) & MAX_UINT32);
    __writemsr((UINT32)msr, msrData);
}

VOID
ShvVmxHandleInit(
    _In_ PSHV_VP_STATE VpState
)
{
    RFLAGS rflags;
    rflags.AsUInt = 0;
    rflags.ReadAs1 = 1;
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags.AsUInt);
    VpState->GuestEFlags = rflags.AsUInt;

    __vmx_vmwrite(VMCS_GUEST_RIP, 0xfff0);
    VpState->GuestRip = 0xfff0;

    __vmx_vmwrite(VMCS_GUEST_RSP, 0);
    VpState->GuestRsp = 0;

    __writecr2(0);
    __vmx_vmwrite(VMCS_GUEST_CR3, 0);

    CR0 cr0;
    cr0.AsUInt = ShvAdjustCr0(0x60000010);
    cr0.PagingEnable = 0;
    cr0.ProtectionEnable = 0;
    __vmx_vmwrite(VMCS_GUEST_CR0, cr0.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, 0x60000010);

    __vmx_vmwrite(VMCS_GUEST_CR4, ShvAdjustCr4(0));
    __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);

    VMX_SEGMENT_ACCESS_RIGHTS accessRights;
    accessRights.AsUInt = 0;

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
    accessRights.DescriptorType = TRUE;
    accessRights.Present = TRUE;
    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, 0xf000);
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, 0xffff0000);
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, accessRights.AsUInt);

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, accessRights.AsUInt);
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, accessRights.AsUInt);
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, accessRights.AsUInt);
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, accessRights.AsUInt);
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, accessRights.AsUInt);

    int cpuId[4];
    __cpuid(cpuId, CPUID_VERSION_INFORMATION);

    CPUID_EAX_01 cpuVersionInfo;
    cpuVersionInfo.CpuidVersionInformation.AsUInt = cpuId[0];
    UINT64 extendedModel = cpuVersionInfo.CpuidVersionInformation.ExtendedModelId;
    
    VpState->VpRegs->Rdx = 0x600 | (extendedModel << 16);
    VpState->VpRegs->Rbx = 0;
    VpState->VpRegs->Rcx = 0;
    VpState->VpRegs->Rsi = 0;
    VpState->VpRegs->Rdi = 0;
    VpState->VpRegs->Rbp = 0;

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_LDT;
    accessRights.DescriptorType = FALSE;
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, accessRights.AsUInt);

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, 0);
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, 0xffff);
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, accessRights.AsUInt);

    __writedr(0, 0);
    __writedr(1, 0);
    __writedr(2, 0);
    __writedr(3, 0);
    __writedr(6, 0xffff0ff0);
    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    VpState->VpRegs->R8 = 0;
    VpState->VpRegs->R9 = 0;
    VpState->VpRegs->R10 = 0;
    VpState->VpRegs->R11 = 0;
    VpState->VpRegs->R12 = 0;
    VpState->VpRegs->R13 = 0;
    VpState->VpRegs->R14 = 0;
    VpState->VpRegs->R15 = 0;

    __vmx_vmwrite(VMCS_GUEST_BNDCFGS, 0);
    __vmx_vmwrite(VMCS_GUEST_EFER, 0);
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, 0);
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, 0);

    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;
    vmEntryControls.AsUInt = ShvVmxRead(VMCS_CTRL_VMENTRY_CONTROLS);
    vmEntryControls.Ia32EModeGuest = FALSE;
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, vmEntryControls.AsUInt);

    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, VmxWaitForSipi);
}

VOID
ShvVmxHandleSipi(
    _In_ PSHV_VP_STATE VpState
)
{
    UINT64 vector = ShvVmxRead(VMCS_EXIT_QUALIFICATION);
    __vmx_vmwrite(VMCS_GUEST_RIP, 0);
    VpState->VpRegs->Rip = 0;
    VpState->GuestRip = 0;

    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, ((UINT64)vector) << 8);
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, ((UINT64)vector) << 12);
    
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, VmxActive);
}

VOID
ShvVmxHandleExit (
    _In_ PSHV_VP_STATE VpState
    )
{
    //
    // This is the generic VM-Exit handler. Decode the reason for the exit and
    // call the appropriate handler. As per Intel specifications, given that we
    // have requested no optional exits whatsoever, we should only see CPUID,
    // INVD, XSETBV and other VMX instructions. GETSEC cannot happen as we do
    // not run in SMX context.
    //
	switch (VpState->ExitReason)
    {
    case EXIT_REASON_CPUID:
        ShvVmxHandleCpuid(VpState);
        break;
    case EXIT_REASON_INVD:
        ShvVmxHandleInvd();
        break;
    case EXIT_REASON_XSETBV:
        ShvVmxHandleXsetbv(VpState);
        break;
    case EXIT_REASON_CR_ACCESS:
        ShvVmxHandleCrAccess(VpState);
        break;
    case EXIT_REASON_MSR_READ:
        ShvVmxHandleMsrRead(VpState);
    	break;
    case EXIT_REASON_MSR_WRITE:
        ShvVmxHandleMsrWrite(VpState);
        break;
    case EXIT_REASON_INIT:
        ShvVmxHandleInit(VpState);
        break;
    case EXIT_REASON_SIPI:
        ShvVmxHandleSipi(VpState);
        break;
    case EXIT_REASON_VMCALL:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
        ShvVmxHandleVmx(VpState);
        break;
    default:
        break;
    }

    //
    // Move the instruction pointer to the next instruction after the one that
    // caused the exit. Since we are not doing any special handling or changing
    // of execution, this can be done for any exit reason.
    //
    VpState->GuestRip += ShvVmxRead(VM_EXIT_INSTRUCTION_LEN);
    __vmx_vmwrite(GUEST_RIP, VpState->GuestRip);
}

DECLSPEC_NORETURN
VOID
ShvVmxEntryHandler (
    _In_ PCONTEXT Context
    )
{
    SHV_VP_STATE guestContext;
    PSHV_VP_DATA vpData;

    //
    // Because we had to use RCX when calling ShvOsCaptureContext, its value
    // was actually pushed on the stack right before the call. Go dig into the
    // stack to find it, and overwrite the bogus value that's there now.
    //
    Context->Rcx = *(UINT64*)((uintptr_t)Context - sizeof(Context->Rcx));

    //
    // Get the per-VP data for this processor.
    //
    vpData = (VOID*)((uintptr_t)(Context + 1) - KERNEL_STACK_SIZE);

    //
    // Build a little stack context to make it easier to keep track of certain
    // guest state, such as the RIP/RSP/RFLAGS, and the exit reason. The rest
    // of the general purpose registers come from the context structure that we
    // captured on our own with RtlCaptureContext in the assembly entrypoint.
    //
    guestContext.GuestEFlags = ShvVmxRead(GUEST_RFLAGS);
    guestContext.GuestRip = ShvVmxRead(GUEST_RIP);
    guestContext.GuestRsp = ShvVmxRead(GUEST_RSP);
    guestContext.ExitReason = ShvVmxRead(VM_EXIT_REASON) & 0xFFFF;
    guestContext.VpRegs = Context;
    guestContext.ExitVm = FALSE;

    //
    // Call the generic handler
    //
    ShvVmxHandleExit(&guestContext);

    //
    // Did we hit the magic exit sequence, or should we resume back to the VM
    // context?
    //
    if (guestContext.ExitVm != FALSE)
    {
        //
        // Return the VP Data structure in RAX:RBX which is going to be part of
        // the CPUID response that the caller (ShvVpUninitialize) expects back.
        // Return confirmation in RCX that we are loaded
        //
        Context->Rax = (uintptr_t)vpData >> 32;
        Context->Rbx = (uintptr_t)vpData & 0xFFFFFFFF;
        Context->Rcx = 0x43434343;

        //
        // Perform any OS-specific CPU uninitialization work
        //
        ShvOsUnprepareProcessor(vpData);

        //
        // Our callback routine may have interrupted an arbitrary user process,
        // and therefore not a thread running with a systemwide page directory.
        // Therefore if we return back to the original caller after turning off
        // VMX, it will keep our current "host" CR3 value which we set on entry
        // to the PML4 of the SYSTEM process. We want to return back with the
        // correct value of the "guest" CR3, so that the currently executing
        // process continues to run with its expected address space mappings.
        //
        __writecr3(ShvVmxRead(GUEST_CR3));

        //
        // Finally, restore the stack, instruction pointer and EFLAGS to the
        // original values present when the instruction causing our VM-Exit
        // execute (such as ShvVpUninitialize). This will effectively act as
        // a longjmp back to that location.
        //
        Context->Rsp = guestContext.GuestRsp;
        Context->Rip = (UINT64)guestContext.GuestRip;
        Context->EFlags = (UINT32)guestContext.GuestEFlags;

        //
        // Turn off VMX root mode on this logical processor. We're done here.
        //
        __vmx_off();
    }
    else
    {
        //
        // Because we won't be returning back into assembly code, nothing will
        // ever know about the "pop rcx" that must technically be done (or more
        // accurately "add rsp, 4" as rcx will already be correct thanks to the
        // fixup earlier. In order to keep the stack sane, do that adjustment
        // here.
        //
        Context->Rsp += sizeof(Context->Rcx);

        //
        // Return into a VMXRESUME intrinsic, which we broke out as its own
        // function, in order to allow this to work. No assembly code will be
        // needed as RtlRestoreContext will fix all the GPRs, and what we just
        // did to RSP will take care of the rest.
        //
        Context->Rip = (UINT64)ShvVmxResume;
    }

    //
    // Restore the context to either ShvVmxResume, in which case the CPU's VMX
    // facility will do the "true" return back to the VM (but without restoring
    // GPRs, which is why we must do it here), or to the original guest's RIP,
    // which we use in case an exit was requested. In this case VMX must now be
    // off, and this will look like a longjmp to the original stack and RIP.
    //
    ShvOsRestoreContext(Context);
}

