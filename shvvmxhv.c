/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

	shvvmxhv.c

Abstract:

	This module implements the Simple Hyper Visor itself.

Author:

	Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

	Hypervisor mode only, IRQL DIRQL_MAX

--*/

#include "shv.h"

DECLSPEC_NORETURN
VOID
ShvVmxResume(
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

ULONG_PTR
FORCEINLINE
ShvVmxRead(
	_In_ ULONG VmcsFieldId
)
{
	SIZE_T FieldData;

	//
	// Because VMXREAD returns an error code, and not the data, it is painful
	// to use in most circumstances. This simple function simplifies it use.
	//
	__vmx_vmread(VmcsFieldId, &FieldData);
	return FieldData;
}

VOID
ShvVmxHandleInvd(
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
ShvVmxHandleCpuid(
	_In_ PSHV_VP_STATE VpState
)
{
	INT cpu_info[4];

	//
	// Check for the magic CPUID sequence, and check that it is is coming from
	// Ring 0. Technically we could also check the RIP and see if this falls
	// in the expected function, but we may want to allow a sepaarate "unload"
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
	__cpuidex(cpu_info, (INT)VpState->VpRegs->Rax, (INT)VpState->VpRegs->Rcx);

	//
	// Check if this was CPUID 1h, which is the features request.
	//
	if (VpState->VpRegs->Rax == 1)
	{
		//
		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication.
		//
		cpu_info[2] |= 0x80000000;
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
ShvVmxHandleXsetbv(
	_In_ PSHV_VP_STATE VpState
)
{
	//
	// Simply issue the XSETBV instruction on the native logical processor.
	//
	_xsetbv((ULONG)VpState->VpRegs->Rcx,
		VpState->VpRegs->Rdx << 32 |
		VpState->VpRegs->Rax);
}

VOID
ShvVmxHandleVmx(
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
ShvVmxHandleExit(
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
		NT_ASSERT(FALSE);
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
EXTERN_C
VOID
ShvVmxEntryHandler(
	_In_ PCONTEXT Context
)
{
	SHV_VP_STATE guestContext;
	PSHV_VP_DATA vpData;

	//
	// Because we run with interrupts disabled during the entire hypervisor's
	// exit handling, raise the IRQL to HIGH_LEVEL which matches the reality of
	// the situation. This will block IPIs and the clock interrupt timer, which
	// means that it's critical to spend as little time here as possible. You
	// can expect CLOCK_WATCHDOG_TIMEOUT bugchecks to happen otherwise. If you
	// chose to enable interrupts note that this will result in further crashes
	// as we are not on a correct OS stack, and you will be hitting crashes if
	// RtlpCheckStackLimits is ever called, or if PatchGuard validates the RSP
	// value.
	//
	KeRaiseIrql(HIGH_LEVEL, &guestContext.GuestIrql);

	//
	// Because we had to use RCX when calling RtlCaptureContext, its true value
	// was actually pushed on the stack right before the call. Go dig into the
	// stack to find it, and overwrite the bogus value that's there now.
	//
	Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));

	//
	// Get the per-VP data for this processor.
	//
	vpData = &ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)];

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
	if (guestContext.ExitVm)
	{
		//
		// When running in VMX root mode, the processor will set limits of the
		// GDT and IDT to 0xFFFF (notice that there are no Host VMCS fields to
		// set these values). This causes problems with PatchGuard, which will
		// believe that the GDTR and IDTR have been modified by malware, and
		// eventually crash the system. Since we know what the original state
		// of the GDTR and IDTR was, simply restore it now.
		//
		__lgdt(&vpData->HostState.SpecialRegisters.Gdtr.Limit);
		__lidt(&vpData->HostState.SpecialRegisters.Idtr.Limit);

		//
		// Our DPC routine may have interrupted an arbitrary user process, and
		// not an idle or system thread as usually happens on an idle system.
		// Therefore if we return back to the original caller after turning off
		// VMX, it will keep our current "host" CR3 value which we set on entry
		// to the PML4 of the SYSTEM process. We want to return back with the
		// correct value of the "guest" CR3, so that the currently executing
		// process continues to run with its expected address space mappings.
		//
		__writecr3(ShvVmxRead(GUEST_CR3));

		//
		// Finally, set the stack and instruction pointer to whatever location
		// had the instruction causing our VM-Exit, such as ShvVpUninitialize.
		// This will effectively act as a longjmp back to that location.
		//
		Context->Rsp = guestContext.GuestRsp;
		Context->Rip = (ULONG64)guestContext.GuestRip;

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
		Context->Rip = (ULONG64)ShvVmxResume;
	}

	//
	// Restore the IRQL back to the original level
	//
	KeLowerIrql(guestContext.GuestIrql);

	//
	// Restore the context to either ShvVmxResume, in which case the CPU's VMX
	// facility will do the "true" return back to the VM (but without restoring
	// GPRs, which is why we must do it here), or to the original guest's RIP,
	// which we use in case an exit was requested. In this case VMX must now be
	// off, and this will look like a longjmp to the original stack and RIP.
	//
	RtlRestoreContext(Context, NULL);
}

