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

BOOLEAN
ShvVmxEnterRootModeOnVp(
	_In_ PSHV_VP_DATA VpData
)
{
	PKSPECIAL_REGISTERS Registers = &VpData->HostState.SpecialRegisters;

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
	// Capture the revision ID for the VMXON and VMCS region
	//
	VpData->VmxOn.RevisionId = VpData->MsrData[0].LowPart;
	VpData->Vmcs.RevisionId = VpData->MsrData[0].LowPart;

	//
	// Store the physical addresses of all per-LP structures allocated
	//
	VpData->VmxOnPhysicalAddress = MmGetPhysicalAddress(&VpData->VmxOn).QuadPart;
	VpData->VmcsPhysicalAddress = MmGetPhysicalAddress(&VpData->Vmcs).QuadPart;
	VpData->MsrBitmapPhysicalAddress = MmGetPhysicalAddress(ShvGlobalData->MsrBitmap).QuadPart;

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
ShvVmxSetupVmcsForVp(
	_In_ PSHV_VP_DATA VpData
)
{
	PKPROCESSOR_STATE state = &VpData->HostState;
	VMX_GDTENTRY64 vmxGdtEntry;

	//
	// Begin by setting the link pointer to the required value for 4KB VMCS.
	//
	__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

	//
	// Load the MSR bitmap. Unlike other bitmaps, not having an MSR bitmap will
	// trap all MSRs, so have to allocate an empty one.
	//
	__vmx_vmwrite(MSR_BITMAP, VpData->MsrBitmapPhysicalAddress);

	//
	// Enable support for RDTSCP and XSAVES/XRESTORES in the guest. Windows 10
	// makes use of both of these instructions if the CPU supports it. By using
	// ShvUtilAdjustMsr, these options will be ignored if this processor does
	// not actully support the instructions to begin with.
	//
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL,
		ShvUtilAdjustMsr(VpData->MsrData[11],
			SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_XSAVES));

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
			CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));

	//
	// If any interrupts were pending upon entering the hypervisor, acknowledge
	// them when we're done. And make sure to enter us in x64 mode at all times
	//
	__vmx_vmwrite(VM_EXIT_CONTROLS,
		ShvUtilAdjustMsr(VpData->MsrData[15],
			VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_IA32E_MODE));

	//
	// As we exit back into the guest, make sure to exist in x64 mode as well.
	//
	__vmx_vmwrite(VM_ENTRY_CONTROLS,
		ShvUtilAdjustMsr(VpData->MsrData[16],
			VM_ENTRY_IA32E_MODE));

	//
	// Load the CS Segment (Ring 0 Code)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK);

	//
	// Load the SS Segment (Ring 0 Data)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK);

	//
	// Load the DS Segment (Ring 3 Data)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK);

	//
	// Load the ES Segment (Ring 3 Data)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK);

	//
	// Load the FS Segment (Ring 3 Compatibility-Mode TEB)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK);

	//
	// Load the GS Segment (Ring 3 Data if in Compatibility-Mode, MSR-based in Long Mode)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK);

	//
	// Load the Task Register (Ring 0 TSS)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_TR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_TR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~RPL_MASK);

	//
	// Load the Local Descriptor Table (Ring 0 LDT on Redstone)
	//
	ShvUtilConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_LDTR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_LDTR_BASE, vmxGdtEntry.Base);

	//
	// Now load the GDT itself
	//
	__vmx_vmwrite(GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit);
	__vmx_vmwrite(HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);

	//
	// And then the IDT
	//
	__vmx_vmwrite(GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit);
	__vmx_vmwrite(HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);

	//
	// Load CR0
	//
	__vmx_vmwrite(CR0_READ_SHADOW, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(HOST_CR0, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(GUEST_CR0, state->SpecialRegisters.Cr0);

	//
	// Load CR3 -- do not use the current process' address space for the host,
	// because we may be executing in an arbitrary user-mode process right now
	// as part of the DPC interrupt we execute in.
	//
	__vmx_vmwrite(HOST_CR3, VpData->SystemDirectoryTableBase);
	__vmx_vmwrite(GUEST_CR3, state->SpecialRegisters.Cr3);

	//
	// Load CR4
	//
	__vmx_vmwrite(HOST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(GUEST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(CR4_READ_SHADOW, state->SpecialRegisters.Cr4);

	//
	// Load debug MSR and register (DR7)
	//
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl);
	__vmx_vmwrite(GUEST_DR7, state->SpecialRegisters.KernelDr7);

	//
	// Finally, load the guest stack, instruction pointer, and rflags, which
	// corresponds exactly to the location where RtlCaptureContext will return
	// to inside of ShvVpInitialize.
	//
	__vmx_vmwrite(GUEST_RSP, state->ContextFrame.Rsp);
	__vmx_vmwrite(GUEST_RIP, state->ContextFrame.Rip);
	__vmx_vmwrite(GUEST_RFLAGS, state->ContextFrame.EFlags);

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
	__vmx_vmwrite(HOST_RSP, (ULONG_PTR)VpData->ShvStackLimit + KERNEL_STACK_SIZE - sizeof(CONTEXT));
	__vmx_vmwrite(HOST_RIP, (ULONG_PTR)ShvVmxEntry);
}

BOOLEAN
ShvVmxProbe(
	VOID
)
{
	INT cpu_info[4];
	ULONGLONG featureControl;

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

VOID
ShvVmxLaunchOnVp(
	_In_ PSHV_VP_DATA VpData
)
{
	ULONG i;

	//
	// Initialize all the VMX-related MSRs by reading their value
	//
	for (i = 0; i < RTL_NUMBER_OF(VpData->MsrData); i++)
	{
		VpData->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);
	}

	//
	// Attempt to enter VMX root mode on this processor.
	//
	if (ShvVmxEnterRootModeOnVp(VpData))
	{
		//
		// Initialize the VMCS, both guest and host state.
		//
		ShvVmxSetupVmcsForVp(VpData);

		//
		// Record that VMX is now enabled
		//
		VpData->VmxEnabled = 1;

		//
		// Launch the VMCS, based on the guest data that was loaded into the
		// various VMCS fields by ShvVmxSetupVmcsForVp. This will cause the
		// processor to jump to the return address of RtlCaptureContext in
		// ShvVpInitialize, which called us.
		//
		__vmx_vmlaunch();

		//
		// If we got here, either VMCS setup failed in some way, or the launch
		// did not proceed as planned. Because VmxEnabled is not set to 1, this
		// will correctly register as a failure.
		//
		__vmx_off();
	}
}
