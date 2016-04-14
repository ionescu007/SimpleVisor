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

VOID
ShvVpInitialize(
	_In_ PSHV_VP_DATA Data,
	_In_ ULONG64 SystemDirectoryTableBase
)
{
	//
	// Store the hibernation state of the processor, which contains all the
	// special registers and MSRs which are what the VMCS will need as part
	// of its setup. This avoids using assembly sequences and manually reading
	// this data.
	//
	KeSaveStateForHibernate(&Data->HostState);

	//
	// Then, capture the entire register state. We will need this, as once we
	// launch the VM, it will begin execution at the defined guest instruction
	// pointer, which is being captured as part of this call. In other words,
	// we will return right where we were, but with all our registers corrupted
	// by the VMCS/VMX initialization code (as guest state does not include
	// register state). By saving the context here, which includes all general
	// purpose registers, we guarantee that we return with all of our starting
	// register values as well!
	//
	RtlCaptureContext(&Data->HostState.ContextFrame);

	//
	// As per the above, we might be here because the VM has actually launched.
	// We can check this by verifying the value of the VmxEnabled field, which
	// is set to 1 right before VMXLAUNCH is performed. We do not use the Data
	// parameter or any other local register in this function, and in fact have
	// defined VmxEnabled as volatile, because as per the above, our register
	// state is currently dirty due to the VMCALL itself. By using the global
	// variable combined with an API call, we also make sure that the compiler
	// will not optimize this access in any way, even on LTGC/Ox builds.
	//
	if (ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].VmxEnabled == 1)
	{
		//
		// We now indicate that the VM has launched, and that we are about to
		// restore the GPRs back to their original values. This will have the
		// effect of putting us yet *AGAIN* at the previous line of code, but
		// this time the value of VmxEnabled will be two, bypassing the if and
		// else if checks.
		//
		ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].VmxEnabled = 2;

		//
		// And finally, restore the context, so that all register and stack
		// state is finally restored. Note that by continuing to reference the
		// per-VP data this way, the compiler will continue to generate non-
		// optimized accesses, guaranteeing that no previous register state
		// will be used.
		//
		RtlRestoreContext(&ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)].HostState.ContextFrame, NULL);
	}
	//
	// If we are in this branch comparison, it means that we have not yet
	// attempted to launch the VM, nor that we have launched it. In other
	// words, this is the first time in ShvVpInitialize. Because of this,
	// we are free to use all register state, as it is ours to use.
	//
	else if (Data->VmxEnabled == 0)
	{
		//
		// First, capture the value of the PML4 for the SYSTEM process, so that
		// all virtual processors, regardless of which process the current LP
		// has interrupted, can share the correct kernel address space.
		//
		Data->SystemDirectoryTableBase = SystemDirectoryTableBase;

		//
		// Then, attempt to initialize VMX on this processor
		//
		ShvVmxLaunchOnVp(Data);
	}
}

VOID
ShvVpUninitialize(
	_In_ PSHV_VP_DATA VpData
)
{
	INT dummy[4];
	UNREFERENCED_PARAMETER(VpData);

	//
	// Send the magic shutdown instruction sequence
	//
	__cpuidex(dummy, 0x41414141, 0x42424242);

	//
	// The processor will return here after the hypervisor issues a VMXOFF
	// instruction and restores the CPU context to this location. Unfortunately
	// because this is done with RtlRestoreContext which returns using "iretq",
	// this causes the processor to remove the RPL bits off the segments. As
	// the x64 kernel does not expect kernel-mode code to chang ethe value of
	// any segments, this results in the DS and ES segments being stuck 0x20,
	// and the FS segment being stuck at 0x50, until the next context switch.
	//
	// If the DPC happened to have interrupted either the idle thread or system
	// thread, that's perfectly fine (albeit unusual). If the DPC interrupted a
	// 64-bit long-mode thread, that's also fine. However if the DPC interrupts
	// a thread in compatibility-mode, running as part of WoW64, it will hit a
	// GPF instantenously and crash.
	//
	// Thus, set the segments to their correct value, one more time, as a fix.
	//
	ShvVmxCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);
}

VOID
ShvVpCallbackDpc(
	_In_ PRKDPC Dpc,
	_In_opt_ PVOID Context,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	PSHV_VP_DATA vpData;
	UNREFERENCED_PARAMETER(Dpc);
	NT_VERIFY(ARGUMENT_PRESENT(SystemArgument1));
	NT_VERIFY(ARGUMENT_PRESENT(SystemArgument2));

	//
	// Get the per-VP data for this logical processor
	//
	vpData = &ShvGlobalData->VpData[KeGetCurrentProcessorNumberEx(NULL)];

	//
	// Check if we are loading, or unloading
	//
	if (ARGUMENT_PRESENT(Context))
	{
		//
		// Initialize the virtual processor
		//
		ShvVpInitialize(vpData, (ULONG64)Context);
	}
	else
	{
		//
		// Tear down the virtual processor
		//
		ShvVpUninitialize(vpData);
	}

	//
	// Wait for all DPCs to synchronize at this point
	//
	KeSignalCallDpcSynchronize(SystemArgument2);

	//
	// Mark the DPC as being complete
	//
	KeSignalCallDpcDone(SystemArgument1);
}

PSHV_GLOBAL_DATA
ShvVpAllocateGlobalData(
	VOID
)
{
	PSHV_GLOBAL_DATA data;
	ULONG cpuCount, size;

	//
	// Query the number of logical processors, including those potentially in
	// groups other than 0. This allows us to support >64 processors.
	//
	cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	//
	// Each processor will receive its own slice of per-virtual processor data.
	//
	size = FIELD_OFFSET(SHV_GLOBAL_DATA, VpData) + cpuCount * sizeof(SHV_VP_DATA);

	//
	// Allocate a contiguous chunk of RAM to back this allocation.
	//
	data = (PSHV_GLOBAL_DATA)ShUtilvAllocateContiguousMemory(size);
	if (data != NULL)
	{
		//
		// Zero out the entire data region
		//
		__stosq((PULONGLONG)data, 0, size / sizeof(ULONGLONG));
	}

	//
	// Return what is hopefully a valid pointer, otherwise NULL.
	//
	return data;
}

