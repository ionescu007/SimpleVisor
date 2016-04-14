/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Module Name:

	shv.c

Abstract:

	This module implements the Driver Entry/Unload for the Simple Hyper Visor.

Author:

	Alex Ionescu (@aionescu) 16-Mar-2016 - Initial version

Environment:

	Kernel mode only.

--*/

#include "shv.h"

// ===========================================================================
//
// GLOBAL DATA
//
// ===========================================================================

PSHV_GLOBAL_DATA ShvGlobalData;

// ===========================================================================
//
// LOCAL PROTOTYPES
//
// ===========================================================================

DRIVER_INITIALIZE ShvInitialize;
DRIVER_UNLOAD ShvUnload;

// ===========================================================================
//
// PUBLIC FUNCTIONS
//
// ===========================================================================

VOID
ShvUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	//
	// Attempt to exit VMX root mode on all logical processors. This will
	// broadcast a DPC interrupt which will execute the callback routine in
	// parallel on the LPs. Send the callback routine a NULL context in order
	// to indicate that this is the unload, not load, path.
	//
	// Note that if SHV is not loaded on any of the LPs, this routine will not
	// perform any work, but will not fail in any way.
	//
	KeGenericCallDpc(ShvVpCallbackDpc, NULL);

	//
	// If the SHV was not fully/correctly loaded, we may not have global data
	// allocated yet. Check for that before freeing it.
	//
	// Note that KeGenericCallDpc is guaranteed to return only after all LPs
	// have succesfully executed the DPC and synchronized. This means that SHV
	// is fully unloaded, and no further VMEXITs can return. It is safe to free
	// this data.
	//
	if (ShvGlobalData != NULL)
	{
		MmFreeContiguousMemory(ShvGlobalData);
	}

	//
	// Indicate unload
	//
	DbgPrintEx(77, 0, "The SHV has been uninstalled.\n");
}

NTSTATUS
ShvInitialize(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	//
	// Detect if a hypervisor is already loaded, using the standard high bit in
	// the ECX features register. Hypervisors may choose to hide from this, at
	// which point entering VMX root mode will fail (unless a shadows VMCS is
	// used).
	//
	if (HviIsAnyHypervisorPresent())
	{
		return STATUS_HV_OBJECT_IN_USE;
	}

	//
	// Next, detect if the hardware appears to support VMX root mode to start.
	// No attempts are made to enable this if it is lacking or disabled.
	//
	if (!ShvVmxProbe())
	{
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}

	//
	// Allocate the global shared data which all virtual processors will share.
	//
	ShvGlobalData = ShvVpAllocateGlobalData();
	if (!ShvGlobalData)
	{
		return STATUS_HV_INSUFFICIENT_BUFFER;
	}

	//
	// Attempt to enter VMX root mode on all logical processors. This will
	// broadcast a DPC interrupt which will execute the callback routine in
	// parallel on the LPs. Send the callback routine the physical address of
	// the PML4 of the system process, which is what this driver entrypoint
	// should be executing in.
	//
	NT_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);
	KeGenericCallDpc(ShvVpCallbackDpc, (PVOID)__readcr3());

	//
	// A hypervisor should now be seen as present on this (and all other) LP,
	// as the SHV correctly handles CPUID ECX features register.
	//
	if (HviIsAnyHypervisorPresent() == FALSE)
	{
		MmFreeContiguousMemory(ShvGlobalData);
		return STATUS_HV_NOT_PRESENT;
	}

	//
	// Make the driver (and SHV itself) unloadable, and indicate success.
	//
	DriverObject->DriverUnload = ShvUnload;
	DbgPrintEx(77, 0, "The SHV has been installed.\n");
	return STATUS_SUCCESS;
}
