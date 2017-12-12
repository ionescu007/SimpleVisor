/*++

Copyright (c) Alex Ionescu.  All rights reserved.

Header Name:

    shv_x.h

Abstract:

    This header defines the externally visible structures and functions of the
    Simple Hyper Visor which are visible between the OS layer and SimpleVisor.

Author:

    Alex Ionescu (@aionescu) 29-Aug-2016 - Initial version

Environment:

    Kernel mode only.

--*/

#pragma once

#include "vmx.h"

#define SHV_STATUS_SUCCESS          0
#define SHV_STATUS_NOT_AVAILABLE    -1
#define SHV_STATUS_NO_RESOURCES     -2
#define SHV_STATUS_NOT_PRESENT      -3

#define _1GB                        (1 * 1024 * 1024 * 1024)
#define _2MB                        (2 * 1024 * 1024)

struct _SHV_CALLBACK_CONTEXT;

typedef
void
SHV_CPU_CALLBACK (
    _In_ struct _SHV_CALLBACK_CONTEXT* Context
    );
typedef SHV_CPU_CALLBACK *PSHV_CPU_CALLBACK;

typedef struct _SHV_SPECIAL_REGISTERS
{
    UINT64 Cr0;
    UINT64 Cr3;
    UINT64 Cr4;
    UINT64 MsrGsBase;
    UINT16 Tr;
    UINT16 Ldtr;
    UINT64 DebugControl;
    UINT64 KernelDr7;
    KDESCRIPTOR Idtr;
    KDESCRIPTOR Gdtr;
} SHV_SPECIAL_REGISTERS, *PSHV_SPECIAL_REGISTERS;

typedef struct _SHV_MTRR_RANGE
{
    UINT32 Enabled;
    UINT32 Type;
    UINT64 PhysicalAddressMin;
    UINT64 PhysicalAddressMax;
} SHV_MTRR_RANGE, *PSHV_MTRR_RANGE;

typedef struct _SHV_VP_DATA
{
    union
    {
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 ShvStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            SHV_SPECIAL_REGISTERS SpecialRegisters;
            CONTEXT ContextFrame;
            UINT64 SystemDirectoryTableBase;
            LARGE_INTEGER MsrData[17];
            SHV_MTRR_RANGE MtrrData[16];
            UINT64 VmxOnPhysicalAddress;
            UINT64 VmcsPhysicalAddress;
            UINT64 MsrBitmapPhysicalAddress;
            UINT64 EptPml4PhysicalAddress;
            UINT32 EptControls;
        };
    };

    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 MsrBitmap[PAGE_SIZE];
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPML4E Epml4[PML4E_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_PDPTE Epdpt[PDPTE_ENTRY_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_LARGE_PDE Epde[PDPTE_ENTRY_COUNT][PDE_ENTRY_COUNT];

    DECLSPEC_ALIGN(PAGE_SIZE) VMX_VMCS VmxOn;
    DECLSPEC_ALIGN(PAGE_SIZE) VMX_VMCS Vmcs;
} SHV_VP_DATA, *PSHV_VP_DATA;

C_ASSERT(sizeof(SHV_VP_DATA) == (KERNEL_STACK_SIZE + (512 + 5) * PAGE_SIZE));

VOID
_sldt (
    _In_ UINT16* Ldtr
    );

VOID
_ltr (
    _In_ UINT16 Tr
    );

VOID
_str (
    _In_ UINT16* Tr
    );

VOID
__lgdt (
    _In_ VOID* Gdtr
    );

INT32
ShvLoad (
    VOID
    );

VOID
ShvUnload (
    VOID
    );