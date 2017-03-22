/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaAdapter.h

Abstract:

    Header file for functions for opening/closing RDMA_ADAPTER objects

--*/

#pragma once

typedef struct _RDMA_ADAPTER
{
    //
    // Pointer to the NDK_ADAPTER object that represents the RDMA adapter
    //
    NDK_ADAPTER *NdkAdapter;

    //
    // The alias (name) for this adapter
    //
    PWSTR InterfaceAlias;

    //
    // The interface index that uniquely identifies the RDMA adapter
    //
    IF_INDEX IfIndex;

    //
    // Stores the RQ depth for QPs that are created on this adapter
    //
    USHORT RqDepth;

    //
    // Stores the SQ depth for QPs that are created on this adapter
    //
    USHORT SqDepth;

    //
    // Maximum number of in-progress incoming read operations per QP
    //
    USHORT MaxInboundReadLimit;

    //
    // Maximum number of in-progress outgoing read operations per QP
    //
    USHORT MaxOutboundReadLimit;

    //
    // Maximum number of pages that a fast register memory region can map
    //
    USHORT MaxFrmrPageCount;

    //
    // Stores the maximum number of SGEs that an SQ work request (excluding Reads) can use
    //  when issued on this adapter.
    //
    USHORT MaxSqSges;

    //
    // The maximum number of SGEs that an NdkRead request can use when issued on this adapter
    //
    USHORT MaxReadSges;

    //
    // The maximum number of SGEs that an NdkReceive request can use when issued on this adapter
    //
    USHORT MaxReceiveSges;

    //
    // The maximum total bytes that a single NdkReceive request can use when issued on this adapter
    //
    ULONG MaxReceiveCbSize;

    //
    // The maximum total bytes that a single SQ work request (excluding Reads) can use when issued
    //  on this adapter
    //
    ULONG MaxSqCbSize;

    //
    // The maximum total bytes that a single NdkRead request can use when issued on this adapter
    //
    ULONG MaxReadCbSize;

    //
    // Whether this adapter supports interrupt moderation
    //
    BOOLEAN SupportsInterruptModeration : 1;

    //
    // Indicates whether the adapter's NDK provider supports
    // remote invalidation of memory region tokens (requires
    // NDK version >= 1.2)
    //
    BOOLEAN SupportsRemoteInvalidation : 1;

    //
    // Indicates whether the adapter's NDK provider supports the
    // NDK_OP_FLAG_DEFER work request flag (requires NDK version
    // >= 1.2)
    //
    BOOLEAN SupportsDeferredPosting : 1;
} RDMA_ADAPTER, *PRDMA_ADAPTER;

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaOpenAdapter(
_In_ IF_INDEX IfIndex,
_Outptr_ RDMA_ADAPTER **oAdapter
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
RdmaCloseAdapter(
_In_ _Frees_ptr_ RDMA_ADAPTER *Adapter
);
