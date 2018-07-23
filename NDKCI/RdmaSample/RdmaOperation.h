/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaOperation.h

Abstract:

    Header file for working with RDMA_OPERATION objects

--*/

#pragma once

//
// Indicates the type of operation that is represented by an RDMA_OPERATION object
//
typedef enum _RDMA_OPERATION_TYPE
{
    //
    // The enum value 0 is reserved to represent an invalid type to help catch instances 
    // in which an RDMA operation type value is not initialized
    //
    RdmaOpUninitialized = 0,

    //
    // The operation represents a request from an upper level driver to transmit data to the 
    // peer using the send/receive channel (vs. the RDMA read/write channel)
    //
    RdmaOpSend,

    //
    // The operation represents a request from an upper level driver to RDMA read data directly
    // from the peer's memory.
    //
    RdmaOpRead,

    //
    // The operation represents a request from an upper level driver to RDMA write data directly
    // to the peer's memory.
    //
    RdmaOpWrite,
} RDMA_OPERATION_TYPE;

//
// Object that represents an RDMA operation. 
//
// An operation is composed of a series of SQ work requests that will be posted to the 
// socket's SQ to satisfy a call an upper level driver.
//
typedef struct _RDMA_OPERATION
{
    //
    // The type of the operation
    //
    RDMA_OPERATION_TYPE Type;

    //
    // Pointer to the first SQ work request in the operation's chain of SQ work requests 
    //
    SQ_WORK_REQUEST *SqWrList;

    //
    // The completion callback that will be invoked when the operation completes. An operation
    // is completed when the last SQ work request completes.  This callback  was specified by 
    // the upper level driver upon operation creation.
    //
    RDMA_COMPLETION_CALLBACK *CompletionCallback;

    //
    // An arbitrary value that will be passed as the context argument to the completion callback
    // routine. This context value was specified by the upper level driver as an argument upon
    // operation creation.
    //
    PVOID CompletionContext;

    //
    // Pointer to the RDMA_SOCKET object that represents the socket with which this operation
    // is associated.
    //
    RDMA_SOCKET *Socket;

    //
    // Completion status of the operation
    //
    NTSTATUS Status;

    //
    // The number of SQ work requests in the SqWrList
    //
    ULONG WrCount;

    struct
    {
        //
        // Pointer to the first LAM in the LAM chain that maps the local buffer that
        // contains the data to RDMA send to the peer, RDMA write to the peer, or will contain
        // the data that is RDMA read from the peer
        //
        LAM *LamChainHead;

        //
        // The number of bytes described by LamChainHead
        //
        ULONG LamChainBytesMapped;
    } Send, Read, Write;
} RDMA_OPERATION, *PRDMA_OPERATION;

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
_Success_(return != NULL)
RDMA_OPERATION *
RdmaAllocateOperation(
_In_ RDMA_SOCKET *Socket,
_In_ RDMA_OPERATION_TYPE Type);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildReadWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ UINT32 PrivilegedMrToken,
_In_ UINT64 RemoteAddress,
_In_ UINT32 RemoteToken);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildWriteWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ UINT32 PrivilegedMrToken,
_In_ UINT64 RemoteAddress,
_In_ UINT32 RemoteToken);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildSendWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ UINT32 PrivilegedMrToken,
_In_ BOOLEAN InvalidateRemoteMemoryRegion,
_In_ UINT32 RemoteMemoryRegionToken);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeOperation(
_In_ _Frees_ptr_ RDMA_OPERATION *Operation);

_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaSetOperationFailureStatus(
_Inout_ RDMA_OPERATION *Operation,
_In_ NTSTATUS FailureStatus);

_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaFreeOperationSqWrList(
_Inout_ RDMA_OPERATION *Operation);

_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaCompleteOperation(
_In_ _Frees_ptr_ RDMA_OPERATION *Operation);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
RdmaBuildSqWorkRequestHelper(
_Inout_ SQ_WORK_REQUEST *wr,
_In_ VOID *CompletionContext,
_In_ RDMA_SGL *Sgl,
_In_ ULONG TotalBytes,
_In_ VOID *SqContext);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
RdmaBuildSqWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ LAM* LamChainHead,
_In_ UINT32 PrivilegedMrToken,
_In_ USHORT MaxSgeCount,
_In_ ULONG MaxCbSize,
_In_ _Strict_type_match_ SQ_WORK_REQUEST_TYPE SqType,
_In_ VOID *SqContext);
