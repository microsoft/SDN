/*++
Copyright (c) Microsoft Corporation

Module Name:

    WorkRequest.h

Abstract:

    Header file for working with SQ_WORK_REQUEST objects.

--*/

#pragma once

typedef enum _SQ_WORK_REQUEST_TYPE
{
    //
    // The enum value 0 is reserved to represent an invalid type to help catch instances 
    // in which an SQ work request type value is not initialized
    //
    SQUninitialized = 0,

    //
    // The object represents an NdkSend or NdkSendAndInvalidate work item
    //
    SQSend,

    //
    // The object represents an NdkRead work request
    //
    SQRead,

    //
    // The object represents an NdkWrite work request
    //
    SQWrite,

    //
    // The object represents an NdkFastRegister work request
    //
    SQFastRegister,

    //
    // The object represents an NdkInvalidate work request
    //
    SQInvalidate,
} SQ_WORK_REQUEST_TYPE;

typedef struct _SQ_WORK_REQUEST_SEND
{
    //
    // The work request's scatter/gather list
    //
    NDK_SGE *NdkSgl;

    //
    // The bytes that will be sent to the peer in the RDMA Send represented by
    // this work request
    //
    ULONG BytesSent;

    //
    // The token of the remote memory region to invalidate. This token
    // is only used when the InvalidateRemoteMemoryRegionToken field's
    // value is non-zero.
    //
    UINT32 RemoteMemoryRegionToken;

    //
    // The number of scatter/gather entries in the scatter/gather list
    //
    USHORT nSge;

    //
    // If non-zero, then the send request will be queued by calling
    // NdkSendAndInvalidate(), passing RemoteMemoryRegionToken as 
    // the token to be invalidated.
    //
    BOOLEAN InvalidateRemoteMemoryRegion;
} SQ_WORK_REQUEST_SEND, *PSQ_WORK_REQUEST_SEND;

typedef struct _SQ_WORK_REQUEST_WRITE
{
    //
    // The work request's scatter/gather list
    //
    NDK_SGE *NdkSgl;

    //
    // The number of scatter/gather entries in the scatter/gather list
    //
    USHORT nSge;

    //
    // The bytes that will be transferred in the RDMA read/write request 
    // represented by this work request
    //
    ULONG BytesTransferred;

    //
    // The remote address to RDMA read from or write to
    //
    UINT64 RemoteAddress;

    //
    // The token that identifies the remotely registered memory to read/write
    //
    UINT32 RemoteToken;
} SQ_WORK_REQUEST_WRITE, *PSQ_WORK_REQUEST_WRITE, SQ_WORK_REQUEST_READ, *PSQ_WORK_REQUEST_READ;

typedef struct _SQ_WORK_REQUEST_FAST_REGISTER
{
    //
    // The memory region initialized for fast registration to fast register
    //
    NDK_MR *NdkMr;

    //
    // Pointer to the array of LAM adapter pages that will be fast registered
    //
    CONST NDK_LOGICAL_ADDRESS *AdapterPageArray;

    //
    // The base address of the registered memory region. The 12 least significant bits
    // store the page offset of the first byte of the registered region within the 
    // first page of physical memory that backs the registered region. The upper bits 
    // represent an arbitrary made-up address to refer to the first page of the registered 
    // region.
    //
    VOID *BaseVirtualAddress;

    //
    // The number of bytes to fast register
    //
    SIZE_T Length;
    
    //
    // The number of LAM adapter pages in the adapter page array
    //
    ULONG AdapterPageCount;
} SQ_WORK_REQUEST_FAST_REGISTER, *PSQ_WORK_REQUEST_FAST_REGISTER;

typedef struct _SQ_WORK_REQUEST_INVALIDATE
{
    //
    // Pointer to the FRMR / MW to invalidate
    //
    NDK_OBJECT_HEADER *NdkMrOrMw;
} SQ_WORK_REQUEST_INVALIDATE, *PSQ_WORK_REQUEST_INVALIDATE;

//
// An SQ work request is a unit of work that is queued to a send queue (SQ), performed by the
// SQ's RNIC, then completed to the send completion queue (SCQ). The following types of work
// requests exist
//
// - Send: transmits data to the peer
// - Fast Register: registers a memory region that has been pre-initialized for fast 
//   registration
// - Invalidate: invalidates a previously fast-registered memory region
// - Read: RDMA reads data directly from the peer's memory into local memory
// - Write: RDMA writes data directly from local memery into the peer's memory
//
typedef struct _SQ_WORK_REQUEST
{
    //
    // ListEntry to link the work requests in queue to serialize access to the Scq
    //
    LIST_ENTRY ListEntry;

    //
    // The next work request in a chain of related work requests belonging to a single operation
    //
    struct _SQ_WORK_REQUEST *Next;

    //
    // Pointer to the routine that will be invoked when the SQ work request is finished being
    // processed. A completion callback must be specified.
    //
    RDMA_COMPLETION_CALLBACK *CompletionCallback;

    //
    // Arbitrary pointer value that is passed as the Context argument of the CompletionCallback
    // routine.
    //
    PVOID CompletionContext;

    //
    // Type of the SQ work request
    //
    SQ_WORK_REQUEST_TYPE Type;

    //
    // Type-specific SQ work request parameters
    //
    union
    {
        SQ_WORK_REQUEST_SEND Send;
        SQ_WORK_REQUEST_WRITE Write;
        SQ_WORK_REQUEST_READ Read;
        SQ_WORK_REQUEST_FAST_REGISTER FastRegister;
        SQ_WORK_REQUEST_INVALIDATE Invalidate;
    };
} SQ_WORK_REQUEST, *PSQ_WORK_REQUEST;

//
// Async context passed to SqGenericCompletionCallback
//
typedef struct _SQ_WORK_REQUEST_ASYNC_CONTEXT
{
    //
    // Pointer to the SQ work request that just completed
    //
    SQ_WORK_REQUEST *SqWorkRequest;

    //
    // Event that is set when the SQ work request completes
    //
    KEVENT Event;

    //
    // The status of the completed SQ work request
    //
    NTSTATUS Status;
} SQ_WORK_REQUEST_ASYNC_CONTEXT, *PSQ_WORK_REQUEST_ASYNC_CONTEXT;

RDMA_COMPLETION_CALLBACK SqGenericCompletionCallback;

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
_Success_(return != NULL)
SQ_WORK_REQUEST *
RdmaAllocateSqWorkRequest(
_In_ _Strict_type_match_ SQ_WORK_REQUEST_TYPE Type);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeSqWorkRequest(
_In_ _Frees_ptr_ SQ_WORK_REQUEST *wr);
