/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaOperation.c

Abstract:

    Contains functions for working with RDMA_OPERATION objects that correspond to socket
    level requests and broken up into a chain or related SQ_WORK_REQUESTS

--*/

#include "precomp.h"

//
// This routine allocates an RDMA operation of a specified type
//
// @param[in] Socket The socket on which this operation will be posted
//
// @param[in] Type The type of RDMA operation to allocate
//
// @returns A pointer to a newly allocated RDMA operation or NULL on failure
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
_Success_(return != NULL)
RDMA_OPERATION *
RdmaAllocateOperation(
_In_ RDMA_SOCKET *Socket,
_In_ RDMA_OPERATION_TYPE Type)
{
    RDMA_OPERATION *Operation = RdmaAllocateNpp(sizeof(*Operation));

    PAGED_CODE();

    if (Operation != NULL)
    {
        RtlZeroMemory(Operation, sizeof(*Operation));
        Operation->Socket = Socket;
        Operation->Type = Type;
    }

    return Operation;
}

//
// Saves the failure status that is associated with a failed SQ work request to the SQ work
// request's operation's Status field so that we can report the reason that the operation 
// failed to the upper level driver. If the operation's Status field already contains a "real" 
// error code (not STATUS_CANCELLED) then it won't be overwritten as this is the "real" error
// that caused the operation to fail in the first place. STATUS_CANCELLED isn't considered a
// "real" error in this context because when a real error occurs, NDK providers will 
// complete all WRs that are still queued to the QP with STATUS_CANCELLED.
//
// @param[in,out] Operation A pointer to the RDMA_OPERATION object that represents the operation
// whose Status field will be set.
//
// @param[in] FailureStatus An NTSTATUS error code that represents the reason that this 
// SQ work request failed.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaSetOperationFailureStatus(
_Inout_ RDMA_OPERATION *Operation,
_In_ NTSTATUS FailureStatus)
{
    if ((STATUS_SUCCESS == Operation->Status) || (STATUS_CANCELLED == Operation->Status))
    {
        Operation->Status = FailureStatus;
    }
}

//
// Frees the SQ_WORK_REQUEST objects that are associated with an operation.
//
// @param[in] Operation A pointer to the RDMA_OPERATION object that represents the
// operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaFreeOperationSqWrList(
_Inout_ RDMA_OPERATION *Operation)
{
    SQ_WORK_REQUEST *wr;

    while (Operation->SqWrList)
    {
        wr = Operation->SqWrList;
        Operation->SqWrList = Operation->SqWrList->Next;

        RdmaFreeSqWorkRequest(wr);
    }

    Operation->WrCount = 0;
}

//
// Helper routine that completes a pending operation. This routine invokes the 
// operation's completion callback and then frees the operation. If the operation
// failed the routine will disconnect the operation's socket and log an event to
// the debug log.
//
// @param[in] Operation A pointer to the RDMA_OPERATION object that represents the
// pending operation that completed.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaCompleteOperation(
_In_ _Frees_ptr_ RDMA_OPERATION *Operation)
{
    RDMA_COMPLETION_CALLBACK *Callback;
    NTSTATUS status;
    PVOID Context;

    status = Operation->Status;
    Callback = Operation->CompletionCallback;
    Context = Operation->CompletionContext;

    if (!NT_SUCCESS(status))
    {
        RdmaQueueDisconnectWorkItem(Operation->Socket, FALSE);
    }

    RdmaFreeOperation(Operation);

    Callback(status, Context);
}

//
// Handles the completion of an Operation's SQ work request. If this is the last of the 
// Operation's SQ work requests to complete then the Operation will be completed and freed.
//
// @param[in] Status Indicates whether the SQ work request completed successfully or not.
//
// @param[in] Context A pointer to the RDMA_OPERATION object that represents the operation that
// owns the completed SQ work request.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static
VOID
RdmaOperationSqWrCompletionCallback(
_In_ NTSTATUS Status,
_In_opt_ PVOID Context)
{
    RDMA_OPERATION *Operation = (RDMA_OPERATION *)Context;

    NT_ASSERT(Operation);

    if (!NT_SUCCESS(Status))
    {
        RdmaSetOperationFailureStatus(Operation, Status);
    }

    if (--Operation->WrCount == 0)
    {
        RdmaCompleteOperation(Operation);
    }
}

//
// This routine helps fill out a work request based on the specific type
// of the work request
//
// @param[in] wr The work request to fill out
//
// @param[in] CompletionContext The completion context to pass back to wr completion 
// callback that is called when the work request has completed
//
// @param[in] Sgl Pointer to a scatter gather list that describes the buffer the work 
// request will use
//
// @param[in] TotalBytes The total number of bytes including the current work request 
// that have been used in the operation so far
//
// @param[in] SqContext Some SQ type specific context to help fill out the work request
//
// @retval STATUS_SUCCESS The operation's SQ work requests were built successfully
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
static
NTSTATUS
RdmaBuildSqWorkRequestHelper(
_Inout_ SQ_WORK_REQUEST *wr,
_In_ VOID *CompletionContext,
_In_ RDMA_SGL *Sgl,
_In_ ULONG TotalBytes,
_In_ VOID *SqContext)
{
    NTSTATUS status = STATUS_SUCCESS;

    NDK_SGE *NdkSgl;
    SQ_WORK_REQUEST_SEND *SqSend;
    SQ_WORK_REQUEST_WRITE *SqWrite;
    SQ_WORK_REQUEST_READ *SqRead;

    NT_ASSERT(TotalBytes >= Sgl->BytesMapped);

    PAGED_CODE();

    NdkSgl = RdmaAllocateNpp(sizeof(NDK_SGE) * Sgl->nSge);
    VERIFY_MALLOC(NdkSgl);

    RtlCopyMemory(NdkSgl, Sgl->NdkSgl, sizeof(NDK_SGE)* Sgl->nSge);

    wr->CompletionContext = CompletionContext;
    wr->CompletionCallback = RdmaOperationSqWrCompletionCallback;

    switch (wr->Type)
    {
    case SQSend:
        SqSend = (SQ_WORK_REQUEST_SEND *)SqContext;

        NT_ASSERT(wr->Send.nSge == 0);
        NT_ASSERT(wr->Send.NdkSgl == NULL);

        wr->Send.nSge = Sgl->nSge;
        wr->Send.NdkSgl = NdkSgl;

        wr->Send.BytesSent = Sgl->BytesMapped;

        wr->Send.InvalidateRemoteMemoryRegion = SqSend->InvalidateRemoteMemoryRegion;
        wr->Send.RemoteMemoryRegionToken = SqSend->RemoteMemoryRegionToken;

        break;
    case SQWrite:
        SqWrite = (SQ_WORK_REQUEST_WRITE *)SqContext;

        NT_ASSERT(wr->Write.nSge == 0);
        NT_ASSERT(wr->Write.NdkSgl == NULL);

        wr->Write.nSge = Sgl->nSge;
        wr->Write.NdkSgl = NdkSgl;

        wr->Write.BytesTransferred = Sgl->BytesMapped;

        wr->Write.RemoteAddress = SqWrite->RemoteAddress + TotalBytes - Sgl->BytesMapped;
        wr->Write.RemoteToken = SqWrite->RemoteToken;

        break;
    case SQRead:
        SqRead = (SQ_WORK_REQUEST_WRITE *)SqContext;

        NT_ASSERT(wr->Read.nSge == 0);
        NT_ASSERT(wr->Read.NdkSgl == NULL);

        wr->Read.nSge = Sgl->nSge;
        wr->Read.NdkSgl = NdkSgl;

        wr->Read.BytesTransferred = Sgl->BytesMapped;

        wr->Read.RemoteAddress = SqRead->RemoteAddress + TotalBytes - Sgl->BytesMapped;
        wr->Read.RemoteToken = SqRead->RemoteToken;

        break;
    default:
        NT_ASSERT(FALSE);
    }

exit:
    return status;
}

//
// Builds SQ work requests for an RDMA_OPERATION object in an SQ type generic way
//
// @param[in,out] Operation A pointer to the RDMA_OPERATION object on which to build the
// SQ work requests
//
// @param[in] LamChainHead Pointer to the first LAM in a chain of LAMs describing the buffer
// that will be used for this operation
//
// @param[in] PrivilegedMrToken A privileged memory region token from the
// protection domain of the local socket over which the outgoing RDMA read will happen
//
// @param[in] MaxSgeCount The maximum number of SGEs a single wr is allowed to have
//
// @param[in] MaxCbSize The maximum number of bytes a single wr is allowed to map
//
// @param[in] SqType The type of SQ work requests to allocate
//
// @param[in] SqContext Some SQ type specific context to help fill out the work request
//
// @retval STATUS_SUCCESS The operation's SQ work requests were built successfully
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
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
_In_ VOID *SqContext)
{
    NTSTATUS status;
    RDMA_SGL *SglChain = NULL, *Sgl;
    ULONG TotalBytes = 0;

    SQ_WORK_REQUEST **wr = &Operation->SqWrList;

    NT_ASSERT(Operation->SqWrList == NULL);
    NT_ASSERT(Operation->WrCount == 0);

    PAGED_CODE();

    status = RdmaBuildSglChainForLamChain(LamChainHead, PrivilegedMrToken, 0, MaxSgeCount, MaxCbSize, &SglChain);
    VERIFY_NTSUCCESS(status);

    for (Sgl = SglChain; Sgl != NULL; Sgl = Sgl->Next)
    {
        TotalBytes += Sgl->BytesMapped;
        *wr = RdmaAllocateSqWorkRequest(SqType);
        VERIFY_MALLOC(*wr);

        status = RdmaBuildSqWorkRequestHelper(*wr, Operation, Sgl, TotalBytes, SqContext);
        VERIFY_NTSUCCESS(status);

        wr = &(*wr)->Next;
        Operation->WrCount++;
    }

exit:
    if (SglChain)
    {
        RdmaFreeSglChain(SglChain);
        SglChain = NULL;
    }

    if (!NT_SUCCESS(status))
    {
        RdmaFreeOperationSqWrList(Operation);
        Operation->SqWrList = NULL;
    }

    return status;
}

//
// Builds RDMA Read work requests for an RDMA Read Operation.
//
// @param[in,out] Operation A pointer to the RDMA_OPERATION object that represents
// the RDMA Write Operation.
//
// @param[in] PrivilegedMrToken A privileged memory region token from the
// protection domain of the local socket over which the outgoing RDMA read will happen
//
// @param[in] RemoteAddress The address on the remote peer from which to RDMA read
//
// @param[in] RemoteToken A token describing the remote memory region on the peer
//
// @retval STATUS_SUCCESS The operation's SQ work requests were built successfully
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildReadWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ UINT32 PrivilegedMrToken,
_In_ UINT64 RemoteAddress,
_In_ UINT32 RemoteToken)
{
    SQ_WORK_REQUEST_READ SqReadContext;

    NT_ASSERT(Operation->Type == RdmaOpRead);
    NT_ASSERT(Operation->Read.LamChainHead);
    NT_ASSERT(Operation->Read.LamChainBytesMapped > 0);
    NT_ASSERT(Operation->SqWrList == NULL);
    NT_ASSERT(Operation->WrCount == 0);

    PAGED_CODE();

    SqReadContext.RemoteAddress = RemoteAddress;
    SqReadContext.RemoteToken = RemoteToken;

    return RdmaBuildSqWorkRequests(
        Operation,
        Operation->Read.LamChainHead,
        PrivilegedMrToken,
        Operation->Socket->MaxReadSges,
        Operation->Socket->MaxReadCbSize,
        SQRead,
        &SqReadContext);
}

//
// Builds RDMA Write work requests for an RDMA Write Operation.
//
// @param[in,out] Operation A pointer to the RDMA_OPERATION object that represents
// the RDMA Write Operation.
//
// @param[in] PrivilegedMrToken A privileged memory region token from the
// protection domain of the local socket from which data will be RDMA written
//
// @param[in] RemoteAddress The address on the remote peer to write to
//
// @param[in] RemoteToken A token identifying the memory region on the remote peer
// to RDMA write to
//
// @retval STATUS_SUCCESS The operation's SQ work requests were built successfully
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildWriteWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ UINT32 PrivilegedMrToken,
_In_ UINT64 RemoteAddress,
_In_ UINT32 RemoteToken)
{
    SQ_WORK_REQUEST_WRITE SqWriteContext;

    NT_ASSERT(Operation->Type == RdmaOpWrite);
    NT_ASSERT(Operation->Write.LamChainHead);
    NT_ASSERT(Operation->Write.LamChainBytesMapped > 0);
    NT_ASSERT(Operation->SqWrList == NULL);
    NT_ASSERT(Operation->WrCount == 0);

    PAGED_CODE();

    SqWriteContext.RemoteAddress = RemoteAddress;
    SqWriteContext.RemoteToken = RemoteToken;

    return RdmaBuildSqWorkRequests(
        Operation,
        Operation->Write.LamChainHead,
        PrivilegedMrToken,
        Operation->Socket->MaxSqSges,
        Operation->Socket->MaxSqCbSize,
        SQWrite,
        &SqWriteContext);
}

//
// Builds RDMA Send work requests for an RDMA Send Operation.
//
// @param[in,out] Operation A pointer to the RDMA_OPERATION object that represents
// the RDMA Write Operation.
//
// @param[in] PrivilegedMrToken A privileged memory region token from the
// protection domain of the socket on which data will be sent
//
// @param[in] InvalidateRemoteMemoryRegion TRUE to additionally invalidate a remote
// memory region on the peer.  FALSE otherwise
//
// @param[in] RemoteMemoryRegionToken The remote token to invalidate on the peer.  Only
// valid if InvalidateRemoteMemoryRegion is TRUE
//
// @retval STATUS_SUCCESS The operation's SQ work requests were built successfully
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildSendWorkRequests(
_Inout_ RDMA_OPERATION *Operation,
_In_ UINT32 PrivilegedMrToken,
_In_ BOOLEAN InvalidateRemoteMemoryRegion,
_In_ UINT32 RemoteMemoryRegionToken)
{
    SQ_WORK_REQUEST_SEND SqSendContext;

    NT_ASSERT(Operation->Type == RdmaOpSend);
    NT_ASSERT(Operation->Send.LamChainHead);
    NT_ASSERT(Operation->Send.LamChainBytesMapped > 0);
    NT_ASSERT(Operation->SqWrList == NULL);
    NT_ASSERT(Operation->WrCount == 0);

    PAGED_CODE();

    SqSendContext.InvalidateRemoteMemoryRegion = InvalidateRemoteMemoryRegion;
    SqSendContext.RemoteMemoryRegionToken = RemoteMemoryRegionToken;

    return RdmaBuildSqWorkRequests(
        Operation,
        Operation->Send.LamChainHead,
        PrivilegedMrToken,
        Operation->Socket->MaxSqSges,
        Operation->Socket->MaxSqCbSize,
        SQSend,
        &SqSendContext);
}

//
// Frees an RDMA_OPERATION object that was previously allocated.  All of the
// Operation's associated resources will be freed along with the object itself
//
// @param[in] Operation A pointer to the operation to free
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeOperation(
_In_ _Frees_ptr_ RDMA_OPERATION *Operation)
{
    switch (Operation->Type)
    {
    case RdmaOpSend:
        if (Operation->Send.LamChainHead)
        {
            RdmaFreeLamChain(Operation->Send.LamChainHead);
            Operation->Send.LamChainHead = NULL;
        }

        break;
    case RdmaOpWrite:
        if (Operation->Write.LamChainHead)
        {
            RdmaFreeLamChain(Operation->Write.LamChainHead);
            Operation->Write.LamChainHead = NULL;
        }

        break;
    case RdmaOpRead:
        if (Operation->Read.LamChainHead)
        {
            RdmaFreeLamChain(Operation->Read.LamChainHead);
            Operation->Read.LamChainHead = NULL;
        }

        break;
    }

    RdmaFreeOperationSqWrList(Operation);

    RdmaFreeNpp(Operation);
}
