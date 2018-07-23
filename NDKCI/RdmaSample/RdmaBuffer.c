/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaBuffer.c

Abstract:

    Contains functions for working with RDMA_REGISTERED_BUFFER objects that 
    correspond to the local buffers fast registered on memory regions within 
    a socket's protection domain.  These buffers are then available for RDMA
    Read/Write operations from the peer

--*/

#include "precomp.h"

//
// This routine allocates an RDMA_REGISTERED_BUFFER object and inserts it
// a socket's free list.  This routine is only called during initial socket
// creation to create a bunch of registered memory buffers
//
// @param[in] Socket The socket on which to allocate the registered buffer
//
// @retval STATUS_SUCCESS The registered buffer was successfully allocated 
// and inserted into the socket's Free list.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RdmaAllocateRegisteredBuffer(
_In_ RDMA_SOCKET *Socket)
{
    NTSTATUS status;
    RDMA_REGISTERED_BUFFER *RdmaBuffer;

    PAGED_CODE();

    RdmaBuffer = RdmaAllocateNpp(sizeof(*RdmaBuffer));
    VERIFY_MALLOC(RdmaBuffer);

    RtlZeroMemory(RdmaBuffer, sizeof(*RdmaBuffer));

    status = NdkCreateFastRegisterMemoryRegion(Socket->NdkPd, &RdmaBuffer->NdkMr);
    VERIFY_NTSUCCESS(status);

    status = NdkInitializeFastRegisterMemoryRegion(RdmaBuffer->NdkMr, Socket->MaxFrmrPageCount, TRUE);
    VERIFY_NTSUCCESS(status);

    RdmaBuffer->RemoteToken = RdmaBuffer->NdkMr->Dispatch->NdkGetRemoteTokenFromMr(RdmaBuffer->NdkMr);

    _No_competing_thread_begin_
    InsertTailList(&Socket->FreeMemoryRegions, &RdmaBuffer->ListEntry);
    _No_competing_thread_end_

exit:
    if (!NT_SUCCESS(status))
    {
        if (RdmaBuffer)
        {
            RdmaFreeRegisteredBuffer(RdmaBuffer);
            RdmaBuffer = NULL;
        }
    }

    return status;
}

//
// This routine grabs a memory region from the free list and posts a fast register
// work request to the SQ to register it and then inserts it into the socket's
// registered memory region list
//
// @param[in,out] Socket The socket on which to register a buffer
//
// @param[in] Mdl The MDL describing the buffer to register
//
// @param[in] BufferCbLen The number of bytes from the buffer to register
//
// @param[out] oRdmaBuffer A pointer to a pointer that will receive the address of the
// newly registered buffer
//
// @retval STATUS_SUCCESS The buffer was successfully registered and inserted
// into the sockets registered memory regions list
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RdmaRegisterBuffer(
_Inout_ RDMA_SOCKET *Socket,
_In_ MDL *Mdl,
_In_ ULONG BufferCbLen,
_Outptr_ RDMA_REGISTERED_BUFFER **oRdmaBuffer)
{
    NTSTATUS status;
    SQ_WORK_REQUEST *SqFastRegister = NULL;
    RDMA_REGISTERED_BUFFER *RdmaBuffer = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;
    SQ_WORK_REQUEST_ASYNC_CONTEXT ctx;
    VOID *BaseVA;

    //
    // Grab buffer from free list
    //
    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    if (Socket->State > RdmaSocketConnected)
    {
        RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

        status = STATUS_CONNECTION_DISCONNECTED;
        goto exit;
    }

    if (IsListEmpty(&Socket->FreeMemoryRegions))
    {
        RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

        status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    RdmaBuffer = CONTAINING_RECORD(RemoveHeadList(&Socket->FreeMemoryRegions), RDMA_REGISTERED_BUFFER, ListEntry);

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

    NT_ASSERT(RdmaBuffer->BaseVirtualAddress == NULL);
    NT_ASSERT(RdmaBuffer->Len == 0);
    NT_ASSERT(RdmaBuffer->Lam == NULL);
    NT_ASSERT(RdmaBuffer->InvalidateWr == NULL);
    NT_ASSERT(RdmaBuffer->NdkMr != NULL);
    NT_ASSERT(RdmaBuffer->RemoteToken != 0);

    //
    // Build LAM to describe the buffer
    //
    status = RdmaAllocateLam(Socket->RdmaAdapter->NdkAdapter, Mdl, BufferCbLen, &RdmaBuffer->Lam);
    VERIFY_NTSUCCESS(status);

    //
    // Pre-Build Invalidate SQ wr so that invalidate can't fail
    //
    RdmaBuffer->InvalidateWr = RdmaAllocateSqWorkRequest(SQInvalidate);
    VERIFY_MALLOC(RdmaBuffer->InvalidateWr);

    //
    // Build Fast Register SQ wr
    //
    SqFastRegister = RdmaAllocateSqWorkRequest(SQFastRegister);
    VERIFY_MALLOC(SqFastRegister);

    // generate pseudo-random base VA to help catch user-after-free bugs
    BaseVA = (VOID *)(((ULONG_PTR)MmGetMdlVirtualAddress(Mdl)) ^ ((ULONG_PTR) SqFastRegister & 0x7FFFFFFFFFFFF000));

    ctx.SqWorkRequest = SqFastRegister;
    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);
    
    SqFastRegister->CompletionContext = &ctx;
    SqFastRegister->CompletionCallback = SqGenericCompletionCallback;

    SqFastRegister->FastRegister.NdkMr = RdmaBuffer->NdkMr;
    SqFastRegister->FastRegister.AdapterPageArray = RdmaBuffer->Lam->NdkLam->AdapterPageArray;
    SqFastRegister->FastRegister.AdapterPageCount = RdmaBuffer->Lam->NdkLam->AdapterPageCount;
    SqFastRegister->FastRegister.Length = BufferCbLen;
    SqFastRegister->FastRegister.BaseVirtualAddress = BaseVA;

    //
    // Post Fast register.  We can't touch it afterward since it may have already been freed
    //
    RdmaQueueSQWrs(Socket, SqFastRegister);
    SqFastRegister = NULL;

    //
    // Wait for SQ to finish.
    //
    KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
    status = ctx.Status;
    VERIFY_NTSUCCESS(status);

    RdmaBuffer->BaseVirtualAddress = BaseVA;
    RdmaBuffer->Len = BufferCbLen;

    //
    // Insert into used list
    //
    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    InsertTailList(&Socket->RegisteredMemoryRegions, &RdmaBuffer->ListEntry);

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

exit:
    if (!NT_SUCCESS(status))
    {
        RdmaQueueDisconnectWorkItem(Socket, FALSE);

        if (RdmaBuffer)
        {
            RdmaInvalidateRegisteredBufferInner(Socket, RdmaBuffer, FALSE);
            RdmaBuffer = NULL;
        }
    }

    *oRdmaBuffer = RdmaBuffer;

    return status;
}

//
// This invalidates a registered memory buffer that was previously registered using the
// invalidate work request that was pre-allocated.  After invalidation the memory region 
// is returned to the free list and another buffer can be registered on it.  The buffer
// may not be used for any RDMA operations after it has been invalidated.
//
// @param[in,out] Socket The socket on which to invalidate the buffer
//
// @param[in] RdmaBuffer The buffer to invalidate
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
VOID
RdmaInvalidateRegisteredBuffer(
_Inout_ RDMA_SOCKET *Socket,
_Inout_ RDMA_REGISTERED_BUFFER *RdmaBuffer)
{
    PAGED_CODE();

    RdmaInvalidateRegisteredBufferInner(Socket, RdmaBuffer, TRUE);
}

//
// This function does all the actual work of invalidating a buffer registration
//
// @param[in,out] Socket The socket on which to invalidate the buffer
//
// @param[in] RdmaBuffer The buffer to invalidate
//
// @param[in] FullyRegistered Whether the buffer has been fully registered or we are getting
// here due to a failure in registration and need to clean up resources
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
static
VOID
RdmaInvalidateRegisteredBufferInner(
_When_(FullyRegistered, _Inout_) RDMA_SOCKET *Socket,
_Inout_ RDMA_REGISTERED_BUFFER *RdmaBuffer,
_In_ BOOLEAN FullyRegistered)
{
    SQ_WORK_REQUEST_ASYNC_CONTEXT ctx;
    KLOCK_QUEUE_HANDLE LockHandle;

    //
    // Post/Free Invalidate SQ wr
    //
    if (RdmaBuffer->InvalidateWr)
    {
        if (FullyRegistered)
        {
            ctx.SqWorkRequest = RdmaBuffer->InvalidateWr;
            KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

            RdmaBuffer->InvalidateWr->Invalidate.NdkMrOrMw = &RdmaBuffer->NdkMr->Header;
            RdmaBuffer->InvalidateWr->CompletionCallback = SqGenericCompletionCallback;
            RdmaBuffer->InvalidateWr->CompletionContext = &ctx;

            RdmaQueueSQWrs(Socket, RdmaBuffer->InvalidateWr);

            KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        }
        else
        {
            NT_ASSERT(RdmaBuffer->BaseVirtualAddress == NULL);
            NT_ASSERT(RdmaBuffer->Len == 0);
            RdmaFreeSqWorkRequest(RdmaBuffer->InvalidateWr);
        }

        RdmaBuffer->InvalidateWr = NULL;
    }

    //
    // Free LAM
    //
    if (RdmaBuffer->Lam)
    {
        RdmaFreeLam(RdmaBuffer->Lam);
        RdmaBuffer->Lam = NULL;
    }

    //
    // Zero out other stuff
    //
    RdmaBuffer->BaseVirtualAddress = NULL;
    RdmaBuffer->Len = 0;

    //
    // Put back on free list
    //
    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    if (FullyRegistered)
    {
        RemoveEntryList(&RdmaBuffer->ListEntry);
    }

    InsertTailList(&Socket->FreeMemoryRegions, &RdmaBuffer->ListEntry);

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);
}

//
// This function frees a buffer registration along with any associated memory regions,
// work requests, etc.  It is called when a socket is being torn down.
//
// @param[in] RdmaBuffer The buffer to free
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeRegisteredBuffer(
_In_ _Frees_ptr_ RDMA_REGISTERED_BUFFER *RdmaBuffer)
{
    if (RdmaBuffer->InvalidateWr)
    {
        RdmaFreeSqWorkRequest(RdmaBuffer->InvalidateWr);
        RdmaBuffer->InvalidateWr = NULL;
    }

    if (RdmaBuffer->Lam)
    {
        RdmaFreeLam(RdmaBuffer->Lam);
        RdmaBuffer->Lam = NULL;
    }

    if (RdmaBuffer->NdkMr)
    {
        NdkCloseMemoryRegionAsyncNoCallback(RdmaBuffer->NdkMr);
        RdmaBuffer->NdkMr = NULL;
    }

    RdmaFreeNpp(RdmaBuffer);
}
