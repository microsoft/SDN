/*++
Copyright (c) Microsoft Corporation

Module Name:

    util.h

Abstract:

    Contains utility functions and macros not tied to any particular aspect of RDMA

--*/

#pragma once

//
// Helper macros to define multi-line macros which end in a semicolon
//  and don't trigger conditional expression is constant warning (C4127)
//
#define MULTI_LINE_MACRO_BEGIN do {

#define MULTI_LINE_MACRO_END        \
    __pragma(warning(push))         \
    __pragma(warning(disable:4127)) \
    } while (FALSE)                 \
    __pragma(warning(pop))

//
// Go through each entry in a list
// Type - The struct type of a list entry
// Var - The variable that would refer to the list entry in the loop body (should be a Type*)
// ListHead - Head of the list. The loop iterations DO NOT include this
// ListEntry - The name of the field in Type that represents the list entry
//
#define FOR_EACH_LIST_ENTRY_X(Type,Var,ListHead,ListEntry)                      \
    for ((Var) = CONTAINING_RECORD((ListHead).Flink,Type,ListEntry);            \
        &(Var)->ListEntry != &(ListHead);                                       \
        (Var) = CONTAINING_RECORD(Var->ListEntry.Flink,Type,ListEntry))

//
// Go through each entry in a list
// Type - The struct type of a list entry
// Var - The variable that would refer to the list entry in the loop body (should be a Type*)
// ListHead - Head of the list. The loop iterations DO NOT include this
//
#define FOR_EACH_LIST_ENTRY(Type,Var,ListHead)  FOR_EACH_LIST_ENTRY_X(Type,Var,(ListHead),ListEntry)

//
// helper macros for taking the min of multiple values
//
#define min3(a, b, c) min(min((a), (b)), (c))
#define min4(a, b, c, d) min(min((a), (b)), min((c), (d)))

//
// Helper macros to make error handling easier
//
#define VERIFY_NTSUCCESS(status)                        \
    MULTI_LINE_MACRO_BEGIN                              \
        if (!NT_SUCCESS(status))                        \
        {                                               \
            goto exit;                                  \
        }                                               \
    MULTI_LINE_MACRO_END

#define VERIFY_MALLOC(var)                              \
    MULTI_LINE_MACRO_BEGIN                              \
        if ((var) == NULL)                              \
        {                                               \
            (status) = STATUS_INSUFFICIENT_RESOURCES;   \
            goto exit;                                  \
        }                                               \
    MULTI_LINE_MACRO_END

//
// define macros for acquiring/releasing the exclusive socket lock
//
#define RDMA_LOCK_SOCKET(Socket, LockHandle)            KeAcquireInStackQueuedSpinLock(&(Socket)->Lock, (LockHandle))
#define RDMA_UNLOCK_SOCKET(Socket, LockHandle)          KeReleaseInStackQueuedSpinLock(LockHandle)

//
// Determines the size, in bytes, of a SOCKADDR struct based on its address family
//
// @param[in] Sockaddr An optional pointer to the SOCKADDR struct that represents 
// an IPv4 or IPv6 address and port.
//
// @returns the size, in bytes, of Sockaddr. If the Sockaddr argument is NULL or
// the address family is not IPv4 or IPv6 then 0 is returned.
//
FORCEINLINE
_Ret_range_(0, sizeof(SOCKADDR_IN6))
ULONG
RdmaGetSockaddrCbSize(
    _In_opt_ CONST SOCKADDR *Sockaddr)
{
    if (!ARGUMENT_PRESENT(Sockaddr))
    {
        return 0;
    }

    switch (Sockaddr->sa_family)
    {
    case AF_INET:
        return sizeof(SOCKADDR_IN);

    case AF_INET6:
        return sizeof(SOCKADDR_IN6);

    default:
        NT_ASSERT(FALSE);
        return 0;
    }
}

//
// Returns the total length, in bytes, of the buffers that are described by an MDL chain
//
// @param[in] Mdl A pointer to the first MDL in the chain.
//
// @returns Returns the total length, in bytes, of the buffers that are described by the MDL 
// chain
//
FORCEINLINE
ULONG
RdmaGetMdlChainByteCount(
    _In_ MDL *Mdl)
{
    ULONG byteCount = 0;

    while (Mdl)
    {
        byteCount += MmGetMdlByteCount(Mdl);
        Mdl = Mdl->Next;
    }

    return byteCount;
}

//
// Simple wrapper around kernel memory allocation API for ease of use
//
// @param[in] NumBytes The number of bytes to allocate
//
// @returns Pointer to the newly allocated memory or NULL on failure
//
FORCEINLINE
VOID *
RdmaAllocateNpp(
_In_ SIZE_T NumBytes)
{
    return ExAllocatePoolWithTagPriority(NonPagedPoolNx, NumBytes, RDMA_SAMPLE_TAG, NormalPoolPriority);
}

//
// Simple wrapper around kernel memory free APIs for ease of use
//
// @param[in] Mem The memory to free
//
FORCEINLINE
VOID
RdmaFreeNpp(
_In_ _Frees_ptr_ VOID *Mem)
{
    ExFreePoolWithTag(Mem, RDMA_SAMPLE_TAG);
}

//
// Simple wrapper around kernel work item allocation API for ease of use
//
// @returns Pointer to the newly allocated work item or NULL on failure
//
FORCEINLINE
PIO_WORKITEM
RdmaAllocWorkItem()
{
    return IoAllocateWorkItem((DEVICE_OBJECT *)RdmaDriverObject);
}

//
// Simple wrapper around kernel work item queueing API for ease of use
//
// @param[in] WorkItem A previously allocated work item to queue
//
// @param[in] WorkerRoutine a callback routine to invoke
//
// @param[in] Context context to pass back to work item routing
//
FORCEINLINE
VOID
RdmaQueueWorkItem(
PIO_WORKITEM WorkItem,
IO_WORKITEM_ROUTINE_EX WorkerRoutine,
VOID *Context)
{
    IoQueueWorkItemEx(WorkItem, WorkerRoutine, DelayedWorkQueue, Context);
}

//
// Simple wrapper around kernel work item freeing API for ease of use
//
// @param[in] WorkItem Pointer to the work item to free
//
FORCEINLINE
VOID
RdmaFreeWorkItem(
_In_ _Frees_ptr_ PIO_WORKITEM WorkItem)
{
    IoFreeWorkItem(WorkItem);
}

//
// Used during connection establishment to check whether any asynchronous disconnects
// have happened and whether connection establishment should proceed
//
// @param[in] Socket The socket which is being connected
//
// @retval STATUS_SUCCESS The socket is still in the connecting state
//
// @retval STATUS_CONNECTION_DISCONNECTED An asynchronous disconnect happened 
// and the socket can no longer be connected
//
FORCEINLINE
NTSTATUS
RdmaCheckSocketConnecting(
_In_ RDMA_SOCKET *Socket)
{
    NTSTATUS status;

    if (Socket->State == RdmaSocketConnecting)
    {
        status = STATUS_SUCCESS;
    } 
    else
    {
        NT_ASSERT(Socket->State == RdmaSocketDisconnecting);
        status = STATUS_CONNECTION_DISCONNECTED;
    }

    return status;
}

//
// Checks whether a socket is still in the connected state
//
// @param[in] Socket Pointer to the RDMA_SOCKET object to check
//
// @retval STATUS_SUCCESS The socket is still connected
//
// @retval STATUS_CONNECTION_DISCONNECTED The socket is no longer connected
//
FORCEINLINE
NTSTATUS
RdmaCheckSocketConnected(
_In_ RDMA_SOCKET *Socket)
{
    NTSTATUS status;

    if (Socket->State == RdmaSocketConnected)
    {
        status = STATUS_SUCCESS;
    } 
    else
    {
        status = STATUS_INVALID_DEVICE_STATE;
    }

    return status;
}

//
// Sets a socket to the disconnected state and sets an event notifying any threads
// waiting for the socket to fully transition into the disconnected state.  This routine
// must be called with the socket lock held
//
// @param[in] Socket The socket to set to the disconnected state
//
// @irql DISPATCH_LEVEL
//
_IRQL_requires_(DISPATCH_LEVEL)
_Requires_exclusive_lock_held_(Socket->Lock)
FORCEINLINE
VOID
RdmaSetSocketDisconnected(
_In_ RDMA_SOCKET *Socket)
{
    NT_ASSERT(Socket->State == RdmaSocketDisconnecting
        || Socket->State == RdmaSocketInitialized);

    Socket->State = RdmaSocketDisconnected;
    KeSetEvent(&Socket->SocketDisconnected, 0, FALSE);
}
