/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaBuffer.h

Abstract:

    Contains header file for working with RDMA_REGISTERED_BUFFER objects

--*/

#pragma once

//
// This struct represents a buffer that has been registered on a socket for
// remote RDMA Write/Read operations to be done on
//
typedef struct _RDMA_REGISTERED_BUFFER
{
    //
    // Used to link registered buffers into Socket->FreeMemoryRegions or
    // Socket->RegisteredMemoryRegions
    //
    LIST_ENTRY ListEntry;

    //
    // Pointer to the memory region on which tis buffer was registered
    //
    NDK_MR *NdkMr;

    //
    // Remote token describing this memory region
    //
    UINT32 RemoteToken;

    //
    // The number bytes in this mapped buffer
    //
    ULONG Len;

    //
    // The least significant 12 bits describe the FBO in the first page mapped
    // by this buffer.  The upper bits are assigned arbitrarily as the start of
    // the buffer
    //
    VOID *BaseVirtualAddress;

    //
    // Pointer to the LAM that maps the registered buffer
    //
    LAM *Lam;

    //
    // A pre-allocated invalidation work request so we that we always
    // handle invalidation even in low memory
    //
    SQ_WORK_REQUEST *InvalidateWr;
} RDMA_REGISTERED_BUFFER, *PRDMA_REGISTERED_BUFFER;

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RdmaAllocateRegisteredBuffer(
_In_ RDMA_SOCKET *Socket);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
RdmaRegisterBuffer(
_Inout_ RDMA_SOCKET *Socket,
_In_ MDL *Mdl,
_In_ ULONG BufferCbLen,
_Outptr_ RDMA_REGISTERED_BUFFER **oRdmaBuffer);

_IRQL_requires_max_(APC_LEVEL)
VOID
RdmaInvalidateRegisteredBuffer(
_Inout_ RDMA_SOCKET *Socket,
_Inout_ RDMA_REGISTERED_BUFFER *RdmaBuffer);

_IRQL_requires_max_(APC_LEVEL)
static VOID
RdmaInvalidateRegisteredBufferInner(
_When_(FullyRegistered, _Inout_) RDMA_SOCKET *Socket,
_Inout_ RDMA_REGISTERED_BUFFER *RdmaBuffer,
_In_ BOOLEAN FullyRegistered);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeRegisteredBuffer(
_In_ _Frees_ptr_ RDMA_REGISTERED_BUFFER *RdmaBuffer);
