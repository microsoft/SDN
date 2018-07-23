/*++
Copyright (c) Microsoft Corporation

Module Name:

    Lam.h

Abstract:

    Header file for functions relating to LAMs, SGEs, SGLs, and buffers

--*/

#pragma once

//
// Maximum amount of bytes that can be mapped by a single SGE
//
#define MAX_SGE_SIZE            (2 * 1024 * 1024UL)   // 2 MB

//
// Maximum number of SGEs in a single SGE List (RDMA_SGL)
//
#define MAX_NUM_SGE_PER_LIST    128

typedef struct _LAM
{
    //
    // Used to link LAMs together in a LAM Chain
    //
    struct _LAM *Next;

    //
    // Pointer to the NDK_ADAPTER object that represents the RNIC on which this LAM was
    // built.
    //
    NDK_ADAPTER *NdkAdapter;

    //
    // Pointer to the NDK_LOGICAL_ADDRESS_MAPPING object that stores the adapter page array,
    // adapter page count, and adapter page size.
    //
    NDK_LOGICAL_ADDRESS_MAPPING *NdkLam;

    //
    // The size, in bytes, of the NDK_LOGICAL_ADDRESS_MAPPING that NdkLam points to, including
    // the NDK LAM's variable-length adapter page array.
    //
    ULONG NdkLamCbSize;

    //
    // The byte offset of the first mapped byte within the first adapter page.
    //
    ULONG Fbo;

    //
    // The number of bytes that are mapped by this LAM.
    //
    ULONG BytesMapped;
} LAM, *PLAM;

typedef struct _LAM_BUFFER
{
    //
    // Use to link the buffers together in a list
    //
    SINGLE_LIST_ENTRY SingleListEntry;

    //
    // pointer to LAM
    //
    LAM *Lam;
    
    // 
    // Pointer array of SGEs 
    //
    NDK_SGE *NdkSgl;

    //
    // The size, in bytes, of the buffer that follows this struct
    // in memory.
    //
    ULONG BufferCbLength;

    //
    // Number of SGEs in Sgl
    //
    USHORT nSge;

    //
    // Padding to ensure alignment
    //
    USHORT Padding;

    //
    // Buffer follows struct
    //
} LAM_BUFFER, *PLAM_BUFFER;

typedef struct _RDMA_SGL
{
    //
    // Used to link into a list of SGLs
    //
    struct _RDMA_SGL *Next;
    
    //
    // Pointer to an array of NDK_SGEs
    //
    NDK_SGE *NdkSgl;
    
    //
    // The number of bytes described by NdkSgl
    //
    ULONG BytesMapped;
    
    //
    // The number of SGEs in NdkSgl
    //
    USHORT nSge;
} RDMA_SGL, *PRDMA_SGL;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Success_(return != NULL)
RDMA_SGL *
RdmaAllocateSgl(
_In_ USHORT MaxNumSge);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeSgl(
_In_ _Frees_ptr_ RDMA_SGL *Sgl);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeSglChain(
_In_ _Frees_ptr_ RDMA_SGL *SglChainHead);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaAllocateLam(
_In_ NDK_ADAPTER *NdkAdapter,
_In_ PMDL Mdl,
_In_range_(>, 0) ULONG BytesToMap,
_Outptr_ LAM **oLam
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeLam(
_In_ _Frees_ptr_ LAM *Lam
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaAllocateLamChain(
_In_ NDK_ADAPTER *NdkAdapter,
_In_ PMDL MdlChain,
_In_range_(>, 0) ULONG BytesToMap,
_Outptr_ LAM **oLamChain
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeLamChain(
_In_ _Frees_ptr_ LAM *Lam
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildSglChainForLamChain(
_In_ LAM *LamChainHead,
_In_ UINT32 PrivilegedMrToken,
_In_ USHORT MaxSgls,
_In_ USHORT MaxSgesPerList,
_In_ ULONG MaxCbSizePerList,
_Outptr_ RDMA_SGL **oSglChain);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaAllocateLamBuffer(
_In_ NDK_ADAPTER *NdkAdapter,
_In_ UINT32 PrivilegedMrToken,
_In_ ULONG ByteCount,
_In_ USHORT MaxSges,
_Outptr_ LAM_BUFFER **oLamBuffer
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeLamBuffer(
_In_ _Frees_ptr_ LAM_BUFFER *LamBuffer
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID *
RdmaGetLBBuffer(
_In_ LAM_BUFFER *LamBuffer
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NDK_LOGICAL_ADDRESS
RdmaGetLBPage(
_In_ LAM_BUFFER *LamBuffer,
_In_ ULONG Index
);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
RdmaGetLamPageCount(
_In_ LAM *Lam
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NDK_LOGICAL_ADDRESS
RdmaGetLamPage(
_In_ LAM *Lam,
_In_ ULONG Index
);
