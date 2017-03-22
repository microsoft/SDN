/*++
Copyright (c) Microsoft Corporation

Module Name:

    Lam.c

Abstract:

    Contains functions for working with NDK logical address mappings (LAM), buffers,
    scatter gather entries (SGEs), and scatter gather lists (SGLs)

--*/

#include "precomp.h"

//
// This routine allocates list of scatter gather list with enough space for MaxNumSge entries
//
// @param[in] MaxNumSge The maximum number of SGE slots to allocate in the SGE array
//
// @returns A pointer to a newly allocated scatter gather list with space for MaxNumSge SGEs or NULL on failure
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Success_(return != NULL)
RDMA_SGL *
RdmaAllocateSgl(
_In_ USHORT MaxNumSge)
{
    RDMA_SGL *Sgl = RdmaAllocateNpp(sizeof(*Sgl));

    if (Sgl)
    {
        RtlZeroMemory(Sgl, sizeof(*Sgl));

        Sgl->NdkSgl = RdmaAllocateNpp(sizeof(NDK_SGE) * MaxNumSge);
        if (Sgl->NdkSgl == NULL)
        {
            RdmaFreeNpp(Sgl);
            Sgl = NULL;
        }
    }

    return Sgl;
}

//
// This routine frees a scatter gather list
//
// @param[in] Sgl Pointer to the scatter gather list to free
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeSgl(
_In_ _Frees_ptr_ RDMA_SGL *Sgl)
{
    RdmaFreeNpp(Sgl->NdkSgl);
    RdmaFreeNpp(Sgl);
}

//
// This routine frees a chain of scatter gather lists
//
// @param[in] SglChainHead Pointer to the chain of scatter gather lists to free
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeSglChain(
_In_ _Frees_ptr_ RDMA_SGL *SglChainHead)
{
    RDMA_SGL *NextSgl;

    do
    {
        NextSgl = SglChainHead->Next;
        RdmaFreeSgl(SglChainHead);
        SglChainHead = NextSgl;
    } while (SglChainHead);
}

//
// Allocates a logical address mapping (LAM) that is large enough to map a buffer, given an
// MDL that describes the buffer and the number of bytes to map.
//
// This routine determines the number of adapter logical pages that are spanned by a contiguous
// range of virtual memory and then allocates a LAM that is large enough to store the adapter 
// logical address of each adapter logical page that is spanned.
//
// @param[in] NdkAdapter A pointer to the NDK_ADAPTER from which to allocate the LAM
//
// @param[in] Mdl A pointer to a MDL that describes a range of contiguous virtual memory to
// map.
//
// @param[in] BytesToMap The number of bytes to map, starting from the MDL's first byte. The
// value of this argument must be > 0 and <= the number of bytes described by the MDL.
//
// @param[out] oLam A pointer to the LAM pointer that receives the address of the newly allocated LAM object.
//
// @retval STATUS_SUCCESS The LAM was successfully allocated
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaAllocateLam(
_In_ NDK_ADAPTER *NdkAdapter,
_In_ PMDL Mdl,
_In_range_(>, 0) ULONG BytesToMap,
_Outptr_ LAM **oLam
)
{
    NTSTATUS status;
    ULONG NumPages;
    LAM *Lam = NULL;

    //
    // A LAM maps a single MDL, not an MDL chain. The specified MDL must describe at 
    // least as many bytes as the caller has asked us to map.
    //
    NT_ASSERT(BytesToMap <= MmGetMdlByteCount(Mdl) && BytesToMap > 0);

    PAGED_CODE();

    Lam = (LAM *)RdmaAllocateNpp(sizeof(*Lam));
    VERIFY_MALLOC(Lam);

    RtlZeroMemory(Lam, sizeof(*Lam));

    Lam->NdkAdapter = NdkAdapter;

    //
    // Determine the number (N) of pages that the memory range spans then allocate a
    // NDK_LOGICAL_ADDRESS_MAPPING struct whose AdapterPageArray member is large enough to
    // store N entries.
    //
    NumPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(Mdl), BytesToMap);
    NT_ASSERT(NumPages > 0);

    //
    // Compute the size, in bytes, of the buffer that is required to store the NDK LAM.
    //
    Lam->NdkLamCbSize = (NumPages - 1) * sizeof(NDK_LOGICAL_ADDRESS) + sizeof(NDK_LOGICAL_ADDRESS_MAPPING);

    Lam->NdkLam = (NDK_LOGICAL_ADDRESS_MAPPING *)RdmaAllocateNpp(Lam->NdkLamCbSize);
    VERIFY_MALLOC(Lam->NdkLam);

    status = NdkBuildLam(NdkAdapter,
        Mdl,
        BytesToMap,
        Lam->NdkLam,
        &Lam->NdkLamCbSize,
        &Lam->Fbo);
    VERIFY_NTSUCCESS(status);

    Lam->BytesMapped = BytesToMap;
    NT_ASSERT(RdmaGetLamPageCount(Lam) == NumPages);

exit:
    if (!NT_SUCCESS(status))
    {
        if (Lam)
        {
            if (Lam->NdkLam)
            {
                RdmaFreeNpp(Lam->NdkLam);
            }
            RdmaFreeNpp(Lam);

            Lam = NULL;
        }
    }

    *oLam = Lam;

    return status;
}

//
// Releases the resources consumed by a logical address mapping
//
// A LAM object must not be released until all NDK operations
// that are dependent on the mapping have completed. For example, a LAM that is used for
// an NdkSend cannot be released until the NdkSend completes.
//
// @param[in] Pointer to the LAM object to free.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeLam(
_In_ _Frees_ptr_ LAM *Lam
)
{
    NdkReleaseLam(Lam->NdkAdapter, Lam->NdkLam);
    RdmaFreeNpp(Lam->NdkLam);
    RdmaFreeNpp(Lam);
}

//
// Builds a chain of adapter logical addresses mappings for a chain of virtually contiguous 
// buffers.
//
// @param[in] NdkAdapter A pointer to the NDK_ADAPTER object that represents the RDMA-capable
// adapter that will use the LAM to perform sends, reads, writes, etc.
//
// @param[in] MdlChain A pointer to the first MDL in the MDL chain that describes the buffers to
// map. Each MDL in the chain must describe a virtually contiguous range of memory.
//
// @param[in] BytesToMap The number of bytes to map, starting from the first byte of
// the first MDL in the MDL chain. This value must be > 0 and <= the number of bytes 
// described by the MDL chain.
//
// @param[out] oLamChain A pointer to a LAM pointer that will receive
// the address of the first LAM in the chain.
//
// @retval STATUS_SUCCESS The LAM chain was successfully built.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaAllocateLamChain(
_In_ NDK_ADAPTER *NdkAdapter,
_In_ PMDL MdlChain,
_In_range_(>, 0) ULONG BytesToMap,
_Outptr_ LAM **oLamChain
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG unmappedBytes, cBytesToMap;
    MDL *Mdl = MdlChain;
    LAM *LamChainHead = NULL;
    LAM **LamChainTail = &LamChainHead;

    NT_ASSERT(BytesToMap <= RdmaGetMdlChainByteCount(MdlChain) && BytesToMap > 0);

    PAGED_CODE();

    unmappedBytes = BytesToMap;

    while (unmappedBytes)
    {
        NT_ASSERT(Mdl);

        cBytesToMap = min(unmappedBytes, MmGetMdlByteCount(Mdl));

        status = RdmaAllocateLam(NdkAdapter, Mdl, cBytesToMap, LamChainTail);
        VERIFY_NTSUCCESS(status);

        unmappedBytes -= cBytesToMap;

        LamChainTail = &(*LamChainTail)->Next;
        Mdl = Mdl->Next;
    }

exit:
    if (!NT_SUCCESS(status))
    {
        if (LamChainHead)
        {
            RdmaFreeLamChain(LamChainHead);

            LamChainHead = NULL;
        }
    }

    *oLamChain = LamChainHead;

    return status;
}

//
// Releases the resources consumed by a chain of LAM objects
//
// A LAM chain must not be released until all NDK operations
// that are dependent on the chain have completed. For example, a LAM that is used for
// an NdkSend cannot be released until the NdkSend completes.
//
// @param[in] LamChain An pointer to the first LAM in the LAM chain to be freed.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeLamChain(
_In_ _Frees_ptr_ LAM *LamChain
)
{
    LAM *NextLam;

    do
    {
        NextLam = LamChain->Next;
        RdmaFreeLam(LamChain);
        LamChain = NextLam;
    } while (LamChain != NULL);
}

//
// This routine takes a chain of logical address mappings describing a buffer and
// builds a chain of scatter gather lists of describe it while obeying several contraints
// passed in as arguments.  The SGL chain contains SGEs which may then be used in RDMA 
// operations
//
// @param[in] LamChainHead pointer to the first LAM in a chain of LAMs to build
// scatter gather lists for
//
// @param[in] PrivilegedMrToken A privileged memory region token that will
// be used to map the buffer.
//
// @param[in] MaxSgls The maximum number of RDMA_SGLs to have in the chain, or 0
// for no limit.  If a limit is specified and the data in the LamChain cannot be mapped
// into that many RDMA_SGLs, the call will fail
//
// @param[in] MaxSgesPerList The maximum number of SGEs that a single RDMA_SGL
// is allowed to have.  The next RDMA_SGL in the chain will continue mapping the
// input data.
//
// @param[in] MaxCbSizePerList The maximum number of bytes a single RDMA_SGL is
// allowed to map.  The next RDMA_SGL in the chain will continue mapping the
// input data.
//
// @param[out] oSglChain A pointer to a RDMA_SGL pointer that will receive
// the address of the first RDMA_SGL in the chain.
//
// @retval STATUS_SUCCESS The 
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaBuildSglChainForLamChain(
_In_ LAM *LamChainHead,
_In_ UINT32 PrivilegedMrToken,
_In_ USHORT MaxSgls,
_In_ USHORT MaxSgesPerList,
_In_ ULONG MaxCbSizePerList,
_Outptr_ RDMA_SGL **oSglChain)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    LAM *Lam;
    ULONG LamBytesRemaining, PageIndex, PageOffset, PageBytesRemainig, MaxCbSizeRemaining,
        MaxCbSgeSizeRemaining, BytesAssigned;
    USHORT SglCount;
    NDK_LOGICAL_ADDRESS PageAddress;
    
    RDMA_SGL *Sgl, *SglChainHead;
    NDK_SGE *cSge;

    BOOLEAN NeedNewSgl, NeedNewSge;

    PAGED_CODE();

    NT_ASSERT(MaxSgesPerList > 0);
    NT_ASSERT(MaxCbSizePerList > 0);

    SglChainHead = RdmaAllocateSgl(MaxSgesPerList);
    VERIFY_MALLOC(SglChainHead);
    SglCount = 1;

    cSge = NULL;
    Sgl = SglChainHead;
    Lam = LamChainHead;

    NeedNewSgl = FALSE;
    NeedNewSge = TRUE;
    MaxCbSgeSizeRemaining = 0;
    MaxCbSizeRemaining = MaxCbSizePerList;

    do
    {
        //
        // Start at the beginning of this LAM
        //
        LamBytesRemaining = Lam->BytesMapped;

        PageIndex = 0;
        PageAddress = RdmaGetLamPage(Lam, PageIndex);
        PageOffset = Lam->Fbo;
        PageBytesRemainig = min(PAGE_SIZE - PageOffset, LamBytesRemaining);

        NT_ASSERT(LamBytesRemaining);
        NT_ASSERT(PageBytesRemainig);

        do
        {
            //
            // Move to the next page if we have used up all the bytes in the current page
            //
            if (PageBytesRemainig == 0)
            {
                PageIndex++;
                PageAddress = RdmaGetLamPage(Lam, PageIndex);
                PageOffset = 0;
                PageBytesRemainig = min(PAGE_SIZE, LamBytesRemaining);
            }

            //
            // Check if we have hit the limit on the number of bytes we can have in this Sge List
            //
            if (MaxCbSizeRemaining == 0)
            {
                NeedNewSgl = TRUE;
            }

            //
            // Check if our current position is contiguous or we ran out of sge space
            //
            if (MaxCbSgeSizeRemaining == 0 ||
                PageAddress.QuadPart + PageOffset != cSge->LogicalAddress.QuadPart + cSge->Length)
            {
                NeedNewSge = TRUE;
            }

            //
            // Check if we hit our Sge limit and need a new work request
            //
            if (NeedNewSge && Sgl->nSge == MaxSgesPerList)
            {
                NeedNewSgl = TRUE;
            }

            //
            // Check if we need a new work request
            //
            if (NeedNewSgl)
            {
                SglCount++;
                if (MaxSgls != 0 && SglCount > MaxSgls)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto exit;
                }

                // alloc new Sge List and add it to list of SgeLists
                Sgl->Next = RdmaAllocateSgl(MaxSgesPerList);
                VERIFY_MALLOC(Sgl->Next);

                Sgl = Sgl->Next;
                
                cSge = NULL;
                MaxCbSizeRemaining = MaxCbSizePerList;
                NeedNewSgl = FALSE;
                NeedNewSge = TRUE;
            }

            //
            // Check if we need a new Sge
            //
            if (NeedNewSge)
            {
                if (cSge)
                {
                    cSge++;
                }
                else
                {
                    cSge = Sgl->NdkSgl;
                }

                Sgl->nSge++;

                cSge->MemoryRegionToken = PrivilegedMrToken;
                cSge->LogicalAddress.QuadPart = PageAddress.QuadPart + PageOffset;
                cSge->Length = 0;

                NeedNewSge = FALSE;
                MaxCbSgeSizeRemaining = MAX_SGE_SIZE;
            }

            NT_ASSERT(PageAddress.QuadPart + PageOffset == cSge->LogicalAddress.QuadPart + cSge->Length);

            //
            // Assign as many bytes from the current page as we can into the current Sge
            //
            BytesAssigned = min4(MaxCbSizeRemaining, MaxCbSgeSizeRemaining, LamBytesRemaining, PageBytesRemainig);

            Sgl->BytesMapped += BytesAssigned;
            cSge->Length += BytesAssigned;
            
            MaxCbSizeRemaining -= BytesAssigned;
            MaxCbSgeSizeRemaining -= BytesAssigned;
            LamBytesRemaining -= BytesAssigned;
            PageBytesRemainig -= BytesAssigned;

            PageOffset += BytesAssigned;

            NT_ASSERT(PageOffset <= PAGE_SIZE);
        } while (LamBytesRemaining);

        Lam = Lam->Next;
    } while (Lam);

exit:
    if (!NT_SUCCESS(status))
    {
        if (SglChainHead)
        {
            RdmaFreeSglChain(SglChainHead);
            SglChainHead = NULL;
        }
    }

    *oSglChain = SglChainHead;

    return status;
}

//
// Allocates a buffer that is mapped for access by an RNIC
//
// @param[in] NdkAdapter Pointer to the NDK adapter object that represents
// the adapter that will access the buffer.
//
// @param[in] PrivilegedMrToken A privileged memory region token that will
// be used to map the buffer.
//
// @param[in] ByteCount The size, in bytes, of the buffer.  Caller needs to ensure
// that this is <= the max size of what it is being used for.
//
// @param[in] MaxSges The maximum number of SGEs that may used to map this buffer
//
// @param[out] oLamBuffer Address of the LAM buffer pointer that will receive
// the address of the newly allocated LAM buffer. Receives NULL on failure.
//
// @retval STATUS_SUCCESS Succeeded
//
// @retval "Other status codes" Failed
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaAllocateLamBuffer(
_In_ NDK_ADAPTER *NdkAdapter,
_In_ UINT32 PrivilegedMrToken,
_In_ ULONG ByteCount,
_In_ USHORT MaxSges,
_Outptr_ LAM_BUFFER **oLamBuffer
)
{
    NTSTATUS status;
    ULONG TotalBytes = sizeof(LAM_BUFFER) + ByteCount;
    RDMA_SGL *Sgl = NULL;
    LAM_BUFFER *LamBuffer = NULL;
    MDL *Mdl = NULL;

    PAGED_CODE();

    NT_ASSERT(ByteCount > 0);

    //
    // Allocate enough buffer for the struct as well as the data
    //
    LamBuffer = (LAM_BUFFER *)RdmaAllocateNpp(TotalBytes);
    VERIFY_MALLOC(LamBuffer);

    RtlZeroMemory(LamBuffer, TotalBytes);

    LamBuffer->BufferCbLength = ByteCount;
    
    //
    // Allocate MDL to describe the data
    //
    Mdl = IoAllocateMdl(RdmaGetLBBuffer(LamBuffer),
        ByteCount,
        FALSE,
        FALSE,
        NULL);
    VERIFY_MALLOC(Mdl);

    MmBuildMdlForNonPagedPool(Mdl);

    //
    // Allocate LAM
    //
    status = RdmaAllocateLam(NdkAdapter, Mdl, ByteCount, &LamBuffer->Lam);
    VERIFY_NTSUCCESS(status);

    //
    // Build SGL for LAM buffer
    //
    status = RdmaBuildSglChainForLamChain(LamBuffer->Lam, PrivilegedMrToken, 1, MaxSges, ByteCount, &Sgl);
    VERIFY_NTSUCCESS(status);

    NT_ASSERT(Sgl->BytesMapped == ByteCount);
    NT_ASSERT(Sgl->Next == NULL);

    LamBuffer->NdkSgl = RdmaAllocateNpp(sizeof(NDK_SGE)* Sgl->nSge);
    VERIFY_MALLOC(LamBuffer->NdkSgl);

    RtlCopyMemory(LamBuffer->NdkSgl, Sgl->NdkSgl, sizeof(NDK_SGE)* Sgl->nSge);
    LamBuffer->nSge = Sgl->nSge;

exit:
    if (Mdl)
    {
        IoFreeMdl(Mdl);
    }

    if (Sgl)
    {
        RdmaFreeSgl(Sgl);
    }

    if (!NT_SUCCESS(status))
    {
        if (LamBuffer)
        {
            if (LamBuffer->Lam)
            {
                RdmaFreeLam(LamBuffer->Lam);
            }

            if (LamBuffer->NdkSgl)
            {
                RdmaFreeNpp(LamBuffer->NdkSgl);
            }

            RdmaFreeNpp(LamBuffer);
            LamBuffer = NULL;
        }
    }

    *oLamBuffer = LamBuffer;

    return status;
}

//
// Frees the resources consumed by a LAM buffer
//
// @param[in] LamBuffer Pointer to the LAM buffer
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeLamBuffer(
_In_ _Frees_ptr_ LAM_BUFFER *LamBuffer
)
{
    RdmaFreeLam(LamBuffer->Lam);

    RdmaFreeNpp(LamBuffer->NdkSgl);
    RdmaFreeNpp(LamBuffer);
}

//
// Returns a pointer to a LAM buffer's buffer
//
// @param[in] LamBuffer Pointer to the LAM buffer object
//
// @returns Pointer to the LAM buffer's buffer
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID *
RdmaGetLBBuffer(
_In_ LAM_BUFFER *LamBuffer
)
{
    return (VOID *)(LamBuffer + 1);
}

//
// Returns the adapter-logical address of a logical address mapping (LAM)
// page.
//
// @param[in] Lam Pointer to the LAM object 
//
// @param[in] Index The index of the page to return. This value must be 
// < the number of pages mapped by the LAM.
//
// @returns Returns the adapter-logical-address of the specified LAM page.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
NDK_LOGICAL_ADDRESS
RdmaGetLBPage(
_In_ LAM_BUFFER *LamBuffer,
_In_ ULONG Index
)
{
    return RdmaGetLamPage(LamBuffer->Lam, Index);
}

//
// Returns the number of pages that are mapped by a logical address
// mapping (LAM)
//
// @param[in] Lam Pointer to the LAM object
//
// @returns Returns the number of pages that are mapped by the LAM
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
RdmaGetLamPageCount(
_In_ LAM *Lam
)
{
    return Lam->NdkLam->AdapterPageCount;
}

//
// Returns the adapter-logical address of a logical address mapping (LAM)
// page.
//
// @param[in] Lam Pointer to the LAM object 
//
// @param[in] Index The index of the page to return. This value must be 
// < the number of pages mapped by the LAM.
//
// @returns Returns the adapter-logical-address of the specified LAM page.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
NDK_LOGICAL_ADDRESS
RdmaGetLamPage(
_In_ LAM *Lam,
_In_ ULONG Index
)
{
    NT_ASSERT(Index < RdmaGetLamPageCount(Lam));
    return Lam->NdkLam->AdapterPageArray[Index];
}
