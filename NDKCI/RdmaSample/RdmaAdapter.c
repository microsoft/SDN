/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaAdapter.c

Abstract:

    Contains functions for opening/closing RDMA_ADAPTER objects

--*/

#include "precomp.h"

//
// Opens an RDMA adapter
//
// @param[in] IfIndex The interface index of the RDMA adapter
//
// @param[out] oAdapter A pointer to the RDMA_ADAPTER pointer that receives 
// the address of the object that represents the RDMA adapter.
//
// @retval STATUS_SUCCESS The function completed successfully.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaOpenAdapter(
_In_ IF_INDEX IfIndex,
_Outptr_ RDMA_ADAPTER **oAdapter
)
{
    NTSTATUS status;
    RDMA_ADAPTER *Adapter = NULL;
    NDK_ADAPTER_INFO *AdapterInfo = NULL;
    NET_LUID IfLuid;

    PAGED_CODE();

    Adapter = (RDMA_ADAPTER *)RdmaAllocateNpp(sizeof(*Adapter));
    VERIFY_MALLOC(Adapter);

    RtlZeroMemory(Adapter, sizeof(*Adapter));

    AdapterInfo = (NDK_ADAPTER_INFO *)RdmaAllocateNpp(sizeof(*AdapterInfo));
    VERIFY_MALLOC(AdapterInfo);

    status = NdkOpenAdapter(IfIndex, &Adapter->NdkAdapter);
    VERIFY_NTSUCCESS(status);

    status = NdkQueryAdapterInfo(Adapter->NdkAdapter, AdapterInfo);
    VERIFY_NTSUCCESS(status);

    if ((AdapterInfo->AdapterFlags & NDK_ADAPTER_FLAG_RDMA_READ_SINK_NOT_REQUIRED) == 0)
    {
        status = STATUS_NOT_SUPPORTED;
        goto exit;
    }

    Adapter->IfIndex = IfIndex;

    Adapter->SupportsInterruptModeration = ((AdapterInfo->AdapterFlags & NDK_ADAPTER_FLAG_CQ_INTERRUPT_MODERATION_SUPPORTED) != 0);
    
    Adapter->RqDepth = (USHORT) min3(MAXUSHORT, AdapterInfo->MaxCqDepth, AdapterInfo->MaxReceiveQueueDepth);
    Adapter->SqDepth = (USHORT) min3(MAXUSHORT, AdapterInfo->MaxCqDepth, AdapterInfo->MaxInitiatorQueueDepth);
    Adapter->MaxInboundReadLimit = (USHORT) min(MAXUSHORT, AdapterInfo->MaxInboundReadLimit);
    Adapter->MaxOutboundReadLimit = (USHORT) min(MAXUSHORT, AdapterInfo->MaxOutboundReadLimit);
    Adapter->MaxFrmrPageCount = (USHORT) min(MAXUSHORT, AdapterInfo->FRMRPageCount);

    Adapter->MaxReceiveSges = (USHORT) min(MAX_NUM_SGE_PER_LIST, AdapterInfo->MaxReceiveRequestSge);
    Adapter->MaxReceiveCbSize = (ULONG) min4(RECEIVE_MAX_BUFFER_SIZE, Adapter->MaxReceiveSges * MAX_SGE_SIZE, 
                                            AdapterInfo->MaxTransferLength, AdapterInfo->MaxRegistrationSize);

    Adapter->MaxSqSges = (USHORT) min(MAX_NUM_SGE_PER_LIST, AdapterInfo->MaxInitiatorRequestSge);
    Adapter->MaxSqCbSize = (ULONG) min3(Adapter->MaxSqSges * MAX_SGE_SIZE, AdapterInfo->MaxTransferLength, AdapterInfo->MaxRegistrationSize);

    Adapter->MaxReadSges = (USHORT) min(MAX_NUM_SGE_PER_LIST, AdapterInfo->MaxReadRequestSge);
    Adapter->MaxReadCbSize = (ULONG) min3(Adapter->MaxReadSges * MAX_SGE_SIZE, AdapterInfo->MaxTransferLength, AdapterInfo->MaxRegistrationSize);

    if (AdapterInfo->Version.Major > 1 || (AdapterInfo->Version.Major == 1 && AdapterInfo->Version.Minor >= 2))
    {
        Adapter->SupportsRemoteInvalidation = TRUE;
        Adapter->SupportsDeferredPosting = TRUE;
    }

    //
    // Retrieve the adapter's alias
    //
    Adapter->InterfaceAlias = (PWSTR)RdmaAllocateNpp(sizeof(WCHAR) * (NDIS_IF_MAX_STRING_SIZE + 1));
    VERIFY_MALLOC(Adapter->InterfaceAlias);

    status = ConvertInterfaceIndexToLuid(IfIndex, &IfLuid);
    VERIFY_NTSUCCESS(status);

    status = ConvertInterfaceLuidToAlias(&IfLuid,
        Adapter->InterfaceAlias,
        NDIS_IF_MAX_STRING_SIZE + 1);
    VERIFY_NTSUCCESS(status);

exit:
    if (AdapterInfo)
    {
        RdmaFreeNpp(AdapterInfo);
    }

    if (!NT_SUCCESS(status))
    {
        if (Adapter)
        {
            RdmaCloseAdapter(Adapter);

            Adapter = NULL;
        }
    }

    *oAdapter = Adapter;

    return status;
}

//
// Frees an RDMA_ADAPTER object.  The caller may no longer access the adapter object after 
// calling this function.
//
// @param[in] Adapter A pointer to the RDMA_ADAPTER object that represents the 
// adapter to close.
//
// @irql PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RdmaCloseAdapter(
_In_ _Frees_ptr_ RDMA_ADAPTER *Adapter)
{
    PAGED_CODE();

    if (Adapter->NdkAdapter)
    {
        NdkCloseAdapter(Adapter->NdkAdapter);
    }

    if (Adapter->InterfaceAlias)
    {
        RdmaFreeNpp(Adapter->InterfaceAlias);
    }

    RdmaFreeNpp(Adapter);
}
