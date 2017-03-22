/*++
Copyright (c) Microsoft Corporation

Module Name:

    NdkWrapper.c

Abstract:

    Contains functions that wrap the NDK APIs. The wrapper functions usually are used to turn
    asynchronous NDK API calls into synchronous function calls and simplify the interface a bit

--*/

#include "precomp.h"

//
// WSK dispatch table of non-socket event callback functions 
//
static CONST WSK_CLIENT_DISPATCH WskClientDispatch =
{
    MAKE_WSK_VERSION(1, 0), 0, NULL
};

//
// Registration as a client of WSK
//
static WSK_REGISTRATION WskRegistration;

//
// Stores the WSK network programming interface (NPI)
//
static WSK_PROVIDER_NPI WskProviderNpi;

//
// NDK subsystem dispatch table
//
static WSK_PROVIDER_NDK_DISPATCH WskNdkDispatch;

//
// Indicates whether we have registered as a WSK client (TRUE) or not (FALSE)
//
static BOOLEAN WskRegistered = FALSE;

//
// Indicates whether the NDK NPI has been captured (TRUE) or not (FALSE)
//
static BOOLEAN WskProviderNpiCaptured = FALSE;


//
// Handles the async completion of an NDK object creation function (NdkCreateQp, 
// NdkCreateMr, etc.)
//
// This routine is invoked when a create finishes and it updates the 
// RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT struct with the result and sets the event to indicate 
// that the request has completed.
//
// @param[in] Context A pointer to the RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT that was supplied by
// the caller of the object creation API.
//
// @param[in] Status The status of the create API.
//
// @param[in] NdkObject A pointer to the NDK object that was created by the create API
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_CREATE_COMPLETION */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
static NdkCreateFnCompletionCallback(
_In_opt_ PVOID Context,
_In_ NTSTATUS Status,
_In_ NDK_OBJECT_HEADER *NdkObject
)
{
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT *ctx = (RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT *) Context;

    NT_ASSERT(ctx);

    ctx->Status = Status;
    ctx->NdkObject = NdkObject;
    KeSetEvent(&ctx->Event, 0, FALSE);
}

//
// Handles the async completion of an NDK object close function (NdkCloseQp, NdkCloseMr, etc.) 
//
// NDK object close requests complete asynchronously. This routine is invoked when a 
// close request completes and it sets the RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT event to 
// indicate that the request has completed.
//
// @param[in] Context A pointer to the RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT that was supplied 
// by the caller of the object close API.
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_CLOSE_COMPLETION */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkCloseFnCompletionCallback(
_In_opt_ PVOID Context
)
{
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT *ctx = (RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT *) Context;

    NT_ASSERT(ctx);

    KeSetEvent(&ctx->Event, 0, FALSE);
}

//
// Handles the async completion of an NDK object close function by ignoring the completion. 
//
// NDK object close requests complete asynchronously. This routine is invoked when a 
// close request completes. This routine is different from NdkCloseFnCompletionCallback in
// that it simply ignores the close completion. This is useful for cases in which an object
// is closed but the closer doesn't care when the close completes.
//
// @param[in] Context Not used
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_CLOSE_COMPLETION */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkCloseFnDoNothingCompletionCallback(
    _In_opt_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);
}

//
// Handles the async completion of an NDK API call
//
// Most NDK APIs complete asynchronously. This routine is invoked when a request finishes 
// and it updates the RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT struct with the result and sets the
// event to indicate that the API call has completed.
//
// @param[in] Context A pointer to the RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT that was supplied by 
// the caller of the NDK routine.
//
// @param[in] Status The status of the NDK API
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_REQUEST_COMPLETION */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkFnCompletionCallback(
_In_opt_ PVOID Context,
_In_ NTSTATUS Status
)
{
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT *ctx = (RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT *)Context;

    NT_ASSERT(ctx);

    ctx->Status = Status;
    KeSetEvent(&ctx->Event, 0, FALSE);
}

//
// Callback that is invoked by the NDK subsystem to indicate that the NDK connection has been
// disconnected.
//
// This routine starts the disconnect process for the socket.
//
// @param[in] Context A pointer to the RDMA_SOCKET object that represents the
// socket that was disconnected.
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_DISCONNECT_EVENT_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkDisconnectEventCallback(
_In_opt_ PVOID Context
)
{
    RDMA_SOCKET *Socket = (RDMA_SOCKET *)Context;

    NT_ASSERT(Socket);

    RdmaQueueDisconnectWorkItem(Socket, FALSE);
}

//
// This routine initializes the NDK dispatch table. It must be called before any of the 
// NDK support routines can be called.
//
// @retval STATUS_SUCCESS Initialization succeeded
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql PASSIVE_LEVEL
//
// @sa NdkDeInitialize
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkInitialize()
{
    NTSTATUS status;
    WSK_CLIENT_NPI wskClientNpi;

    PAGED_CODE();

    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &WskClientDispatch;

    status = WskRegister(&wskClientNpi, &WskRegistration);
    VERIFY_NTSUCCESS(status);

    WskRegistered = TRUE;

    status = WskCaptureProviderNPI(&WskRegistration,
        WSK_NO_WAIT,
        &WskProviderNpi);
    VERIFY_NTSUCCESS(status);

    WskProviderNpiCaptured = TRUE;

    status = WskProviderNpi.Dispatch->WskControlClient(
        WskProviderNpi.Client,
        WSKNDK_GET_WSK_PROVIDER_NDK_DISPATCH,
        0,
        NULL,
        sizeof(WskNdkDispatch),
        &WskNdkDispatch,
        NULL,
        NULL);
    VERIFY_NTSUCCESS(status);

exit:
    if (!NT_SUCCESS(status))
    {
        NdkDeInitialize();
    }

    return status;

}

//
// Releases resources that were acquired by NdkInitialize.
//
// It is safe to call this routine even if NdkInitialize did not succeed or was not called.
//
// @irql PASSIVE_LEVEL
//
// @sa NdkInitialize
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NdkDeInitialize()
{
    PAGED_CODE();

    if (WskProviderNpiCaptured)
    {
        WskReleaseProviderNPI(&WskRegistration);
        WskProviderNpiCaptured = FALSE;
    }

    if (WskRegistered)
    {
        WskDeregister(&WskRegistration);
        WskRegistered = FALSE;
    }
}

//
// Opens the NDK adapter object associated with the specified interface index.
//
// @param[in] InterfaceIndex The interface index of the NDK adapter
//
// @param[out] Adapter A pointer to an NDK_ADAPTER pointer which recieves the address of the 
// specified adapter object.
//
// @retval STATUS_SUCCESS The adapter was successfully opened
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql PASSIVE_LEVEL
//
// @sa NdkCloseAdapter
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkOpenAdapter(
_In_ NET_IFINDEX InterfaceIndex,
_Outptr_ NDK_ADAPTER **Adapter
)
{
    NDK_VERSION ndkVersion = { 1, 0 };

    PAGED_CODE();

    return WskNdkDispatch.WskOpenNdkAdapter(WskProviderNpi.Client,
        ndkVersion,
        InterfaceIndex,
        Adapter);
}

//
// Retrieves information about an RDMA adapter
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represents the adapter to query.
//
// @param[out] AdapterInfo A pointer to the NDK_ADAPTER_INFO struct that will receive the 
// specified adapter's info.
//
// @retval STATUS_SUCCESS The adapter info was successfully queried.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkQueryAdapterInfo(
_In_ NDK_ADAPTER *Adapter,
_Out_ NDK_ADAPTER_INFO *AdapterInfo
)
{
    ULONG adapterInfoSize = sizeof(NDK_ADAPTER_INFO);

    PAGED_CODE();

    RtlZeroMemory(AdapterInfo, adapterInfoSize);

    return Adapter->Dispatch->NdkQueryAdapterInfo(Adapter, AdapterInfo, &adapterInfoSize);
}

//
// Releases the resources that were aquired when the specified NDK adapter was opened.
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represents the adapter to close.
//
// @irql PASSIVE_LEVEL
//
// @sa NdkOpenAdapter
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NdkCloseAdapter(
_In_ _Frees_ptr_ NDK_ADAPTER *Adapter
)
{
    PAGED_CODE();
    
    WskNdkDispatch.WskCloseNdkAdapter(WskProviderNpi.Client, Adapter);
}

//
// Creates an NDK completion queue
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represent the adapter on which the
// completion queue will be created.
//
// @param[in] Depth Specifies the number of completion entries that the queue will be capable
// of storing.
//
// @param[in] NotificationEventHandler A pointer to the event handler that will be invoked  
// when a completion event occurs.
//
// @param[in] Context An optional pointer to a context object that will be passed as the 
// CqNotificationContext argument of the NotificationEventHandler.
//
// @param[in] Affinity An optional pointer to a GROUP_AFFINITY object that specifies the 
// processor group to which this completion queue will be affinitized.
//
// @param[out] CompletionQueue A pointer to a NDK_CQ pointer that will receive the address of 
// the newly created NDK_CQ object.
//
// @retval STATUS_SUCCESS The completion queue was successfully created
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
// @sa NdkCloseCompletionQueue
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateCompletionQueue(
_In_ NDK_ADAPTER *Adapter,
_In_ ULONG Depth,
_In_ NDK_FN_CQ_NOTIFICATION_CALLBACK NotificationEventHandler,
_In_opt_ PVOID Context,
_In_opt_ GROUP_AFFINITY *Affinity,
_Outptr_ NDK_CQ **CompletionQueue
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Adapter->Dispatch->NdkCreateCq(Adapter,
        Depth,
        NotificationEventHandler,
        Context,
        Affinity,
        NdkCreateFnCompletionCallback,
        &ctx,
        CompletionQueue);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
        *CompletionQueue = (NDK_CQ*)ctx.NdkObject;
    }

    if (!NT_SUCCESS(status))
    {
        *CompletionQueue = NULL;
    }

    return status;
}

//
// Arms a completion queue so that the completion queue's notification callback will be 
// invoked when the specified type of completion notification is queued to the completion queue.
//
// @param[in] CompletionQueue A pointer to the NDK_CQ object that represents the completion queue.
//
// @param[in] TriggerType The type of completion notification that will trigger the CQ's 
// notification event handler to be invoked. TriggerType must be one of the following values:
//
// - NDK_CQ_NOTIFY_ERRORS: the notification callback will be invoked if there are any
//   completion queue errors such as a completion queue overrun or catastrophic failure.
// - NDK_CQ_NOTIFY_ANY: the notification callback will be invoked when the next completion
//   is queued to the completion queue.
// - NDK_CQ_NOTIFY_SOLICITED: the notification callback will be invoked when the completion
//   queue receives an incoming Send request that includes the NDK_OP_FLAG_SEND_AND_SOLICIT_EVENT 
//   flag.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkArmCompletionQueue(
_In_ NDK_CQ *CompletionQueue,
_In_ ULONG TriggerType
)
{
    NT_ASSERT((NDK_CQ_NOTIFY_ERRORS == TriggerType) ||
        (NDK_CQ_NOTIFY_ANY == TriggerType) ||
        (NDK_CQ_NOTIFY_SOLICITED == TriggerType));

    CompletionQueue->Dispatch->NdkArmCq(CompletionQueue, TriggerType);
}

//
// Closes an NDK completion queue.
//
// @param[in] CompletionQueue A pointer to the NDK_CQ object that represents the completion 
// queue.
//
// @irql <= APC_LEVEL
//
// @sa NdkCreateCompletionQueue
//
_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseCompletionQueue(
_In_ _Frees_ptr_ NDK_CQ *CompletionQueue
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = CompletionQueue->Dispatch->NdkCloseCq(&CompletionQueue->Header,
        NdkCloseFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
    }
}

//
// Creates an NDK protection domain
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represents the adapter on which 
// to create the protection domain.
//
// @param[out] ProtectionDomain A pointer to an NDK_PD pointer that will receive the address of 
// the NDK_PD object that represents the newly created protection domain.
//
// @retval STATUS_SUCCESS The protection domain was successfully created
//
// @retval "An NTSTATUS error code" An error occurred
//
// @irql <= APC_LEVEL
//
// @sa NdkCloseProtectionDomain
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateProtectionDomain(
_In_ NDK_ADAPTER *Adapter,
_Outptr_ NDK_PD **ProtectionDomain
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Adapter->Dispatch->NdkCreatePd(Adapter,
        NdkCreateFnCompletionCallback,
        &ctx,
        ProtectionDomain);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
        *ProtectionDomain = (NDK_PD*)ctx.NdkObject;
    }

    if (!NT_SUCCESS(status))
    {
        *ProtectionDomain = NULL;
    }

    return status;
}

//
// Closes an NDK protection domain
//
// @param[in] ProtectionDomain A pointer to the NDK_PD object that represents the protection 
// domain to close.
//
// @irql <= APC_LEVEL
//
// @sa NdkCreateProtectionDomain
//
_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseProtectionDomain(
_In_ _Frees_ptr_ NDK_PD *ProtectionDomain
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = ProtectionDomain->Dispatch->NdkClosePd(&ProtectionDomain->Header,
        NdkCloseFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
    }
}

//
// Creates an NDK queue pair (receive/work queues)
//
// @param[in] ProtectionDomain A pointer to the NDK_PD object that represents the protection 
// domain in which to create the queue pair.
//
// @param[in] ReceiveCompletionQueue A pointer to the NDK_CQ object that represents the 
// completion queue into which receive request completions will be queued.
//
// @param[in] WorkCompletionQueue A pointer to the NDK_CQ object that represents the completion
// queue into which work request completions will be queued.
//
// @param[in] Context An optional pointer to a context object that will be returned in the 
// NDK_RESULT's QPContext field for all requests posted to this queue pair.
//
// @param[in] ReceiveQueueDepth The number of receive requests that the receive queue will be
// capable of storing.
//
// @param[in] WorkQueueDepth The number of work requests that the work queue will be capable 
// of storing.
//
// @param[in] MaxReceiveSges The maximum number of scatter gather elements that can be 
// associated with a receive request.
//    
// @param[in] MaxWorkRequestSges The maximum number of scatter gather elements that can be
// associated with a work request.
//
// @param[out] QueuePair A pointer to the NDK_QP pointer that will receive the address of the 
// newly created queue pair object.
//
// @retval STATUS_SUCCESS The queue pair was successfully created
//
// @retval "An NTSTATUS error code" An error occurred
// 
// @irql <= APC_LEVEL
//
// @sa NdkCloseQueuePair
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateQueuePair(
_In_ NDK_PD *ProtectionDomain,
_In_ NDK_CQ *ReceiveCompletionQueue,
_In_ NDK_CQ *WorkCompletionQueue,
_In_opt_ PVOID Context,
_In_ ULONG ReceiveQueueDepth,
_In_ ULONG WorkQueueDepth,
_In_ ULONG MaxReceiveSges,
_In_ ULONG MaxWorkRequestSges,
_Outptr_ NDK_QP **QueuePair
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = ProtectionDomain->Dispatch->NdkCreateQp(ProtectionDomain,
        ReceiveCompletionQueue,
        WorkCompletionQueue,
        Context,
        ReceiveQueueDepth,
        WorkQueueDepth,
        MaxReceiveSges,
        MaxWorkRequestSges,
        0, // we don't use inline data
        NdkCreateFnCompletionCallback,
        &ctx,
        QueuePair);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
        *QueuePair = (NDK_QP*)ctx.NdkObject;
    }

    if (!NT_SUCCESS(status))
    {
        *QueuePair = NULL;
    }

    return status;
}

//
// Gets NDK_RESULT results from a socket's receive completion queue
//
// @param[in] Socket The socket from which to drain the receive queue
//
// @returns the number of results that were drained from the queue.  
// 0 means there were no completions in the queue
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NdkGetRcqResults(
_Inout_ RDMA_SOCKET *Socket)
{
    return Socket->NdkRcq->Dispatch->NdkGetCqResults(
        Socket->NdkRcq,
        Socket->NdkRcqResult,
        Socket->MaxNumReceives);
}

//
// Gets NDK_RESULT_EX results from a socket's receive completion queue
//
// @param[in] Socket The socket from which to drain the receive queue
//
// @returns the number of results that were drained from the queue.  
// 0 means there were no completions in the queue
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NdkGetRcqResultsEx(
_Inout_ RDMA_SOCKET *Socket)
{
    return Socket->NdkRcq->Dispatch->NdkGetCqResultsEx(
        Socket->NdkRcq,
        Socket->NdkRcqResultEx,
        Socket->MaxNumReceives);
}

//
// Gets NDK_RESULT_EX results from a socket's send completion queue
//
// @param[in] Socket The socket from which to drain the send queue
//
// @returns the number of results that were drained from the queue.  
// 0 means there were no completions in the queue
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NdkGetScqResults(
_Inout_ RDMA_SOCKET *Socket)
{
    return Socket->NdkScq->Dispatch->NdkGetCqResults(
        Socket->NdkScq,
        Socket->NdkScqResult,
        SCQ_BATCH_SIZE);
}

//
// Flushes an NDK queue pair
//
// @param[in] QueuePair A pointer to the NDK_QP object to flush
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkFlushQueuePair(
_In_ NDK_QP *QueuePair)
{
    QueuePair->Dispatch->NdkFlush(QueuePair);
}

//
// Closes an NDK queue pair
//
// @param[in] QueuePair A pointer to the NDK_QP object that represents the queue pair to close.
//
// @irql <= APC_LEVEL
//
// @sa NdkCreateQueuePair
//
_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseQueuePair(
_In_ _Frees_ptr_ NDK_QP *QueuePair
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = QueuePair->Dispatch->NdkCloseQp(&QueuePair->Header,
        NdkCloseFnCompletionCallback,
        &ctx);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
    }
    else
    {
        NT_ASSERT(NT_SUCCESS(status));
    }
}

//
// Creates an NDK connector
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represents the adapter on which
// the connector will be created.
//
// @param[out] Connector A pointer to the NDK_CONNECTOR pointer that will receive the address 
// of the newly created NDK_CONNECTOR object.
//
// @retval STATUS_SUCCESS The connector was successfully created
//
// @retval "An NTSTATUS error code" An error occurred
//
// @irql <= APC_LEVEL
//
// @sa NdkCloseConnector
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateConnector(
_In_ NDK_ADAPTER *Adapter,
_Outptr_ NDK_CONNECTOR **Connector
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Adapter->Dispatch->NdkCreateConnector(Adapter,
        NdkCreateFnCompletionCallback,
        &ctx,
        Connector);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
        *Connector = (NDK_CONNECTOR*)ctx.NdkObject;
    }

    if (!NT_SUCCESS(status))
    {
        *Connector = NULL;
    }

    return status;
}

//
// Gets the private data sent by the peer via connect, accept, or reject request and the 
// effective InboundReadLimit/OutboundReadLimit values.
//
// @param[in] Connector - a pointer to the NDK_CONNECTOR object that represents the connector
// on which a connect / accept / reject request has been received.
//
// @param[out] InboundReadLimit An optional pointer to a ULONG that receives the value of the 
// peer's IRD
//
// @param[out] OutboundReadLimit An optional pointer to a ULONG that receives the value of the
// peer's ORD
//
// @retval STATUS_SUCCESS Successfully retrieved the connection data
//
// @retval "An NTSTATUS error code" An error occurred
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkGetConnectionData(
_In_ NDK_CONNECTOR *Connector,
_Out_opt_ PULONG InboundReadLimit,
_Out_opt_ PULONG OutboundReadLimit
)
{
    ULONG PrivateDataLen = 0;

    return Connector->Dispatch->NdkGetConnectionData(Connector,
        InboundReadLimit,
        OutboundReadLimit,
        NULL,
        &PrivateDataLen);
}

//
// Initiate a connect request from the local client socket to a remote address
//
// @param[in] ClientSocket A pointer to the client socket from which to initiate the request
//
// @retval STATUS_SUCCESS The connect request was initiated
//
// @retval "An NTSTATUS error code" An error occurred.  The connection could not be established
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkConnect(
_In_ RDMA_SOCKET *ClientSocket)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    NT_ASSERT(ClientSocket->Type == RdmaClientSocket);

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    //
    // Since the socket isn't connected yet, grab read limits from the adapter.  The socket limits
    // get set later
    //
    status = ClientSocket->NdkConnector->Dispatch->NdkConnect(ClientSocket->NdkConnector,
        ClientSocket->NdkQp,
        ClientSocket->LocalAddress,
        RdmaGetSockaddrCbSize(ClientSocket->LocalAddress),
        ClientSocket->RemoteAddress,
        RdmaGetSockaddrCbSize(ClientSocket->RemoteAddress),
        ClientSocket->RdmaAdapter->MaxInboundReadLimit,
        ClientSocket->RdmaAdapter->MaxOutboundReadLimit,
        NULL,
        0,
        NdkFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    return status;
}

//
// Complete a connection request initiated by a previous call to NdkConnect.  Consumers call this
//  after the peer accepts the connection and NdkConnect completes
//
// @param[in] ClientSocket A pointer to the client socket from which to initiate the request
//
// @retval STATUS_SUCCESS The connection was completed and the socket is now connected
//
// @retval "An NTSTATUS error code" An error occurred.  The connection could not be established
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCompleteConnect(
_In_ RDMA_SOCKET *ClientSocket)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    NT_ASSERT(ClientSocket->Type == RdmaClientSocket);

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = ClientSocket->NdkConnector->Dispatch->NdkCompleteConnect(
        ClientSocket->NdkConnector,
        NdkDisconnectEventCallback,
        ClientSocket,
        NdkFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    return status;
}

//
// Accept an incoming connect request on a server socket
//
// @param[in] ServerSocket A pointer to the server socket on which to accept the connection
//
// @retval STATUS_SUCCESS The connection was accepted successfully
//
// @retval "An NTSTATUS error code" An error occurred. The connection was not accepted
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkAccept(
_In_ RDMA_SOCKET *ServerSocket)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    NT_ASSERT(ServerSocket->Type == RdmaServerSocket);

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = ServerSocket->NdkConnector->Dispatch->NdkAccept(ServerSocket->NdkConnector,
        ServerSocket->NdkQp,
        ServerSocket->MaxInboundReadLimit,
        ServerSocket->MaxOutboundReadLimit,
        NULL,
        0,
        NdkDisconnectEventCallback,
        ServerSocket,
        NdkFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    return status;
}

//
// Closes an NDK connector
//
// @param[in] Connector A pointer to the NDK_CONNECTOR object to close
//
// @irql <= APC_LEVEL
//
// @sa NdkCreateConnector
//
_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseConnector(
_In_ _Frees_ptr_ NDK_CONNECTOR *Connector)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Connector->Dispatch->NdkCloseConnector(&Connector->Header,
        NdkCloseFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
    }
}

//
// Closes an NDK connector asynchronously. The caller will not be notified when the close has
// completed. If the connector was created by an NDK_LISTENER for an incoming connection request
// then closing the connector will implicitly reject the incoming connection.
//
// @param[in] Connector A pointer to the NDK_CONNECTOR object that represents the connector to 
// close.
//
// @irql <= DISPATCH_LEVEL
//
// @sa NdkCreateConnector
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkCloseConnectorAsyncNoCallback(
_In_ _Frees_ptr_ NDK_CONNECTOR *Connector
)
{
    Connector->Dispatch->NdkCloseConnector(&Connector->Header,
        NdkCloseFnDoNothingCompletionCallback,
        NULL);
}

//
// Creates an NDK Listener object to accept incoming NDK connect requests
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represents the adapter on which 
// the listener will be created.
//
// @param[in] ConnectEventHandler A pointer to the event handler that will be invoked by NDK 
// when a connection request arrives on the listener.
//
// @param[in] Context A pointer to an optional context object that will be passed by NDK to the 
// connect event handler via its Context argument.
//
// @param[out] Listener - a pointer to the NDK_LISTENER pointer that will receive the address of
// the NDK_LISTENER object that represents the newly created listener.
//
// @retval STATUS_SUCCESS The listener was successfully created.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
// @sa NdkCloseListener
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateListener(
_In_ NDK_ADAPTER *Adapter,
_In_ NDK_FN_CONNECT_EVENT_CALLBACK ConnectEventHandler,
_In_opt_ PVOID Context,
_Outptr_ NDK_LISTENER **Listener
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Adapter->Dispatch->NdkCreateListener(Adapter,
        ConnectEventHandler,
        Context,
        NdkCreateFnCompletionCallback,
        &ctx,
        Listener);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
        *Listener = (NDK_LISTENER*)ctx.NdkObject;
    }

    if (!NT_SUCCESS(status))
    {
        *Listener = NULL;
    }

    return status;
}

//
// Puts a listener into listening mode on a given address and port.
//
// @param[in] Listener A pointer to the NDK_LISTENER object that represents the listener.
//
// @param[in] Address A pointer to the SOCKADDR object that defines the IP address and port on 
// which the listener should listen for incoming connections.
//
// @param[in] AddressCbLength The size, in bytes, of the Address struct.
//
// @retval STATUS_SUCCESS The listener has successfully been put into listening mode
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkListen(
_In_ NDK_LISTENER *Listener,
_In_reads_bytes_(AddressCbLength) CONST PSOCKADDR Address,
_In_ ULONG AddressCbLength
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Listener->Dispatch->NdkListen(Listener,
        Address,
        AddressCbLength,
        NdkFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    return status;
}

//
// Pauses an NDK Listener
//
// @param[in] Listener A pointer to the NDK_LISTENER to pause
//
// @irql <= DISPATCH_LEVEL
//
// @sa NdkCreateListener
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkPauseListener(
_In_ NDK_LISTENER *Listener)
{
    Listener->Dispatch->NdkControlConnectEvents(Listener, TRUE);
}

//
// Closes an NDK listener
//
// @param[in] Listener A pointer to the NDK_LISTENER object that represents the listener to close.
//
// @irql <= APC_LEVEL
//
// @sa NdkCreateListener
//
_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseListener(
_In_ _Frees_ptr_ NDK_LISTENER *Listener)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Listener->Dispatch->NdkCloseListener(
        &Listener->Header,
        NdkCloseFnCompletionCallback,
        &ctx);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
    }
}

//
// Creates a memory region
//
// @param[in] ProtectionDomain A pointer to the NDK_PD object that represents the protection 
// domain in which to create the queue pair.
//
// @param[out] MemoryRegion A pointer to the NDK_MR pointer that will receive the address of the 
// newly created memory region object.
//
// @retval STATUS_SUCCESS The memory region was successfully created.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
// @sa NdkCloseMemoryRegionAsyncNoCallback
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateFastRegisterMemoryRegion(
_In_ NDK_PD *ProtectionDomain,
_Outptr_ NDK_MR **MemoryRegion
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = ProtectionDomain->Dispatch->NdkCreateMr(ProtectionDomain,
        TRUE,
        NdkCreateFnCompletionCallback,
        &ctx,
        MemoryRegion);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
        *MemoryRegion = (NDK_MR*)ctx.NdkObject;
    }

    if (!NT_SUCCESS(status))
    {
        *MemoryRegion = NULL;
    }

    return status;

}

//
// Initializes a fast-register memory region (FRMR) prior to it being fast registered
//
// @param[in] MemoryRegion A pointer to the NDK_MR that represents the memory region to 
// initialize for fast registration. This memory region must be eligible for fast registration.
//
// @param[in] AdapterPageCount The maximum number of adapter pages that the FRMR will be able
// to register.
//
// @param[in] AllowRemoteAccess Indicates whether the FRMR will be used to register memory that
// will be remotely accessible by the peer (TRUE) or not (FALSE).
//
// @retval STATUS_SUCCESS The FRMR initialization completed successfully
//
// @retval "An NTSTATUS error code" An error occurred
//
// @irql <= APC_LEVEL
//
// @sa NdkCreateFastRegisterMemoryRegion
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkInitializeFastRegisterMemoryRegion(
_In_ NDK_MR *MemoryRegion,
_In_ ULONG AdapterPageCount,
_In_ BOOLEAN AllowRemoteAccess
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = MemoryRegion->Dispatch->NdkInitializeFastRegisterMr(MemoryRegion,
        AdapterPageCount,
        AllowRemoteAccess,
        NdkFnCompletionCallback,
        &ctx);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    return status;
}

//
// Closes an NDK memory region asynchronously
//
// @param[in] MemoryRegion An optional pointer to the NDK_MR object that represents the 
// memory region to close.
//
// @irql <= DISPATCH_LEVEL
//
// @sa NdkCreateFastRegisterMemoryRegion
//
// @note If no completion callback routine is specified then the caller only knows that the MR
// has finished closing when the MR's protection domain finishes closing. A request to close a
// protection domain will pend until all the MRs that were created in the PD finish closing.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkCloseMemoryRegionAsyncNoCallback(
_In_ _Frees_ptr_ NDK_MR *MemoryRegion
)
{
    MemoryRegion->Dispatch->NdkCloseMr(&MemoryRegion->Header,
        NdkCloseFnDoNothingCompletionCallback,
        NULL);
}

//
// Posts a receive request to a socket's QP
//
// @param[in] Socket A pointer to the Socket on which to post the receive
//
// @param[in] LamBuffer A pointer to the LAM_BUFFER which will hold the result of the receive
//
// @retval STATUS_SUCCESS The receive request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the 
// QP and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkReceive(
_In_ RDMA_SOCKET *Socket,
_In_ LAM_BUFFER *LamBuffer)
{
    return Socket->NdkQp->Dispatch->NdkReceive(Socket->NdkQp,
        LamBuffer,
        LamBuffer->NdkSgl,
        LamBuffer->nSge);
}

//
// Posts a send request to a socket's QP
//
// @param[in] Socket A pointer to the Socket on which to post the send
//
// @param[in] wr A pointer to the send work request to post
//
// @param[in] Flags NDK flags that specify how the NDK subsystem should process the send request.
//
// @retval STATUS_SUCCESS The send request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the QP 
// and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkSend(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags)
{
    NT_ASSERT(wr->Type == SQSend);

    return Socket->NdkQp->Dispatch->NdkSend(Socket->NdkQp,
        wr,
        wr->Send.NdkSgl,
        wr->Send.nSge,
        Flags);
}

//
// Posts a send request to a socket's QP and supplies a token to be invalidated upon receive completion
//
// @param[in] Socket A pointer to the Socket on which to post the send
//
// @param[in] wr A pointer to the send work request to post
//
// @param[in] Flags NDK flags that specify how the NDK subsystem should process the send request.
//
// @retval STATUS_SUCCESS The request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the QP 
// and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkSendAndInvalidate(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags)
{
    NT_ASSERT(wr->Type == SQSend);

    return Socket->NdkQp->Dispatch->NdkSendAndInvalidate(Socket->NdkQp,
        wr,
        wr->Send.NdkSgl,
        wr->Send.nSge,
        Flags,
        wr->Send.RemoteMemoryRegionToken);
}

//
// Posts a read request to a socket's QP
//
// @param[in] Socket A pointer to the Socket on which to post the read
//
// @param[in] wr A pointer to the work request to post
//
// @param[in] Flags NDK flags that specify how the NDK subsystem should process the request.
//
// @retval STATUS_SUCCESS The request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the QP 
// and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkRead(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags)
{
    NT_ASSERT(wr->Type == SQRead);

    return Socket->NdkQp->Dispatch->NdkRead(Socket->NdkQp,
        wr,
        wr->Read.NdkSgl,
        wr->Read.nSge,
        wr->Read.RemoteAddress,
        wr->Read.RemoteToken,
        Flags);
}

//
// Posts a write request to a socket's QP
//
// @param[in] Socket A pointer to the Socket on which to post the write
//
// @param[in] wr A pointer to the work request to post
//
// @param[in] Flags NDK flags that specify how the NDK subsystem should process the request.
//
// @retval STATUS_SUCCESS The request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the QP 
// and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkWrite(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags)
{
    NT_ASSERT(wr->Type == SQWrite);

    return Socket->NdkQp->Dispatch->NdkWrite(Socket->NdkQp,
        wr,
        wr->Write.NdkSgl,
        wr->Write.nSge,
        wr->Write.RemoteAddress,
        wr->Write.RemoteToken,
        Flags);
}

//
// Posts a fast register request to a socket's QP
//
// @param[in] Socket A pointer to the Socket on which to post the write
//
// @param[in] wr A pointer to the work request to post
//
// @param[in] Flags NDK flags that specify how the NDK subsystem should process the request.
//
// @retval STATUS_SUCCESS The request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the QP 
// and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkFastRegister(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags)
{
    NT_ASSERT(wr->Type == SQFastRegister);

    return Socket->NdkQp->Dispatch->NdkFastRegister(Socket->NdkQp,
        wr,
        wr->FastRegister.NdkMr,
        wr->FastRegister.AdapterPageCount,
        wr->FastRegister.AdapterPageArray,
        0,
        wr->FastRegister.Length,
        wr->FastRegister.BaseVirtualAddress,
        Flags);
}

//
// Posts an invalidate request to a socket's QP
//
// @param[in] Socket A pointer to the Socket on which to post the write
//
// @param[in] wr A pointer to the work request to post
//
// @param[in] Flags NDK flags that specify how the NDK subsystem should process the request.
//
// @retval STATUS_SUCCESS The request has successfully been posted to the QP and a 
// completion will be queued to the CQ when it completes.
//
// @retval "An NTSTATUS error code" An error occurred. The request was not posted to the QP 
// and no completion will be queued to the CQ.
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkInvalidate(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags)
{
    NT_ASSERT(wr->Type == SQInvalidate);

    return Socket->NdkQp->Dispatch->NdkInvalidate(
        Socket->NdkQp,
        wr,
        wr->Invalidate.NdkMrOrMw,
        Flags);
}

//
// Builds an adapter logical address mapping (LAM) for a virtually contiguous range of memory
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object that represents the adapter for which
// the LAM will be built.
//
// @param[in] Mdl A pointer to an MDL or MDL chain that describes a virtually contiguous 
// memory range.
//
// @param[in] BytesToMap The number of bytes to map starting from the virtual address of the
// first MDL.
//
// @param[out] Lam A pointer to the NDK_LOGICAL_ADDRESS_MAPPING that represents the LAM object
// that receives the mapping.
//
// @param[in,out] LamCbSize The size, in bytes, of the LAM object
// 
// @param[out] Fbo The first byte offset (FBO) of the LAM
//
// @retval STATUS_SUCCESS The LAM was successfully built
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkBuildLam(
_In_ NDK_ADAPTER *Adapter,
_In_ PMDL Mdl,
_In_ SIZE_T BytesToMap,
_Out_writes_bytes_to_opt_(*LamCbSize, *LamCbSize) NDK_LOGICAL_ADDRESS_MAPPING *Lam,
_Inout_ PULONG LamCbSize,
_Out_ PULONG Fbo
)
{
    NTSTATUS status;
    RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT ctx;

    PAGED_CODE();

    KeInitializeEvent(&ctx.Event, NotificationEvent, FALSE);

    status = Adapter->Dispatch->NdkBuildLAM(Adapter,
        Mdl,
        BytesToMap,
        NdkFnCompletionCallback,
        NULL,
        Lam,
        LamCbSize,
        Fbo);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    return status;
}

//
// Releases a previously allocated LAM.
//
// @param[in] Adapter A pointer to the NDK_ADAPTER object which initially allocated this LAM
//
// @param[in] Lam A pointer to the LAM object to free
//
// @irql <= DISPATCH_LEVEL
//
// @sa NdkBuildLam
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkReleaseLam(
_In_ NDK_ADAPTER *Adapter,
_In_ _Frees_ptr_ NDK_LOGICAL_ADDRESS_MAPPING *Lam)
{
    Adapter->Dispatch->NdkReleaseLAM(Adapter, Lam);
}
