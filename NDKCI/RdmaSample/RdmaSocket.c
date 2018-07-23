/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaSocket.c

Abstract:

    Contains functions for creating/deleting and posting various requests to a
    RDMA_SOCKET object.  The RDMA_SOCKET object is the main object to work with
    and provides socket-level semantics on top of the RDMA NDKPI in the sample
    RDMA subsystem.

    Being a sample subsystem it lacks a number of features, is not optimized for
    performance and requires many operations to be synchronous, but it should give 
    a good idea of how to build socket-like semantics on top of the NDKPI.

--*/

#include "precomp.h"

//
// Callback that is invoked by NDK when an NDK-level connect request arrives at an RDMA_LISTEN_SOCKET
// This routine is invoked by NDK when an incoming connection request arrives on a listen socket.  It
// saves some basic information about the request and then queues a work item to finish processing it.
//
// @param[in] Context A pointer to the RDMA_LISTEN_SOCKET object that represents the listen
// socket on which the connection request arrived.
//
// @param[in] NdkConnector A pointer to the NDK_CONNECTOR object that the NDK subsystem created
// to represent the incoming connection. Responsibility for closing the NDK_CONNECTOR passes to
// this routine.
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_CONNECT_EVENT_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
RdmaNdkConnectEventCallback(
    _In_opt_ PVOID Context,
    _In_ NDK_CONNECTOR *NdkConnector)
{
    NTSTATUS status;
    PIO_WORKITEM WorkItem = NULL;
    RDMA_NDK_CONNECT_REQUEST *ConnectRequest = NULL;
    RDMA_LISTEN_SOCKET *ListenSocket = (RDMA_LISTEN_SOCKET *)Context;
    ULONG RemoteAddressCbSize = sizeof(SOCKADDR_STORAGE);

    NT_ASSERT(ListenSocket);

    ConnectRequest = RdmaAllocateNpp(sizeof(*ConnectRequest));
    VERIFY_MALLOC(ConnectRequest);

    status = NdkConnector->Dispatch->NdkGetPeerAddress(NdkConnector, 
        (SOCKADDR *)&ConnectRequest->RemoteAddress, &RemoteAddressCbSize);
    VERIFY_NTSUCCESS(status);

    WorkItem = RdmaAllocWorkItem();
    VERIFY_MALLOC(WorkItem);

    ConnectRequest->NdkConnector = NdkConnector;
    ConnectRequest->Socket = ListenSocket;
    RdmaQueueWorkItem(WorkItem, RdmaNdkConnectEventCallbackWorkItem, ConnectRequest);

exit:
    if (!NT_SUCCESS(status))
    {
        if (ConnectRequest)
        {
            RdmaFreeNpp(ConnectRequest);
        }

        // Closing the connector rejects the connection and allows the listener to be freed
        NdkCloseConnectorAsyncNoCallback(NdkConnector);
    }
}

//
// The main worker routine that accepts an NDK-level connection.
//
// This routine will create a server socket for the incoming connection, post receives
// to the newly created server socket's QP, accept the NDK-level connection and then
// upcall into the upper level driver and let them know about the connection and give
// them a chance to accept/reject the connection.
//
// @param[in] IoObject Not used
//
// @param[in,out] Context A pointer to the RDMA_NDK_CONNECT_REQUEST object that 
// represents the incoming connection request.
//
// @param[in] IoWorkItem The work item that was allocated for this connection request.  It
// is freed at the end of the function
//
// @irql PASSIVE_LEVEL 
//
_Use_decl_annotations_
static VOID
RdmaNdkConnectEventCallbackWorkItem(
    PVOID IoObject,
    PVOID Context,
    PIO_WORKITEM IoWorkItem)
{
    NTSTATUS status;
    ULONG InboundReadLimit, OutboundReadLimit;
    RDMA_NDK_CONNECT_REQUEST *ConnectRequest = (RDMA_NDK_CONNECT_REQUEST *)Context;
    RDMA_LISTEN_SOCKET *ListenSocket = ConnectRequest->Socket;
    RDMA_SOCKET *ServerSocket = NULL;
    KLOCK_QUEUE_HANDLE LockHandle;
    
    UNREFERENCED_PARAMETER(IoObject);

    NT_ASSERT(ConnectRequest);

    status = NdkGetConnectionData(ConnectRequest->NdkConnector, 
        &InboundReadLimit, 
        &OutboundReadLimit);
    VERIFY_NTSUCCESS(status);

    status = RdmaCreateServerSocket(ListenSocket->RdmaAdapter->IfIndex, 
        ConnectRequest->NdkConnector, 
        (SOCKADDR *) &ConnectRequest->RemoteAddress, 
        ListenSocket, 
        &ServerSocket);
    VERIFY_NTSUCCESS(status);

    _No_competing_thread_begin_
    ServerSocket->State = RdmaSocketConnecting;
    _No_competing_thread_end_

    ServerSocket->MaxInboundReadLimit = (USHORT) min(MAXUSHORT, InboundReadLimit);
    ServerSocket->MaxOutboundReadLimit = (USHORT) min(MAXUSHORT, OutboundReadLimit);

    // Prevent disconnects from proceeding
    NT_VERIFY(ExAcquireRundownProtectionEx(&ServerSocket->DisconnectProtection, 1));

    // Accept the connection
    status = NdkAccept(ServerSocket);
    VERIFY_NTSUCCESS(status);

    // Check socket state
    status = RdmaCheckSocketConnecting(ServerSocket);
    VERIFY_NTSUCCESS(status);

    // Post receives
    status = RdmaAllocateAndPostReceives(ServerSocket);
    VERIFY_NTSUCCESS(status);

    // Check socket state
    status = RdmaCheckSocketConnecting(ServerSocket);
    VERIFY_NTSUCCESS(status);

    //
    // Give upper level driver a chance to accept/reject the connection
    //
    status = ListenSocket->AcceptEventCallback(
        ListenSocket->AcceptEventCallbackContext,
        ServerSocket,
        &ServerSocket->DisconnectEventCallback,
        &ServerSocket->ReceiveEventCallback,
        &ServerSocket->EventCallbackContext);
    VERIFY_NTSUCCESS(status);

    //
    // ARM CQ
    //
    NdkArmCompletionQueue(ServerSocket->NdkRcq, NDK_CQ_NOTIFY_ANY);
    NdkArmCompletionQueue(ServerSocket->NdkScq, NDK_CQ_NOTIFY_ANY);

    RDMA_LOCK_SOCKET(ServerSocket, &LockHandle);
    
    ServerSocket->DisconnectCallbackEnabled = TRUE;
    if (ServerSocket->State == RdmaSocketConnecting)
    {
        ServerSocket->State = RdmaSocketConnected;
    }

    RDMA_UNLOCK_SOCKET(ServerSocket, &LockHandle);

exit:
    if (ServerSocket)
    {
        ExReleaseRundownProtectionEx(&ServerSocket->DisconnectProtection, 1);
    }

    if (!NT_SUCCESS(status))
    {
        if (ServerSocket)
        {
            // This will close the NdkConnector as well
            RdmaCloseSocket(ServerSocket);
        }
        else
        {
            // We have to clean up the NdkConnector
            NdkCloseConnectorAsyncNoCallback(ConnectRequest->NdkConnector);
        }
    }

    RdmaFreeNpp(ConnectRequest);
    RdmaFreeWorkItem(IoWorkItem);
}

//
// Dequeues and processes a batch of receive results (NDK_RESULTs) from a
// socket's RCQ.
//
// @param[in,out] Socket Pointer to the RDMA_SOCKET structure that represents
// the socket.
//
// @param[in,out] DiscInProgress Pointer to a boolean that indicates whether a
// disconnect was in progress when this function was called.  If there was, then
// it does not call back into the upper level driver to notify it of the receives.
// It is also used as an out paramter.  If the function encounters an error when
// processing the receives, it starts the disconnect process and sets this variable
// to TRUE
//
// @returns A list of the LAM_BUFFERs that were drained from the completion queue
// and can be reposted or freed
//
// @irql <= DISPATCH_LEVEL
//
SINGLE_LIST_ENTRY
RdmaProcessReceives(
_In_ RDMA_SOCKET *Socket,
_In_ BOOLEAN *DiscInProgress)
{
    ULONG NumReceives, i;
    LAM_BUFFER *ReceiveBuffer;
    NDK_RESULT *Result;
    SINGLE_LIST_ENTRY ReceiveBufferListHead = { 0 };

    while ((NumReceives = NdkGetRcqResults(Socket)) > 0)
    {
        for (i = 0; i < NumReceives; i++)
        {
            Result = &Socket->NdkRcqResult[i];

            ReceiveBuffer = (LAM_BUFFER *)Result->RequestContext;
            ReceiveBuffer->BufferCbLength = Result->BytesTransferred;

            PushEntryList(&ReceiveBufferListHead, &ReceiveBuffer->SingleListEntry);

            if (!NT_SUCCESS(Result->Status) && !(*DiscInProgress))
            {
                *DiscInProgress = TRUE;
                RdmaQueueDisconnectWorkItem(Socket, FALSE);
            }

            if (!(*DiscInProgress) && Socket->State == RdmaSocketConnected)
            {
                Socket->ReceiveEventCallback(Socket->EventCallbackContext,
                    RdmaGetLBBuffer(ReceiveBuffer),
                    ReceiveBuffer->BufferCbLength,
                    FALSE,
                    0);
            }
        }
    }

    return ReceiveBufferListHead;
}

//
// Dequeues and processes a batch of receive results (NDK_RESULT_EXs) from a
// socket's RCQ.
//
// @param[in,out] Socket Pointer to the RDMA_SOCKET structure that represents
// the socket.
//
// @param[in,out] DiscInProgress Pointer to a boolean that indicates whether a
// disconnect was in progress when this function was called.  If there was, then
// it does not call back into the upper level driver to notify it of the receives.
// It is also used as an out paramter.  If the function encounters an error when
// processing the receives, it starts the disconnect process and sets this variable
// to TRUE
//
// @returns A list of the LAM_BUFFERs that were drained from the completion queue
// and can be reposted or freed
//
// @irql <= DISPATCH_LEVEL
//
static SINGLE_LIST_ENTRY
RdmaProcessReceivesEx(
_Inout_ RDMA_SOCKET *Socket,
_Inout_ BOOLEAN *DiscInProgress)
{
    ULONG NumReceives, i;
    LAM_BUFFER *ReceiveBuffer;
    NDK_RESULT_EX *ResultEx;
    SINGLE_LIST_ENTRY ReceiveBufferListHead = { 0 };
    BOOLEAN PeerInvalidatedMemoryRegion = FALSE;
    UINT32 PeerInvalidatedMrToken = 0;

    while ((NumReceives = NdkGetRcqResultsEx(Socket)) > 0)
    {
        for (i = 0; i < NumReceives; i++)
        {
            ResultEx = &Socket->NdkRcqResultEx[i];
            NT_ASSERT(ResultEx->Type & NdkOperationTypeReceive);
            if (ResultEx->Type == NdkOperationTypeReceiveAndInvalidate)
            {
                PeerInvalidatedMemoryRegion = TRUE;
                PeerInvalidatedMrToken = (UINT32) ResultEx->TypeSpecificCompletionOutput;
            }

            ReceiveBuffer = (LAM_BUFFER *)ResultEx->RequestContext;
            ReceiveBuffer->BufferCbLength = ResultEx->BytesTransferred;

            PushEntryList(&ReceiveBufferListHead, &ReceiveBuffer->SingleListEntry);

            if (!NT_SUCCESS(ResultEx->Status) && !(*DiscInProgress))
            {
                *DiscInProgress = TRUE;
                RdmaQueueDisconnectWorkItem(Socket, FALSE);
            }

            if (!(*DiscInProgress) && Socket->State == RdmaSocketConnected)
            {
                Socket->ReceiveEventCallback(Socket->EventCallbackContext,
                    RdmaGetLBBuffer(ReceiveBuffer),
                    ReceiveBuffer->BufferCbLength,
                    PeerInvalidatedMemoryRegion,
                    PeerInvalidatedMrToken);
            }
        }
    }

    return ReceiveBufferListHead;
}

//
// Invoked by NDK to notify us that RQ operations have completed to an RCQ.
//
// @param[in] CqNotificationContext A pointer to the RDMA_SOCKET object that 
// represents the socket that owns the RQ and RCQ.
//
// @param[in] CqStatus Indicates the status of the RCQ.  Right now the sample
// doesn't handle catastrophic CQ errors, but a production quality driver
// should
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_CQ_NOTIFICATION_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkRcqNotificationEventCallback(
    _In_opt_ PVOID CqNotificationContext,
    _In_ NTSTATUS CqStatus)
{
    NTSTATUS status;
    RDMA_SOCKET *Socket = (RDMA_SOCKET *)CqNotificationContext;
    BOOLEAN DiscProtectionAcquired;
    BOOLEAN DiscInProgress;
    LAM_BUFFER *ReceiveBuffer;
    SINGLE_LIST_ENTRY ReceiveBufferList;

    NT_ASSERT(Socket);

    if (!NT_SUCCESS(CqStatus))
    {
        // CqStatus other than STATUS_SUCCESS represents a programming error or catastrophic
        //  hardware failure that has rendered the CQ unusable.  Right now this sample doesn't
        //  handle this since it should be a rare occurence, but a production quality driver
        //  should
        NT_ASSERT(FALSE);
    }

    // Prevent disconnect from racing with receive upcall
    DiscProtectionAcquired = ExAcquireRundownProtectionEx(&Socket->DisconnectProtection, 1);
    DiscInProgress = !DiscProtectionAcquired;

    // Process receives in batches
    if (Socket->RdmaAdapter->SupportsRemoteInvalidation)
    {
        ReceiveBufferList = RdmaProcessReceivesEx(Socket, &DiscInProgress);
    }
    else
    {
        ReceiveBufferList = RdmaProcessReceives(Socket, &DiscInProgress);
    }

    //
    // Repost receive buffers
    //
    if (!DiscInProgress) {
        NT_ASSERT(ReceiveBufferList.Next);
        while (ReceiveBufferList.Next)
        {
            ReceiveBuffer = (LAM_BUFFER *)CONTAINING_RECORD(
                PopEntryList(&ReceiveBufferList),
                LAM_BUFFER,
                SingleListEntry);

            status = NdkReceive(Socket, ReceiveBuffer);
            if (!NT_SUCCESS(status))
            {
                RdmaQueueDisconnectWorkItem(Socket, FALSE);
                break;
            }
        }
    }

    //
    // Free any receive buffers that were not posted
    //
    while (ReceiveBufferList.Next)
    {
        ReceiveBuffer = (LAM_BUFFER *)CONTAINING_RECORD(
            PopEntryList(&ReceiveBufferList),
            LAM_BUFFER,
            SingleListEntry);

        ExReleaseRundownProtectionEx(&Socket->CloseProtection, 1);

        RdmaFreeLamBuffer(ReceiveBuffer);
    }

    // Re-arm completion queue
    NdkArmCompletionQueue(Socket->NdkRcq, NDK_CQ_NOTIFY_ANY);

    //
    // Release rundown protection
    //
    if (DiscProtectionAcquired)
    {
        ExReleaseRundownProtectionEx(&Socket->DisconnectProtection, 1);
    }
}

//
// Called during socket connection to allocate and post the initial receives 
// for the socket
// 
// @param[in,out] Socket A pointer to the RDMA_SOCKET object that represents 
// the socket for which receives are allocated and posted
//
// @retval STATUS_SUCCESS The number of configured receives were posted to the 
// socket's RQ
//
// @retval "An NTSTATUS error code" Failed to post the receives
//
// @irql <= APC_LEVEL
//
_Use_decl_annotations_
static NTSTATUS
RdmaAllocateAndPostReceives(
RDMA_SOCKET *Socket)
{
    NTSTATUS status = STATUS_SUCCESS;
    LAM_BUFFER *LamBuffer = NULL;
    ULONG i, ResultCbSize;
    ULONG ReceiveCbSize = Socket->MaxReceiveCbSize;

    PAGED_CODE();

    //
    // Allocate receive result array
    //
    ResultCbSize = Socket->MaxNumReceives * (Socket->RdmaAdapter->SupportsRemoteInvalidation ? sizeof(NDK_RESULT_EX) : sizeof(NDK_RESULT));
    Socket->NdkRcqResult = (NDK_RESULT *)RdmaAllocateNpp(ResultCbSize);
    VERIFY_MALLOC(Socket->NdkRcqResult);

    i = 0;
    do
    {
        // Allocate LAM buffer
        status = RdmaAllocateLamBuffer(
            Socket->RdmaAdapter->NdkAdapter,
            Socket->PrivilegedMrToken,
            ReceiveCbSize,
            Socket->MaxReceiveSges,
            &LamBuffer);
        VERIFY_NTSUCCESS(status);

        // Post receive
        status = NdkReceive(Socket, LamBuffer);
        VERIFY_NTSUCCESS(status);

        i++;
        NT_VERIFY(ExAcquireRundownProtectionEx(&Socket->CloseProtection, 1));
    } while (i < Socket->MaxNumReceives);

exit:
    if (!NT_SUCCESS(status))
    {
        if (LamBuffer)
        {
            RdmaFreeLamBuffer(LamBuffer);
        }
    }

    return status;
}

//
// Invoked by NDK to notify that SQ operations have completed to an SCQ.
//
// @param[in] CqNotificationContext A pointer to the RDMA_SOCKET object that 
// represents the socket that owns the SQ and SCQ.
//
// @param[in] CqStatus Indicates the status of the SCQ.  Right now the sample
// doesn't handle catastrophic CQ errors, but a production quality driver
// should
//
// @irql <= DISPATCH_LEVEL
//
/* NDK_FN_CQ_NOTIFICATION_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkScqNotificationEventCallback(
    _In_opt_ PVOID CqNotificationContext,
    _In_ NTSTATUS CqStatus)
{
    RDMA_SOCKET *Socket = (RDMA_SOCKET *) CqNotificationContext;
    BOOLEAN DisconnectQueued = FALSE;
    ULONG NumResults, i;
    NDK_RESULT *Result;
    SQ_WORK_REQUEST *wr;

    NT_ASSERT(Socket);

    if (!NT_SUCCESS(CqStatus))
    {
        // CqStatus other than STATUS_SUCCESS represents a programming error or catastrophic
        //  hardware failure that has rendered the CQ unusable.  Right now this sample doesn't
        //  handle this since it should be a rare occurence, but a production quality driver
        //  should
        NT_ASSERT(FALSE);
    }

    // process completions
    while ((NumResults = NdkGetScqResults(Socket)) > 0)
    {
        for (i = 0; i < NumResults; i++)
        {
            Result = &Socket->NdkScqResult[i];

            wr = (SQ_WORK_REQUEST *)Result->RequestContext;
            if (!NT_SUCCESS(Result->Status) && !DisconnectQueued)
            {
                DisconnectQueued = TRUE;
                RdmaQueueDisconnectWorkItem(Socket, FALSE);
            }

            wr->CompletionCallback(Result->Status, wr->CompletionContext);
        }
    }

    // Re-arm completion queue
    NdkArmCompletionQueue(Socket->NdkScq, NDK_CQ_NOTIFY_ANY);
}

//
// Performs socket creation tasks that are common to both client and server sockets
//
// @param[in] AdapterIfIndex The interface index of the RDMA adapter to associate 
// with the socket.
//
// @param[out] oSocket A pointer to an RDMA_SOCKET pointer that will receive the
// address of the newly created socket.
//
// @retval STATUS_SUCCESS The socket was successfully created
//
// @retval "An NTSTATUS error code" An error occurred
//
// @irql PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static NTSTATUS
RdmaCreateSocket(
_In_ IF_INDEX AdapterIfIndex,
_Outptr_ RDMA_SOCKET **oSocket
)
{
    NTSTATUS status;
    RDMA_SOCKET *Socket = NULL;
    RDMA_ADAPTER *Adapter;
    USHORT i;

    PAGED_CODE();

    Socket = (RDMA_SOCKET *)RdmaAllocateNpp(sizeof(*Socket));
    VERIFY_MALLOC(Socket);

    RtlZeroMemory(Socket, sizeof(RDMA_SOCKET));

    KeInitializeSpinLock(&Socket->Lock);

    _No_competing_thread_begin_
    Socket->State = RdmaSocketInitializing;

    KeInitializeEvent(&Socket->SocketDisconnected, NotificationEvent, FALSE);
   
    InitializeListHead(&Socket->SqWorkQueue);
    InitializeListHead(&Socket->FreeMemoryRegions);
    InitializeListHead(&Socket->RegisteredMemoryRegions);
    _No_competing_thread_end_

    ExInitializeRundownProtection(&Socket->DisconnectProtection);
    ExInitializeRundownProtection(&Socket->CloseProtection);

    Socket->DisconnectWorkItem = RdmaAllocWorkItem();
    VERIFY_MALLOC(Socket->DisconnectWorkItem);

    Socket->NdkScqResult = (NDK_RESULT *)RdmaAllocateNpp(sizeof(NDK_RESULT)* SCQ_BATCH_SIZE);
    VERIFY_MALLOC(Socket->NdkScqResult);

    status = RdmaOpenAdapter(AdapterIfIndex, &Socket->RdmaAdapter);
    VERIFY_NTSUCCESS(status);

    Adapter = Socket->RdmaAdapter;

    status = NdkCreateProtectionDomain(Adapter->NdkAdapter, &Socket->NdkPd);
    VERIFY_NTSUCCESS(status);

    Socket->NdkPd->Dispatch->NdkGetPrivilegedMemoryRegionToken(Socket->NdkPd,
        &Socket->PrivilegedMrToken);

    Socket->NdkRqDepth = Adapter->RqDepth;
    Socket->NdkSqDepth = Adapter->SqDepth;
    Socket->MaxFrmrPageCount = Adapter->MaxFrmrPageCount;

    Socket->MaxNumReceives = min(RECEIVE_MAX_BATCH_SIZE, Socket->NdkRqDepth);

    Socket->MaxReceiveSges = Adapter->MaxReceiveSges;
    Socket->MaxSqSges = Adapter->MaxSqSges;
    Socket->MaxReadSges = Adapter->MaxReadSges;

    Socket->MaxReceiveCbSize = Adapter->MaxReceiveCbSize;
    Socket->MaxSqCbSize = Adapter->MaxSqCbSize;
    Socket->MaxReadCbSize = Adapter->MaxReadCbSize;

    for (i = 0; i < MAX_NUM_REGISTERED_BUFFERS; i++)
    {
        status = RdmaAllocateRegisteredBuffer(Socket);
        VERIFY_NTSUCCESS(status);
    }

    //
    // Create the socket's Receive Completion Queue (RCQ)
    //
    status = NdkCreateCompletionQueue(Adapter->NdkAdapter,
        Socket->NdkRqDepth,
        NdkRcqNotificationEventCallback,
        Socket,
        NULL,
        &Socket->NdkRcq);
    VERIFY_NTSUCCESS(status);

    //
    // Create the socket's Send Completion Queue (SCQ)
    //
    status = NdkCreateCompletionQueue(Adapter->NdkAdapter,
        Socket->NdkSqDepth,
        NdkScqNotificationEventCallback,
        Socket,
        NULL,
        &Socket->NdkScq);
    VERIFY_NTSUCCESS(status);

    //
    // If the adapter supports interrupt moderation then set the moderation parameters
    //
    if (Adapter->SupportsInterruptModeration)
    {
        // Set RCQ interrupt moderation parameters
        status = Socket->NdkRcq->Dispatch->NdkControlCqInterruptModeration(Socket->NdkRcq,
            CQ_INTERRUPT_MODERATION_INTERVAL,
            CQ_INTERRUPT_MODERATION_COUNT);
        VERIFY_NTSUCCESS(status);

        // Set SCQ interrupt moderation parameters
        status = Socket->NdkScq->Dispatch->NdkControlCqInterruptModeration(Socket->NdkScq,
            CQ_INTERRUPT_MODERATION_INTERVAL,
            CQ_INTERRUPT_MODERATION_COUNT);
        VERIFY_NTSUCCESS(status);
    }

    //
    // Create the socket's Queue Pair (QP) - the "pair" in queue pair is the SQ and RQ.
    //
    status = NdkCreateQueuePair(Socket->NdkPd,
        Socket->NdkRcq,
        Socket->NdkScq,
        Socket,
        Socket->NdkRqDepth,
        Socket->NdkSqDepth,
        Socket->MaxReceiveSges,
        Socket->MaxSqSges,
        &Socket->NdkQp);
    VERIFY_NTSUCCESS(status);

exit:
    if (!NT_SUCCESS(status))
    {
        if (Socket)
        {
            RdmaCloseSocket(Socket);
            Socket = NULL;
        }
    }

    *oSocket = Socket;

    return status;
}

//
// Creates an RDMA client socket
//
// @param[in] AdapterIfIndex The interface index of the RDMA adapter on which the 
// socket is being created.
//
// @param[in] DisconnectEventCallback A pointer to the routine to invoke when the 
// socket is disconnected.
//
// @param[in] ReceiveEventCallback A pointer to the routine to invoke when data is 
// received on the socket.
//
// @param[in] EventCallbackContext An optional context value that will be returned 
// via the context argument of the socket's disconnect and receive event callbacks.
//
// @param[out] oSocket A pointer to an RDMA_SOCKET pointer that will receive the 
// address of the newly created client socket object.
//
// @retval STATUS_SUCCESS The socket was successfully created
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaCreateClientSocket(
_In_ IF_INDEX AdapterIfIndex,
_In_ RDMA_DISCONNECT_EVENT_CALLBACK *DisconnectEventCallback,
_In_ RDMA_RECEIVE_EVENT_CALLBACK *ReceiveEventCallback,
_In_opt_ PVOID EventCallbackContext,
_Outptr_ RDMA_SOCKET **oSocket)
{
    NTSTATUS status;
    RDMA_SOCKET *Socket;

    PAGED_CODE();

    status = RdmaCreateSocket(AdapterIfIndex, &Socket);
    VERIFY_NTSUCCESS(status);

    status = NdkCreateConnector(Socket->RdmaAdapter->NdkAdapter, &Socket->NdkConnector);
    VERIFY_NTSUCCESS(status);

    Socket->DisconnectEventCallback = DisconnectEventCallback;
    Socket->ReceiveEventCallback = ReceiveEventCallback;
    Socket->EventCallbackContext = EventCallbackContext;
    
    Socket->Type = RdmaClientSocket;

    _No_competing_thread_begin_
    Socket->State = RdmaSocketInitialized;
    _No_competing_thread_end_

exit:
    if (!NT_SUCCESS(status))
    {
        if (Socket)
        {
            RdmaCloseSocket(Socket);
            Socket = NULL;
        }
    }

    *oSocket = Socket; 

    return status;
}

//
// Creates an RDMA server socket
//
// @param[in] AdapterIfIndex The interface index of the RDMA adapter on which the 
// socket will be created.
//
// @param[in] NdkConnector A pointer to the NDK_CONNECTOR object that represents 
// the connector that is associated with an incoming connection request.
//
// @param[in] RemoteAddress A pointer to the SOCKADDR struct that stores the remote 
// address that is associated with NdkConnector.
//
// @param[in] ListenSocket A pointer to the RDMA_LISTEN_SOCKET object that represents 
// the listen socket that received the incoming connection request and created the 
// NdkConnector object.
//
// @param[out] Socket A pointer to an RDMA_SOCKET pointer that will receive the 
// address of the newly created server socket object.
//
// @retval STATUS_SUCCESS The socket was successfully created. The server socket has 
// assumed ownership of NdkConnector.
//
// @retval "An NTSTATUS error code" An error occurred. The caller is responsible for 
// closing NdkConnector.
//
// @irql PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static NTSTATUS
RdmaCreateServerSocket(
_In_ IF_INDEX AdapterIfIndex,
_In_ NDK_CONNECTOR *NdkConnector,
_In_ PSOCKADDR RemoteAddress,
_In_ RDMA_LISTEN_SOCKET *ListenSocket,
_Outptr_ RDMA_SOCKET **oSocket)
{
    NTSTATUS status;
    RDMA_SOCKET *Socket = NULL;

    PAGED_CODE();

    status = RdmaCreateSocket(AdapterIfIndex, &Socket);
    VERIFY_NTSUCCESS(status);

    Socket->RemoteAddress = RdmaAllocateNpp(RdmaGetSockaddrCbSize(RemoteAddress));
    VERIFY_MALLOC(Socket->RemoteAddress);

    Socket->LocalAddress = RdmaAllocateNpp(RdmaGetSockaddrCbSize(ListenSocket->ListenAddr));
    VERIFY_MALLOC(Socket->LocalAddress);

    RtlCopyMemory(Socket->RemoteAddress, RemoteAddress, RdmaGetSockaddrCbSize(RemoteAddress));
    RtlCopyMemory(Socket->LocalAddress, ListenSocket->ListenAddr, RdmaGetSockaddrCbSize(ListenSocket->ListenAddr));
    
    Socket->Type = RdmaServerSocket;
    Socket->NdkConnector = NdkConnector;
    
    _No_competing_thread_begin_
    Socket->State = RdmaSocketInitialized;
    _No_competing_thread_end_

exit:
    if (!NT_SUCCESS(status))
    {
        if (Socket)
        {
            RdmaCloseSocket(Socket);
            Socket = NULL;
        }
    }

    *oSocket = Socket;

    return status;
}

//
// Connects a socket to a remote transport address.
//
// An upper level driver may call this only once per socket. Once a socket has 
// been disconnected it cannot be reused.
//
// @param[in,out] Socket A pointer to an RDMA_SOCKET object that represents the 
// socket to connect.
//
// @param[in] LocalAddress A pointer to the SOCKADDR struct that defines the IP 
// address and port from which the socket will connect. If the port value is set 
// to zero then the RDMA subsystem will choose an arbitrary unused port.
//
// @param[in] RemoteAddress A pointer to the SOCKADDR struct that defines the IP 
// address and port to which the socket will connect.
//
// @retval STATUS_SUCCESS The socket was successfully connected to the remote
// endpoint
//
// @retval "An NTSTATUS error code" An error occurred and the socket could not be 
// connected.  
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaConnect(
_Inout_ RDMA_SOCKET *Socket,
_In_ CONST SOCKADDR *LocalAddress,
_In_ CONST SOCKADDR *RemoteAddress)
{
    NTSTATUS status;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG RemoteAddressSize, LocalAddressSize, InboundReadLimit, OutboundReadLimit;

    if (!ExAcquireRundownProtectionEx(&Socket->DisconnectProtection, 1))
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Check for valid socket state and set to connecting
    //
    RDMA_LOCK_SOCKET(Socket, &LockHandle);
    if (Socket->State != RdmaSocketInitialized)
    {
        RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

        status = STATUS_INVALID_DEVICE_STATE;
        goto exit;
    }

    Socket->State = RdmaSocketConnecting;
    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

    //
    // Copy over local and remote addresses
    //
    RemoteAddressSize = RdmaGetSockaddrCbSize(RemoteAddress);
    Socket->RemoteAddress = (SOCKADDR *)RdmaAllocateNpp(RemoteAddressSize);
    VERIFY_MALLOC(Socket->RemoteAddress);

    LocalAddressSize = RdmaGetSockaddrCbSize(LocalAddress);
    Socket->LocalAddress = (SOCKADDR *)RdmaAllocateNpp(LocalAddressSize);
    VERIFY_MALLOC(Socket->LocalAddress);

    RtlCopyMemory(Socket->RemoteAddress, RemoteAddress, RemoteAddressSize);
    RtlCopyMemory(Socket->LocalAddress, LocalAddress, LocalAddressSize);

    //
    // Call NdkConnect to request an NDK-level connection to the remote address
    //
    status = NdkConnect(Socket);
    VERIFY_NTSUCCESS(status);

    //
    // Check if we have disconnects in progress
    //
    status = RdmaCheckSocketConnecting(Socket);
    VERIFY_NTSUCCESS(status);

    //
    // Complete the connection
    //
    status = NdkCompleteConnect(Socket);
    VERIFY_NTSUCCESS(status);

    //
    // Check if we have disconnects in progress
    //
    status = RdmaCheckSocketConnecting(Socket);
    VERIFY_NTSUCCESS(status);

    //
    // Get read limits on the connection
    //
    status = NdkGetConnectionData(Socket->NdkConnector,
        &InboundReadLimit,
        &OutboundReadLimit);
    VERIFY_NTSUCCESS(status);

    Socket->MaxInboundReadLimit = (USHORT) min(MAXUSHORT, InboundReadLimit);
    Socket->MaxOutboundReadLimit = (USHORT) min(MAXUSHORT, OutboundReadLimit);

    //
    // The original request to connect might have specified a local port of 0 meaning that
    // the NDK provider gets to chose any unused local port for the connection. Query the 
    // local address now that the NDK-level connection is established to determine what 
    // local port was chosen. 
    //
    NT_ASSERT(Socket->LocalAddress);
    status = Socket->NdkConnector->Dispatch->NdkGetLocalAddress(Socket->NdkConnector,
        Socket->LocalAddress,
        &LocalAddressSize);
    VERIFY_NTSUCCESS(status);

    status = RdmaAllocateAndPostReceives(Socket);
    VERIFY_NTSUCCESS(status);

    //
    // Arm completion queues
    //
    NdkArmCompletionQueue(Socket->NdkRcq, NDK_CQ_NOTIFY_ANY);
    NdkArmCompletionQueue(Socket->NdkScq, NDK_CQ_NOTIFY_ANY);

    //
    // Set socket state to connected
    //
    RDMA_LOCK_SOCKET(Socket, &LockHandle);
    status = RdmaCheckSocketConnecting(Socket);
    if (NT_SUCCESS(status))
    {
        Socket->DisconnectCallbackEnabled = TRUE;
        Socket->State = RdmaSocketConnected;
    }
    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

exit:
    if (!NT_SUCCESS(status))
    {
        NT_VERIFY(ExAcquireRundownProtectionEx(&Socket->CloseProtection, 1));
        ExReleaseRundownProtectionEx(&Socket->DisconnectProtection, 1);
        RdmaDisconnect(Socket);
        ExReleaseRundownProtectionEx(&Socket->CloseProtection, 1);
    } else
    {
        ExReleaseRundownProtectionEx(&Socket->DisconnectProtection, 1);
    }

    return status;
}

//
// Synchronously disconnects a socket and waits for the socket to be fully
// disconnected before returning.
//
// @param[in,out] Socket A pointer to the RDMA_SOCKET object that represents 
// the socket to disconnect.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
VOID
RdmaDisconnect(
_In_ RDMA_SOCKET *Socket)
{
    PAGED_CODE();

    RdmaQueueDisconnectWorkItem(Socket, TRUE);
}

//
// This routine transitions the socket's state to RdmaSocketDisconnecting and
// then initiates the socket disconnection process by queueing a work item (if
// necessary) to continue the process.  It can optionally wait for the socket
// to be fully disconnected before returning
//
// @param[in,out] Socket A pointer to the RDMA_SOCKET object that represents 
// the socket to disconnect.
//
// @param[in] Wait Whether to wait for the disconnect operation to complete
//
// @irql <= DISPATCH_LEVEL if the caller does not need to wait for disconnect
// to complete.  <= APC_LEVEL otherwise
//
_Requires_lock_not_held_(Socket->Lock)
_When_(Wait, _IRQL_requires_max_(APC_LEVEL))
_When_(!Wait, _IRQL_requires_max_(DISPATCH_LEVEL))
VOID
RdmaQueueDisconnectWorkItem(
_Inout_ RDMA_SOCKET *Socket,
_In_ BOOLEAN Wait)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    BOOLEAN StartDisconnect = FALSE;

    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    switch (Socket->State)
    {
    case RdmaSocketInitialized:
        // Transition to disconnected state without doing any work
        RdmaSetSocketDisconnected(Socket);
        break;
    case RdmaSocketConnecting:
    case RdmaSocketConnected:
        Socket->State = RdmaSocketDisconnecting;
        StartDisconnect = TRUE;
        break;
    case RdmaSocketDisconnecting:
    case RdmaSocketDisconnected:
    case RdmaSocketClosing:
        // No need to do anything
        break;
    default:
        NT_ASSERT(FALSE);
        break;
    }

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

    if (StartDisconnect)
    {
        RdmaQueueWorkItem(Socket->DisconnectWorkItem, RdmaDisconnectWorkItem, Socket);
    }

    if (Wait)
    {
        KeWaitForSingleObject(&Socket->SocketDisconnected, Executive, KernelMode, FALSE, 0);
    }
}

//
// This work item routine synchronously disconnects a socket.  It flushes the 
// QP and closes the socket's connector and transitions the socket's state
// to RdmaSocketDisconnected.
//
// @param[in] IoObject Not used
//
// @param[in,out] Context A pointer to the RDMA_SOCKET object that represents 
// the socket to disconnect.
//
// @param[in] IoWorkItem the disconnect work item.  Not used
//
// @irql PASSIVE_LEVEL
//
_Use_decl_annotations_
static VOID
RdmaDisconnectWorkItem(
PVOID IoObject,
PVOID Context,
PIO_WORKITEM IoWorkItem)
{
    RDMA_SOCKET *Socket = (RDMA_SOCKET *)Context;
    KLOCK_QUEUE_HANDLE LockHandle;

    NT_ASSERT(Socket);
    NT_ASSERT(Socket->State == RdmaSocketDisconnecting);
    NT_ASSERT(Socket->DisconnectWorkItem == IoWorkItem);

    UNREFERENCED_PARAMETER(IoObject);
    UNREFERENCED_PARAMETER(IoWorkItem);

    //
    // Wait for in progress connects to finish
    //
    ExWaitForRundownProtectionRelease(&Socket->DisconnectProtection);

    //
    // Synchronously flush the QP
    //
    NdkFlushQueuePair(Socket->NdkQp);

    //
    // Synchronously close the connector
    //
    NdkCloseConnector(Socket->NdkConnector);
    Socket->NdkConnector = NULL;

    //
    // Callback into upper level driver to let them know the socket is now disconnected
    //
    if (Socket->DisconnectCallbackEnabled && Socket->DisconnectEventCallback)
    {
        Socket->DisconnectEventCallback(Socket->EventCallbackContext);
    }

    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    RdmaSetSocketDisconnected(Socket);

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);
}

//
// Closes a socket and frees all associated resources.  And upper level driver
// can call this function on a socket in any state and the RDMA subsystem will
// clean up all resources associated with the socket gracefully.
// 
// After calling this routine, the upper level driver may not make any further
// calls to any of the socket's functions.
//
// @param[in] Socket A pointer to the RDMA_SOCKET object that represents the 
// socket to close.
//
// @irql <= PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
VOID
RdmaCloseSocket(
_In_ _Frees_ptr_ RDMA_SOCKET *Socket)
{
    KLOCK_QUEUE_HANDLE LockHandle;
    BOOLEAN Disconnect = FALSE;

    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    switch (Socket->State)
    {
    case RdmaSocketInitializing:
    case RdmaSocketInitialized:
    case RdmaSocketDisconnected:
        // We can proceed directly to closing
        Socket->State = RdmaSocketClosing;
        break;

    case RdmaSocketConnecting:
    case RdmaSocketConnected:
    case RdmaSocketDisconnecting:
        // Have to wait for the socket to become disconnected
        Disconnect = TRUE;
        break;

    default:
        NT_ASSERT(FALSE);
        break;
    }

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

    if (Disconnect)
    {
        RdmaQueueDisconnectWorkItem(Socket, TRUE);

        RDMA_LOCK_SOCKET(Socket, &LockHandle);

        switch (Socket->State)
        {
        case RdmaSocketDisconnected:
            Socket->State = RdmaSocketClosing;
            break;

        default:
            NT_ASSERT(FALSE);
            break;
        }

        RDMA_UNLOCK_SOCKET(Socket, &LockHandle);
    }

    // Wait for close protection
    ExWaitForRundownProtectionRelease(&Socket->CloseProtection);

    if (Socket->NdkQp)
    {
        NdkCloseQueuePair(Socket->NdkQp);
        Socket->NdkQp = NULL;
    }

    if (Socket->NdkRcq)
    {
        NdkCloseCompletionQueue(Socket->NdkRcq);
        Socket->NdkRcq = NULL;
    }

    if (Socket->NdkScq)
    {
        NdkCloseCompletionQueue(Socket->NdkScq);
        Socket->NdkScq = NULL;
    }
    
    _No_competing_thread_begin_
    while (!IsListEmpty(&Socket->FreeMemoryRegions))
    {
        RdmaFreeRegisteredBuffer(CONTAINING_RECORD(RemoveHeadList(&Socket->FreeMemoryRegions), RDMA_REGISTERED_BUFFER, ListEntry));
    }

    while (!IsListEmpty(&Socket->RegisteredMemoryRegions))
    {
        RdmaFreeRegisteredBuffer(CONTAINING_RECORD(RemoveHeadList(&Socket->RegisteredMemoryRegions), RDMA_REGISTERED_BUFFER, ListEntry));
    }
    _No_competing_thread_end_

    if (Socket->NdkPd)
    {
        NdkCloseProtectionDomain(Socket->NdkPd);
        Socket->NdkPd = NULL;
    }

    if (Socket->RdmaAdapter)
    {
        RdmaCloseAdapter(Socket->RdmaAdapter);
        Socket->RdmaAdapter = NULL;
    }

    if (Socket->DisconnectWorkItem)
    {
        RdmaFreeWorkItem(Socket->DisconnectWorkItem);
        Socket->DisconnectWorkItem = NULL;
    }

    if (Socket->RemoteAddress)
    {
        RdmaFreeNpp(Socket->RemoteAddress);
        Socket->RemoteAddress = NULL;
    }

    if (Socket->LocalAddress)
    {
        RdmaFreeNpp(Socket->LocalAddress);
        Socket->LocalAddress = NULL;
    }

    if (Socket->NdkScqResult)
    {
        RdmaFreeNpp(Socket->NdkScqResult);
        Socket->NdkScqResult = NULL;
    }

    if (Socket->NdkRcqResult)
    {
        RdmaFreeNpp(Socket->NdkRcqResult);
        Socket->NdkRcqResult = NULL;
    }

    RdmaFreeNpp(Socket);
}

//
// Creates a RDMA listen socket.
//
// A listen socket is used to listen for and accept incoming RDMA connections.
//
// @param[in] AdapterInterfaceIndex The interface index of the RNIC on which the
// listen socket will be created.
//
// @param[in] AcceptEventCallback A pointer to the callback function that the
// sample RDMA subsystem will invoke to notify the upper level driver that a 
// connection request was received
//
// @param[in] AcceptEventCallbackContext An optional pointer to the context that 
// will be passed back to the upper level driver on the AcceptEventCallback
//
// @param[out] oListenSocket A pointer to an RDMA_LISTEN_SOCKET pointer that will 
// receive the address of the newly created listen socket object.
//
// @retval STATUS_SUCCESS The new listen socket was successfully created. It is 
// the caller's responsibility to close the socket when it is no longer needed.
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= PASSIVE_LEVEL
//
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaCreateListenSocket(
    _In_ NET_IFINDEX AdapterInterfaceIndex,
    _In_ RDMA_ACCEPT_EVENT_CALLBACK *AcceptEventCallback,
    _In_opt_ PVOID AcceptEventCallbackContext,
    _Outptr_ RDMA_LISTEN_SOCKET **oListenSocket)
{
    NTSTATUS status;
    RDMA_LISTEN_SOCKET *ListenSocket = NULL;

    PAGED_CODE();

    ListenSocket = (RDMA_LISTEN_SOCKET *)RdmaAllocateNpp(sizeof(*ListenSocket));
    VERIFY_MALLOC(ListenSocket);

    RtlZeroMemory(ListenSocket, sizeof(*ListenSocket));

    status = RdmaOpenAdapter(AdapterInterfaceIndex, &ListenSocket->RdmaAdapter);
    VERIFY_NTSUCCESS(status);

    status = NdkCreateListener(ListenSocket->RdmaAdapter->NdkAdapter,
        RdmaNdkConnectEventCallback,
        ListenSocket,
        &ListenSocket->NdkListener);
    VERIFY_NTSUCCESS(status);

    ListenSocket->AcceptEventCallbackContext = AcceptEventCallbackContext;
    ListenSocket->AcceptEventCallback = AcceptEventCallback;

    *oListenSocket = ListenSocket;

exit:
    if (!NT_SUCCESS(status))
    {
        if (ListenSocket)
        {
            RdmaCloseListenSocket(ListenSocket);
        }
    }

    return status;
}

//
// Starts listening on a supplied address and port
//
// @param[in] ListenSocket A pointer to the RDMA_LISTEN_SOCKET to start listening
// on.
//
// @param[in] ListenAddress The IP address and port on which to listen
// 
// @retval STATUS_SUCCESS The listen socket is now listening for incoming connections
//
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaListen(
_Inout_ RDMA_LISTEN_SOCKET *ListenSocket,
_In_ CONST PSOCKADDR ListenAddress)
{
    NTSTATUS status;
    ULONG ListenAddressCbLength;

    PAGED_CODE();

    ListenAddressCbLength = RdmaGetSockaddrCbSize(ListenAddress);
    ListenSocket->ListenAddr = (SOCKADDR *)RdmaAllocateNpp(ListenAddressCbLength);
    VERIFY_MALLOC(ListenSocket->ListenAddr);

    RtlCopyMemory(ListenSocket->ListenAddr, ListenAddress, ListenAddressCbLength);

    status = NdkListen(ListenSocket->NdkListener, ListenAddress, ListenAddressCbLength);
    if (!NT_SUCCESS(status))
    {
        RdmaFreeNpp(ListenSocket->ListenAddr);
        ListenSocket->ListenAddr = NULL;
    }

exit:
    return status;
}

//
// Closes a listen socket and frees any associated resources.  After calling this 
// routine, the upper level driver must not call any more functions on the listen
// socket.
//
// @param[in] ListenSocket A pointer to the RDMA_LISTEN_SOCKET object that represents 
// the listen socket to close.
//
// @irql <= PASSIVE_LEVEL
//
_Use_decl_annotations_
VOID
RdmaCloseListenSocket(
RDMA_LISTEN_SOCKET *Socket)
{
    PAGED_CODE();

    if (Socket->NdkListener)
    {
        //
        // Prevent NDK from invoking any more connect event callbacks for this listener
        //
        NdkPauseListener(Socket->NdkListener);

        //
        // Close the listener
        //
        NdkCloseListener(Socket->NdkListener);
    }

    if (Socket->ListenAddr)
    {
        RdmaFreeNpp(Socket->ListenAddr);
    }

    if (Socket->RdmaAdapter)
    {
        RdmaCloseAdapter(Socket->RdmaAdapter);
    }

    RdmaFreeNpp(Socket);
}

//
// Sends data over an RDMA socket to the remotely connected peer via the RDMA 
// send/recv channel using a priviledged memory token.
//
// @param[in,out] Socket A pointer to the RDMA_SOCKET object that represents the 
// connected socket over which the data will be sent.
//
// @param[in] SourceMdlChain A pointer to an MDL chain that describes the buffer 
// containing the data to send. The MDL can be a single MDL or the first MDL in an 
// MDL chain. The caller must guarantee that the buffers described by the MDLs are 
// pinned prior to calling this function and remain pinned until the Send operation 
// completes.
//
// @param[in] SourceCbLength The size, in bytes, of the data to send, starting 
// from the first byte described by the specified MDL.
//
// @param[in] InvalidateRemoteMemoryRegion If TRUE, requests the socket's RNIC
// to invalidate the remote memory region whose token is RemoteMemoryRegionToken
// when performing the send. Note that the send-and-invalidate capability may not
// be supported by the RNIC or its driver stack, in which case no invalidation is
// performed.
//
// @param[in] RemoteMemoryRegionToken The token of the remote memory region to
// invalidate.  Only valid if InvalidateRemoteMemoryRegion is TRUE
//
// @param[in] CompletionContext An optional pointer to the context that will be 
// passed back to the upper level driver via the Context argument of the completion 
// callback function.
//
// @param[in] CompletionCallback A pointer to the callback function that to
// invoke when the send operation has completed.
//
// @retval STATUS_PENDING The requests are queued for posting to the socket's
// SQ. The specified completion callback function will be invoked upon completion
//
// @retval "An NTSTATUS error code" An error occurred. The completion callback 
// function will not be invoked. If an error status is returned immediately or 
// via the operation's completion callback routine then socket will be automatically
// disconnected
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaSend(
_Inout_ RDMA_SOCKET *Socket,
_In_ MDL *SourceMdlChain,
_In_range_(> , 0) ULONG SourceCbLength,
_In_ BOOLEAN InvalidateRemoteMemoryRegion,
_In_ UINT32 RemoteMemoryRegionToken,
_In_opt_ PVOID CompletionContext,
_In_ RDMA_COMPLETION_CALLBACK *CompletionCallback)
{
    NTSTATUS status;
    RDMA_OPERATION *Operation = NULL;

    PAGED_CODE();

    status = RdmaCheckSocketConnected(Socket);
    VERIFY_NTSUCCESS(status);

    // Allocate operation container
    Operation = RdmaAllocateOperation(Socket, RdmaOpSend);
    VERIFY_MALLOC(Operation);

    Operation->CompletionCallback = CompletionCallback;
    Operation->CompletionContext = CompletionContext;

    status = RdmaAllocateLamChain(
        Socket->RdmaAdapter->NdkAdapter, 
        SourceMdlChain, 
        SourceCbLength, 
        &Operation->Send.LamChainHead);
    VERIFY_NTSUCCESS(status);

    Operation->Send.LamChainBytesMapped = SourceCbLength;

    status = RdmaBuildSendWorkRequests(
        Operation,
        Socket->PrivilegedMrToken,
        InvalidateRemoteMemoryRegion,
        RemoteMemoryRegionToken);
    VERIFY_NTSUCCESS(status);

    RdmaQueueSQWrs(Socket, Operation->SqWrList);

    status = STATUS_PENDING;

exit:
    if (!NT_SUCCESS(status))
    {
        if (Operation)
        {
            RdmaFreeOperation(Operation);
        }
    }

    return status;
}

//
// RDMA Writes data from a local buffer into a remote buffer
//
// @param[in,out] Socket A pointer to the RDMA_SOCKET object that represents the 
// socket on which the RDMA Writes will be performed.
//
// @param[in] WriteMdlChain A pointer to an MDL that describes the local source 
// buffer from which data will be RDMA written. The MDL can be a single MDL or the 
// first MDL in an MDL chain. The caller must guarantee that the buffers described 
// by the MDLs are pinned prior to calling this function and remain pinned until 
// the RDMA Write operation completes.
//
// @param[in] WriteCbLength The number of bytes to RDMA write into the destination 
// buffer.
//
// @param[in] RemoteAddress The remote virtual address to start writing data to
//
// @param[in] RemoteToken A token enabled for remote access that identifies the
// memory region on the remote peer in which to RDMA write data
//
// @param[in] CompletionContext An optional pointer to the context that will be 
// passed back to the upper level driver via the Context argument of the completion 
// callback function.
//
// @param[in] CompletionCallback A pointer to the callback function that to
// invoke when the operation has completed.
//
// @retval STATUS_PENDING The requests are queued for posting to the socket's
// SQ. The specified completion callback function will be invoked upon completion
//
// @retval "An NTSTATUS error code" An error occurred. The completion callback 
// function will not be invoked. If an error status is returned immediately or 
// via the operation's completion callback routine then socket will be automatically
// disconnected
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaWrite(
_Inout_ RDMA_SOCKET *Socket,
_In_ MDL *WriteMdlChain,
_In_range_(> , 0) ULONG WriteCbLength,
_In_ UINT64 RemoteAddress,
_In_ UINT32 RemoteToken,
_In_opt_ PVOID CompletionContext,
_In_ RDMA_COMPLETION_CALLBACK *CompletionCallback)
{
    NTSTATUS status;
    RDMA_OPERATION *Operation = NULL;

    NT_ASSERT(WriteCbLength != 0);
    NT_ASSERT(RdmaGetMdlChainByteCount(WriteMdlChain) >= WriteCbLength);
    
    PAGED_CODE();

    status = RdmaCheckSocketConnected(Socket);
    VERIFY_NTSUCCESS(status);

    // Allocate operation container
    Operation = RdmaAllocateOperation(Socket, RdmaOpWrite);
    VERIFY_MALLOC(Operation);

    Operation->CompletionCallback = CompletionCallback;
    Operation->CompletionContext = CompletionContext;

    status = RdmaAllocateLamChain(
        Socket->RdmaAdapter->NdkAdapter,
        WriteMdlChain,
        WriteCbLength,
        &Operation->Write.LamChainHead);
    VERIFY_NTSUCCESS(status);

    Operation->Write.LamChainBytesMapped = WriteCbLength;

    status = RdmaBuildWriteWorkRequests(
        Operation,
        Socket->PrivilegedMrToken, 
        RemoteAddress,
        RemoteToken);
    VERIFY_NTSUCCESS(status);

    RdmaQueueSQWrs(Socket, Operation->SqWrList);

    status = STATUS_PENDING;

exit:
    if (!NT_SUCCESS(status))
    {
        if (Operation)
        {
            RdmaFreeOperation(Operation);
        }
    }

    return status;
}

//
// RDMA Reads data from a remote buffer into a local buffer using a privileged 
// memory token to access the local destination buffer
//
// @param[in,out] Socket A pointer to the RDMA_SOCKET object that represents the 
// socket on which the RDMA Reads will be performed.
//
// @param[in] DestMdlChain A pointer to an MDL chain that describes the local 
// destination buffer into which data will be RDMA read. The MDL can be a single 
// MDL or the first MDL in an MDL chain. The caller must guarantee that the buffers
// described by the MDLs are pinned prior to calling this function and remain pinned 
// until the RDMA Read operation completes.
//
// @param[in] ReadCbLength The number of bytes to RDMA read into the destination buffer.
//
// @param[in] RemoteAddress The remote virtual address to start reading data from
//
// @param[in] RemoteToken A token enabled for remote access that identifies the
// memory region on the remote peer from which to RDMA read data
//
// @param[in] CompletionContext An optional pointer to the context that will be 
// passed back to the upper level driver via the Context argument of the completion 
// callback function.
//
// @param[in] CompletionCallback A pointer to the callback function that to
// invoke when the operation has completed.
//
// @retval STATUS_PENDING The requests are queued for posting to the socket's
// SQ. The specified completion callback function will be invoked upon completion
//
// @retval "An NTSTATUS error code" An error occurred. The completion callback 
// function will not be invoked. If an error status is returned immediately or 
// via the operation's completion callback routine then socket will be automatically
// disconnected
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaRead(
_Inout_ RDMA_SOCKET *Socket,
_In_ MDL *DestMdlChain,
_In_range_(> , 0) ULONG ReadCbLength,
_In_ UINT64 RemoteAddress,
_In_ UINT32 RemoteToken,
_In_opt_ PVOID CompletionContext,
_In_ RDMA_COMPLETION_CALLBACK *CompletionCallback)
{
    NTSTATUS status;
    RDMA_OPERATION *Operation = NULL;

    NT_ASSERT(ReadCbLength != 0);
    NT_ASSERT(RdmaGetMdlChainByteCount(DestMdlChain) >= ReadCbLength);

    PAGED_CODE();

    status = RdmaCheckSocketConnected(Socket);
    VERIFY_NTSUCCESS(status);

    // Allocate operation container
    Operation = RdmaAllocateOperation(Socket, RdmaOpRead);
    VERIFY_MALLOC(Operation);

    Operation->CompletionCallback = CompletionCallback;
    Operation->CompletionContext = CompletionContext;

    status = RdmaAllocateLamChain(
        Socket->RdmaAdapter->NdkAdapter,
        DestMdlChain,
        ReadCbLength,
        &Operation->Read.LamChainHead);
    VERIFY_NTSUCCESS(status);

    Operation->Read.LamChainBytesMapped = ReadCbLength;

    status = RdmaBuildReadWorkRequests(
        Operation,
        Socket->PrivilegedMrToken,
        RemoteAddress,
        RemoteToken);
    VERIFY_NTSUCCESS(status);

    RdmaQueueSQWrs(Socket, Operation->SqWrList);

    status = STATUS_PENDING;

exit:
    if (!NT_SUCCESS(status))
    {
        if (Operation)
        {
            RdmaFreeOperation(Operation);
        }
    }

    return status;
}

//
// Queue's a list of work requests to a socket's work request queue and potentially
// pumps the queue by posting all the work requests to the socket's SQ
//
// @param[in,out] Socket Pointer to the RDMA_SOCKET object that represents
// the socket.
//
// @param[in] WrList Pointer to the head of list of SQ_WORK_REQUEST objects 
// to queue on the socket. Once this routine is called, the caller may no longer 
// access this pointer as the work requests could have already completed and been 
// freed.
//
// @irql <= DISPATCH_LEVEL
//
_Use_decl_annotations_
VOID
RdmaQueueSQWrs(
RDMA_SOCKET *Socket,
SQ_WORK_REQUEST *WrList)
{
    NTSTATUS status = STATUS_SUCCESS;
    LIST_ENTRY SqList;
    SQ_WORK_REQUEST *wr = WrList, *nextWr;
    KLOCK_QUEUE_HANDLE LockHandle;
    ULONG Flags = 0;
    
    BOOLEAN SupportsDeferredPosting = Socket->RdmaAdapter->SupportsDeferredPosting;
    UCHAR DeferredCount = 0;

    //
    // If we have already begun disconnecting complete all the WRs with failure
    //
    if (!ExAcquireRundownProtectionEx(&Socket->DisconnectProtection, 1))
    {
        do {
            nextWr = wr->Next;
            wr->CompletionCallback(STATUS_CONNECTION_DISCONNECTED, wr->CompletionContext);
            wr = nextWr;
        } while (wr != NULL);

        return;
    }

    RDMA_LOCK_SOCKET(Socket, &LockHandle);

    //
    // Add the WRs to the end of the SCQ
    //
    do
    {
        InsertTailList(&Socket->SqWorkQueue, &wr->ListEntry);
        wr = wr->Next;
    } while (wr != NULL);

    if (!Socket->SqPumping)
    {
        Socket->SqPumping = TRUE;

        do
        {
            SqList = Socket->SqWorkQueue;
            SqList.Flink->Blink = &SqList;
            SqList.Blink->Flink = &SqList;

            InitializeListHead(&Socket->SqWorkQueue);

            RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

            //
            // Pump the queue
            //
            FOR_EACH_LIST_ENTRY(SQ_WORK_REQUEST, wr, SqList)
            {
                if (SupportsDeferredPosting)
                {
                    if (DeferredCount <= MAX_DEFERRED_SQ_REQUESTS && 
                        wr->ListEntry.Flink != &SqList)
                    {
                        Flags = NDK_OP_FLAG_DEFER;
                        DeferredCount++;
                    }
                    else
                    {
                        Flags = 0;
                        DeferredCount = 0;
                    }
                }

                status = RdmaPostSQRequest(Socket, wr, Flags);
                VERIFY_NTSUCCESS(status);
            }

            RDMA_LOCK_SOCKET(Socket, &LockHandle);
        } while (!IsListEmpty(&Socket->SqWorkQueue));

        Socket->SqPumping = FALSE;
    }

    RDMA_UNLOCK_SOCKET(Socket, &LockHandle);

exit:
    ExReleaseRundownProtectionEx(&Socket->DisconnectProtection, 1);

    if (!NT_SUCCESS(status))
    {
        nextWr = CONTAINING_RECORD(wr->ListEntry.Flink, SQ_WORK_REQUEST, ListEntry);
        wr->CompletionCallback(status, wr->CompletionContext);
        wr = nextWr;

        while (&wr->ListEntry != &SqList)
        {
            nextWr = CONTAINING_RECORD(wr->ListEntry.Flink, SQ_WORK_REQUEST, ListEntry);
            wr->CompletionCallback(STATUS_CONNECTION_DISCONNECTED, wr->CompletionContext);
            wr = nextWr;
        }

        RdmaQueueDisconnectWorkItem(Socket, FALSE);
    }
}

//
// This routine asynchronously posts a work request to a socket's SQ
//
// @param[in] Socket Pointer to the RDMA_SOCKET object that represents
// the socket.
//
// @param[in] wr work request to post to the sockets SQ
//
// @param[in] Flags The flags to pass along to the NDK wrapper
//
// @irql <= DISPATCH_LEVEL
//
_Use_decl_annotations_
static NTSTATUS
RdmaPostSQRequest(
RDMA_SOCKET *Socket,
SQ_WORK_REQUEST *wr,
ULONG Flags)
{
    NTSTATUS status;

    switch (wr->Type)
    {
    case SQSend:
        if (wr->Send.InvalidateRemoteMemoryRegion)
        {
            status = NdkSendAndInvalidate(Socket, wr, Flags);
        } else
        {
            status = NdkSend(Socket, wr, Flags);
        }
        break;

    case SQRead:
        status = NdkRead(Socket, wr, Flags);
        break;

    case SQWrite:
        status = NdkWrite(Socket, wr, Flags);
        break;

    case SQFastRegister:
        status = NdkFastRegister(Socket, wr, Flags | NDK_OP_FLAG_ALLOW_REMOTE_READ | NDK_OP_FLAG_ALLOW_REMOTE_WRITE);
        break;

    case SQInvalidate:
        status = NdkInvalidate(Socket, wr, Flags);
        break;

    default:
        status = STATUS_INVALID_PARAMETER;

        NT_ASSERT(FALSE);
    }

    return status;
}
