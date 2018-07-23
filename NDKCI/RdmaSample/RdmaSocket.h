/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaSocket.h

Abstract:

    Header file for the sample RDMA subsystem which provides socket like semantics
    on top of the NDKPI and functions for manipulating RDMA_SOCKET objects.

--*/

#pragma once

#define CQ_INTERRUPT_MODERATION_INTERVAL    20  // us
#define CQ_INTERRUPT_MODERATION_COUNT       MAXULONG

#define RECEIVE_MAX_BATCH_SIZE              32
#define RECEIVE_MAX_BUFFER_SIZE             (64 * 1024)     // 64K

#define SCQ_BATCH_SIZE                      128

#define MAX_NUM_REGISTERED_BUFFERS          512

//
// Max number of deferred requests to post to the SQ before posting a non-deferred one
//
#define MAX_DEFERRED_SQ_REQUESTS            15

typedef struct _RDMA_SOCKET RDMA_SOCKET, *PRDMA_SOCKET;
typedef struct _RDMA_LISTEN_SOCKET RDMA_LISTEN_SOCKET, *PRDMA_LISTEN_SOCKET;

//
// Callback invoked when an RDMA operation completes
//
// @param[in] Status Indicates success/failure of the operation.
//
// @param[in] Context An optional pointer to the context for the operation that has 
// completed. This pointer was provided to the sample RDMA subsystem when it called 
// the API that initiated the operation.
//
// @irql <= DISPATCH_LEVEL.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RDMA_COMPLETION_CALLBACK(
_In_ NTSTATUS Status,
_In_opt_ PVOID Context
);

//
// Notifies an upper level driver using the sample RDMA subsystem that data has been 
// received on an RDMA socket.
//
// The data buffer is owned by the sample RDMA subsystem and will be recycled after the
// receive event callback function returns. The upper level driver must copy the data
// into its own buffer if it needs to access the received data after the receive event
// callback function returns.
//
// @param[in] Context An optional pointer to the socket context for the socket on which the
// data was received. The upper level driver provided this pointer to the sample RDMA
// subsystem when it created the socket.
//
// @param[in] Data A pointer to a buffer containing the received data.
//
// @param[in] BytesReceived The number of bytes of received data.
//
// @param[in] PeerInvalidatedMemoryRegion When not FALSE, indicates that the peer
// remotely invalidated a memory region.
//
// @param[in] InvalidatedMemoryRegionToken The token of the memory region that the
// peer remotely invalidated. The token is only valid when PeerInvalidatedMemoryRegion
// is not FALSE.
//
// @irql <= DISPATCH_LEVEL.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RDMA_RECEIVE_EVENT_CALLBACK(
_In_ PVOID Context,
_In_reads_bytes_(BytesReceived) UCHAR *Data,
_In_ ULONG BytesReceived,
_In_ BOOLEAN PeerInvalidatedMemoryRegion,
_In_ UINT32 InvalidatedMemoryRegionToken
);

//
// Creates a type name for a pointer to a RDMA_RECEIVE_EVENT_CALLBACK function.
//
typedef RDMA_RECEIVE_EVENT_CALLBACK *PRDMA_RECEIVE_EVENT_CALLBACK;

//
// Notifies an upper level driver that a socket has been disconnected.
//
// @param[in] Context An optional pointer to the socket context for the socket
// that has been disconnected. The upper level driver provided this when it 
// created the socket.
//
// @irql <= DISPATCH_LEVEL.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
typedef
VOID
RDMA_DISCONNECT_EVENT_CALLBACK(
_In_opt_ PVOID Context
);

//
// Creates a type name for a pointer to a RDMA_DISCONNECT_EVENT_CALLBACK function.
//
typedef RDMA_DISCONNECT_EVENT_CALLBACK *PRDMA_DISCONNECT_EVENT_CALLBACK;

//
// Notifies an upper level driver that a connection has been accepted on a listen socket
//
// @param[in] Context Context An optional pointer to the listen socket context of the listen
// socket on which the connection request arrived. The upper level driver provided this
// when it created the listen socket.
//
// @param[in] Socket A pointer to the RDMA_SOCKET object that represents the socket that was
// created for the connection.
//
// @param[out] DisconnectEventCallback A pointer to a disconnect event callback function pointer
// that the upper level driver sets to the address of the function that will be invoked when 
// the socket has been disconnected.
//
// @param[out] ReceiveEventCallback A pointer to a receive event callback function pointer that
// that the upper level driver sets to the address of the function that will be invoked when
// data has been received on the socket.
//
// @param[out] EventCallbackContext A pointer to a socket context pointer that the upper
// level driver may set to an arbitrary value. This value will be passed back to the
// upper level driver via the Context argument of the disconnect and receive callbacks.
//
// @retval STATUS_SUCCESS The upper level driver accepted the incoming connection and has
// taken ownership of the connection's socket.
//
// @retval "An NTSTATUS error code" The upper level driver rejected the incoming connection.
// The sample RDMA subsystem will close the socket.
//
// @irql <= DISPATCH_LEVEL.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
RDMA_ACCEPT_EVENT_CALLBACK(
_In_opt_ PVOID Context,
_In_ RDMA_SOCKET *Socket,
_Deref_out_ RDMA_DISCONNECT_EVENT_CALLBACK **DisconnectEventCallback,
_Deref_out_ RDMA_RECEIVE_EVENT_CALLBACK **ReceiveEventCallback,
_Deref_out_ VOID **EventCallbackContext
);

//
// Creates a type name for a pointer to a RDMA_ACCEPT_EVENT_CALLBACK function.
//
typedef RDMA_ACCEPT_EVENT_CALLBACK *PRDMA_ACCEPT_EVENT_CALLBACK;

//
// Stores information about an incoming NDK-level connect request
//
typedef struct _RDMA_NDK_CONNECT_REQUEST
{
    //
    // A pointer to the RDMA_LISTEN_SOCKET object that represents the listen socket
    // on which the incoming connection request was received.
    //
    RDMA_LISTEN_SOCKET *Socket;

    //
    // A pointer to the NDK_CONNECTOR object that the NDK subsystem created to represent the
    // incoming connection.
    //
    NDK_CONNECTOR *NdkConnector;

    //
    // Stores the address/port of the peer that is attempting to connect
    //
    SOCKADDR_STORAGE RemoteAddress;
} RDMA_NDK_CONNECT_REQUEST, *PRDMA_NDK_CONNECT_REQUEST;

//
// Defines the two socket types
//
typedef enum _RDMA_SOCKET_TYPE
{
    //
    // A client socket is one that is created via a call to RdmaCreateClientSocket
    //
    RdmaClientSocket,

    //
    // A server socket is one that is created as a response to a connection
    // request being received by a listen socket.
    //
    RdmaServerSocket
} RDMA_SOCKET_TYPE, *PRDMA_SOCKET_TYPE;

//
// Specifies the state of a socket's connection
//
typedef enum _RDMA_SOCKET_STATE
{
    //
    // The socket is in the process of being initialized. This is the state the socket is in
    // until RdmaCreateClientSocket/RdmaCreateServerSocket completes successfully.
    //
    // No RDMA operations may be posted to the socket in this state.
    //
    // Transitions to RdmaSocketInitialized on successful socket initialization, or 
    // RdmaSocketClosing on failure to initialize.
    //
    RdmaSocketInitializing,

    //
    // The socket is initialized and ready to connect. This is the state of all sockets
    // after a successful call to RdmaCreateClientSocket/RdmaCreateServerSocket.
    //
    // No RDMA operations may be posted to the socket in this state.
    // 
    // Transitions to RdmaSocketConnecting when RdmaConnect is called.
    //
    RdmaSocketInitialized,

    //
    // The socket is in the process of connecting to a remote peer.
    //
    // For client type sockets this state encompasses the calls to NdkConnect and
    // NdkCompleteConnect.  For server type sockets this state encompasses the 
    // calls to NdkAccept.
    // 
    // No RDMA operations may be posted to the socket in this state.
    //
    // Transitions to RdmaSocketConnected upon successfull completion of the
    // connection, or RdmaSocketDisconnecting upon failure.
    //
    RdmaSocketConnecting,

    //
    // The connection has been established.  RDMA operations (Read, Write, Send, etc.)
    // may now be posted on the socket.
    //
    // Transitions to RdmaSocketDisconnecting when the socket is disconnected
    // or closed.
    //
    RdmaSocketConnected,

    //
    // The socket is in the process of disconnecting and is waiting for the socket's
    // NDK connector to finish closing and for the last complete disconnect protection
    // reference to be released.
    //
    // No RDMA operations may be posted to the socket in this state.
    //
    RdmaSocketDisconnecting,

    //
    // The socket's NDK connector has finished closing and the last complete disconnect
    // protection reference has been released. The socket's disconnect callback
    // has been be invoked, and all work requests have been flushed.
    //
    // No RDMA operations may be posted to the socket in this state.
    //
    // Transitions to RdmaSocketClosing when RdmaCloseSocket is called.
    //
    RdmaSocketDisconnected,

    //
    // The socket is closing and all associated resources including the socket itself will
    // soon be freed.
    //
    RdmaSocketClosing
} RDMA_SOCKET_STATE, *PRDMA_SOCKET_STATE;

//
// This is the main object that an upper level driver will work with and supplies
// represents an object that provides socket like semantics on top of the NDKPI
//
typedef struct _RDMA_SOCKET
{
    //
    // A pointer to the RDMA_ADAPTER object that represents the RDMA adapter with 
    // which this socket is associated.
    //
    RDMA_ADAPTER *RdmaAdapter;

    //
    // Indicates whether this is a client or server socket.
    //
    RDMA_SOCKET_TYPE Type;

    //
    // A pointer to the NDK_PD object that represents the socket's RDMA 
    // protection domain
    //
    NDK_PD *NdkPd;

    //
    // Stores the address and port of the connection's local endpoint
    //
    PSOCKADDR LocalAddress;

    //
    // Stores the address and port of the connection's remote endpoint
    //
    PSOCKADDR RemoteAddress;

    //
    // A pointer to the NDK_CONNECTOR object that represents the socket's RDMA connector.
    //
    // All DMA operations for work requests that have been queued to the QP are guaranteed
    // to have completed when the connector finishes closing.
    //
    NDK_CONNECTOR *NdkConnector;

    //
    // A pointer to the NDK_CQ object that represents the socket's receive completion queue
    //
    NDK_CQ *NdkRcq;

    //
    // A pointer to the NDK_CQ object that represents the socket's send completion queue
    //
    NDK_CQ *NdkScq;

    //
    // A pointer to the NDK_QP object that represents the socket's RDMA queue pair - the
    // receive queue (RQ) and send queue (SQ).
    //
    NDK_QP *NdkQp;

    //
    // The disconnect event callback routine that was specified by the upper level 
    // driver when it created the socket (client type sockets) or accepted the socket 
    // (server type sockets). This callback is invoked to notify the upper level 
    // driver that the socket has been disconnected.
    //
    RDMA_DISCONNECT_EVENT_CALLBACK *DisconnectEventCallback;

    //
    // The receive event callback routine that was specified by the upper level 
    // driver when it created the socket. This callback is invoked to notify the 
    // upper level driver that data has been received on the socket.
    //
    RDMA_RECEIVE_EVENT_CALLBACK *ReceiveEventCallback;

    //
    // An arbitrary context value that was specified by the upper level driver 
    // when it created the socket. This value is passed back to the upper level
    // driver via the context argument of the receive event and disconnect event 
    // callbacks.
    //
    VOID *EventCallbackContext;

    //
    // Guards Disconnect from proceeding
    //
    EX_RUNDOWN_REF DisconnectProtection;

    //
    // Guards against the socket being closed and freed
    //
    EX_RUNDOWN_REF CloseProtection;

    //
    // Work item used to perform disconnection
    //
    PIO_WORKITEM DisconnectWorkItem;

    //
    // Serialize access to a socket's state, SQ, and memory region lists
    //
    KSPIN_LOCK Lock;
    
    //
    // The state of the socket's connection
    //
    _Write_guarded_by_(Lock)
    RDMA_SOCKET_STATE State;

    //
    // Event set when a socket transitions into the RdmaSocketDisconnected state
    //
    _Write_guarded_by_(Lock)
    KEVENT SocketDisconnected;

    //
    // List of requests to post to the initiator queue
    //
    _Guarded_by_(Lock)
    LIST_ENTRY SqWorkQueue;

    //
    // List of memory regions initialized for fast registration that are
    // available to used in a call to RdmaRegisterBuffer
    //
    _Guarded_by_(Lock)
    LIST_ENTRY FreeMemoryRegions;

    //
    // List of memory regions that have already been fast registered
    //
    _Guarded_by_(Lock)
    LIST_ENTRY RegisteredMemoryRegions;

    //
    // Whether another thread is currently pumping the SqWorkQueue
    //
    _Guarded_by_(Lock)
    BOOLEAN SqPumping;

    //
    // Whether to invoke the upper level drivers disconnect callback
    //
    BOOLEAN DisconnectCallbackEnabled;

    //
    // A privileged memory region token that allows the adapter to access local physical memory
    // without registration.
    //
    UINT32 PrivilegedMrToken;

    //
    // The depth of the socket's Receive Queue (RQ) and Receive Completion Queue (RCQ)
    //
    USHORT NdkRqDepth;

    //
    // The depth of the socket's Send Queue (SQ) and Send Completion Queue (SCQ)
    //
    USHORT NdkSqDepth;

    //
    // The maximum number of outstanding receives to post to the RCQ.  Must be <= NdkRqDepth
    //
    USHORT MaxNumReceives;

    //
    // Maximum number of pages that a fast register memory region can map
    //
    USHORT MaxFrmrPageCount;

    //
    // Maximum number of in-progress incoming read operations on this socket
    //
    USHORT MaxInboundReadLimit;

    //
    // Maximum number of in-progress outgoing read operations on this socket
    //
    USHORT MaxOutboundReadLimit;

    //
    // Maximum number of SGEs that can be specified in a single receive
    //
    USHORT MaxReceiveSges;

    //
    // Maximum number of SGEs that can be specified in a single SQ work request 
    // (excluding reads)
    //
    USHORT MaxSqSges;

    //
    // Maximum number of SGEs that can be specified in a single read work request
    //
    USHORT MaxReadSges;

    //
    // Maximum number of bytes that can be specified in a single receive
    //
    ULONG MaxReceiveCbSize;
    
    //
    // Maximum number of bytes that can be specified in a single SQ work request 
    // (excluding reads)
    //
    ULONG MaxSqCbSize;

    //
    // Maximum number of bytes that can be specified in a single RDMA read work request
    //
    ULONG MaxReadCbSize;

    //
    // Pointer to an array that stores completions that are dequeued from the RCQ for
    // processing.  
    //
    // For NDK providers that do not support remote invalidation, this is an array 
    // of NDK_RESULT structures.
    //
    // For NDK providers that support remote invalidation, this is an array of 
    // NDK_RESULT_EX structures.
    //
    union
    {
        NDK_RESULT *NdkRcqResult;
        NDK_RESULT_EX *NdkRcqResultEx;
    };

    //
    // Pointer to an array that stores completions that are dequeued from the SCQ 
    // for processing
    //
    NDK_RESULT *NdkScqResult;

} RDMA_SOCKET, *PRDMA_SOCKET;

//
// The object that represents an RDMA listen socket that can be used to listen for
// incoming connections.
//
typedef struct _RDMA_LISTEN_SOCKET
{
    //
    // Pointer to the NDK_LISTENER object that represents the NDKPI listening endpoint
    //
    NDK_LISTENER *NdkListener;

    //
    // The accept event callback context value.
    //
    // The upper level driver supplied this value when the listen socket was created. The
    // context value is passed back to the upper level driver via the Context argument
    // of the accept event callback function.
    //
    PVOID AcceptEventCallbackContext;

    //
    // Pointer to the accept event callback function.
    //
    // The event callback function that the RDMA sample subsystem will invoke to notify the 
    // upper level driver that a connection has been accepted. The upper level driver 
    // supplied this callback function when the listen socket was created.
    //
    RDMA_ACCEPT_EVENT_CALLBACK *AcceptEventCallback;

    //
    // Pointer to the RDMA_ADAPTER object of the adapter that is associated with this listen
    // socket.
    //
    RDMA_ADAPTER *RdmaAdapter;

    //
    // Pointer to the SOCKADDR that stores the address/port on which the listen socket is
    // listening.
    //
    SOCKADDR *ListenAddr;
} RDMA_LISTEN_SOCKET, *PRDMA_LISTEN_SOCKET;

/* NDK_FN_CONNECT_EVENT_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
RdmaNdkConnectEventCallback(
_In_opt_ PVOID Context,
_In_ NDK_CONNECTOR *NdkConnector);

/* NDK_FN_CQ_NOTIFICATION_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkScqNotificationEventCallback(
_In_opt_ PVOID CqNotificationContext,
_In_ NTSTATUS CqStatus);

/* NDK_FN_CQ_NOTIFICATION_CALLBACK */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
NdkRcqNotificationEventCallback(
_In_opt_ PVOID CqNotificationContext,
_In_ NTSTATUS CqStatus);

static IO_WORKITEM_ROUTINE_EX RdmaNdkConnectEventCallbackWorkItem;
static IO_WORKITEM_ROUTINE_EX RdmaDisconnectWorkItem;

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static NTSTATUS
RdmaCreateSocket(
_In_ IF_INDEX AdapterIfIndex,
_Outptr_ RDMA_SOCKET **oSocket
);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaCreateClientSocket(
_In_ IF_INDEX AdapterIfIndex,
_In_ RDMA_DISCONNECT_EVENT_CALLBACK *DisconnectEventCallback,
_In_ RDMA_RECEIVE_EVENT_CALLBACK *ReceiveEventCallback,
_In_opt_ PVOID EventCallbackContext,
_Outptr_ RDMA_SOCKET **oSocket);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
static NTSTATUS
RdmaCreateServerSocket(
_In_ IF_INDEX AdapterIfIndex,
_In_ NDK_CONNECTOR *NdkConnector,
_In_ PSOCKADDR RemoteAddress,
_In_ RDMA_LISTEN_SOCKET *ListenSocket,
_Outptr_ RDMA_SOCKET **oSocket);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaConnect(
_Inout_ RDMA_SOCKET *Socket,
_In_ CONST SOCKADDR *LocalAddress,
_In_ CONST SOCKADDR *RemoteAddress);

_IRQL_requires_max_(APC_LEVEL)
VOID
RdmaDisconnect(
_In_ RDMA_SOCKET *Socket);

_Requires_lock_not_held_(Socket->Lock)
_When_(Wait, _IRQL_requires_max_(APC_LEVEL))
_When_(!Wait, _IRQL_requires_max_(DISPATCH_LEVEL))
VOID
RdmaQueueDisconnectWorkItem(
_Inout_ RDMA_SOCKET *Socket,
_In_ BOOLEAN Wait);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
RdmaCloseSocket(
_In_ _Frees_ptr_ RDMA_SOCKET *Socket);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaCreateListenSocket(
_In_ NET_IFINDEX AdapterInterfaceIndex,
_In_ RDMA_ACCEPT_EVENT_CALLBACK *AcceptEventCallback,
_In_opt_ PVOID AcceptEventCallbackContext,
_Outptr_ RDMA_LISTEN_SOCKET **oListenSocket);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
RdmaListen(
_Inout_ RDMA_LISTEN_SOCKET *ListenSocket,
_In_ CONST PSOCKADDR ListenAddress);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
RdmaCloseListenSocket(
_In_ _Frees_ptr_ RDMA_LISTEN_SOCKET *Socket);

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
_In_ RDMA_COMPLETION_CALLBACK *CompletionCallback);

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
_In_ RDMA_COMPLETION_CALLBACK *CompletionCallback);

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
_In_ RDMA_COMPLETION_CALLBACK *CompletionCallback);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaQueueSQWrs(
_Inout_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *WrList);

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
RdmaAllocateAndPostReceives(
_Inout_ RDMA_SOCKET *Socket);

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
RdmaPostSQRequest(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);
