/*++
Copyright (c) Microsoft Corporation

Module Name:

    NdkWrapper.h

Abstract:

    Header file to functions that wrap NDK APIs

--*/

#pragma once

typedef struct _RDMA_SOCKET RDMA_SOCKET, *PRDMA_SOCKET;
typedef struct _LAM_BUFFER LAM_BUFFER, *PLAM_BUFFER;
typedef struct _SQ_WORK_REQUEST SQ_WORK_REQUEST, *PSQ_WORK_REQUEST;

//
// This context struct is used by the NDK routines to wait for async NDK API calls to 
// complete and then retrieve the result.
//
typedef struct _RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT
{
    //
    // Event that is signaled when the NDK API call completes
    //
    KEVENT Event;

    //
    // The status of the NDK API call
    //
    NTSTATUS Status;

    //
    // For NDK object creation APIs, this field will point to the created object if the
    // request was successful.
    //
    NDK_OBJECT_HEADER *NdkObject;
} RDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT, *PRDMA_NDK_FN_ASYNC_COMPLETION_CONTEXT;

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkInitialize();

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NdkDeInitialize();

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkOpenAdapter(
_In_ NET_IFINDEX InterfaceIndex,
_Outptr_ NDK_ADAPTER **Adapter
);

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkQueryAdapterInfo(
_In_ NDK_ADAPTER *Adapter,
_Out_ NDK_ADAPTER_INFO *AdapterInfo
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
NdkCloseAdapter(
_In_ _Frees_ptr_ NDK_ADAPTER *Adapter
);

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
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkArmCompletionQueue(
_In_ NDK_CQ *CompletionQueue,
_In_ ULONG TriggerType
);

_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseCompletionQueue(
_In_ _Frees_ptr_ NDK_CQ *CompletionQueue
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateProtectionDomain(
_In_ NDK_ADAPTER *Adapter,
_Outptr_ NDK_PD **ProtectionDomain
);

_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseProtectionDomain(
_In_ _Frees_ptr_ NDK_PD *ProtectionDomain
);

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
);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NdkGetRcqResults(
_Inout_ RDMA_SOCKET *Socket);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NdkGetRcqResultsEx(
_Inout_ RDMA_SOCKET *Socket);

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
NdkGetScqResults(
_Inout_ RDMA_SOCKET *Socket);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkFlushQueuePair(
_In_ NDK_QP *QueuePair);

_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseQueuePair(
_In_ _Frees_ptr_ NDK_QP *QueuePair
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateConnector(
_In_ NDK_ADAPTER *Adapter,
_Outptr_ NDK_CONNECTOR **Connector
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkGetConnectionData(
_In_ NDK_CONNECTOR *Connector,
_Out_opt_ PULONG InboundReadLimit,
_Out_opt_ PULONG OutboundReadLimit
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkConnect(
_In_ RDMA_SOCKET *ClientSocket);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCompleteConnect(
_In_ RDMA_SOCKET *ClientSocket);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkAccept(
_In_ RDMA_SOCKET *ServerSocket);

_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseConnector(
_In_ _Frees_ptr_ NDK_CONNECTOR *Connector);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkCloseConnectorAsyncNoCallback(
_In_ _Frees_ptr_ NDK_CONNECTOR *Connector
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateListener(
_In_ NDK_ADAPTER *Adapter,
_In_ NDK_FN_CONNECT_EVENT_CALLBACK ConnectEventHandler,
_In_opt_ PVOID Context,
_Outptr_ NDK_LISTENER **Listener
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkListen(
_In_ NDK_LISTENER *Listener,
_In_reads_bytes_(AddressCbLength) CONST PSOCKADDR Address,
_In_ ULONG AddressCbLength
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkPauseListener(
_In_ NDK_LISTENER *Listener);

_IRQL_requires_max_(APC_LEVEL)
VOID
NdkCloseListener(
_In_ _Frees_ptr_ NDK_LISTENER *Listener);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkCreateFastRegisterMemoryRegion(
_In_ NDK_PD *ProtectionDomain,
_Outptr_ NDK_MR **MemoryRegion
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkCloseMemoryRegionAsyncNoCallback(
_In_ _Frees_ptr_ NDK_MR *MemoryRegion
);

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkInitializeFastRegisterMemoryRegion(
_In_ NDK_MR *MemoryRegion,
_In_ ULONG AdapterPageCount,
_In_ BOOLEAN AllowRemoteAccess
);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkReceive(
_In_ RDMA_SOCKET *Socket,
_In_ LAM_BUFFER *LamBuffer);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkSend(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkSendAndInvalidate(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkRead(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkWrite(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkFastRegister(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
NdkInvalidate(
_In_ RDMA_SOCKET *Socket,
_In_ SQ_WORK_REQUEST *wr,
_In_ ULONG Flags);

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
);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NdkReleaseLam(
_In_ NDK_ADAPTER *Adapter,
_In_ _Frees_ptr_ NDK_LOGICAL_ADDRESS_MAPPING *Lam);
