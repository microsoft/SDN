/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaSample.h

Abstract:

    Header file for the RDMA sample upper level driver

--*/

#pragma once

//
// Tag this sample will use when allocating pool
//
#define RDMA_SAMPLE_TAG 'amdR'

//
// Context that this sample associates with an RDMA_SOCKET object
// Right now it only stores a pointer to the underlying object
//
typedef struct _RDMA_SOCKET_CONTEXT
{
    RDMA_SOCKET *RdmaSocket;
} RDMA_SOCKET_CONTEXT, *PRDMA_SOCKET_CONTEXT;

//
// Context that this sample associates with an RDMA_LISTEN_SOCKET object
// Right now it only stores a pointer to the underlying object
//
typedef struct _RDMA_LISTEN_SOCKET_CONTEXT
{
    RDMA_LISTEN_SOCKET *RdmaListenSocket;
} RDMA_LISTEN_SOCKET_CONTEXT, *PRDMA_LISTEN_SOCKET_CONTEXT;

//
// Context used to pass to CompletionCallback when an RDMA operation completes.
//
typedef struct _RDMA_COMPLETION_CONTEXT
{
    //
    // Event to set to signal any waiting threads that the operation completed
    //
    KEVENT CompletionEvent;

    //
    // The completion status of the event is saved here
    //
    NTSTATUS Status;
} RDMA_COMPLETION_CONTEXT, *PRDMA_COMPLETION_CONTEXT;

extern DRIVER_OBJECT *RdmaDriverObject;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DummyIrpHandler;

RDMA_DISCONNECT_EVENT_CALLBACK DisconnectCallback;
RDMA_RECEIVE_EVENT_CALLBACK ReceiveCallback;
RDMA_ACCEPT_EVENT_CALLBACK AcceptCallback;

RDMA_COMPLETION_CALLBACK CompletionCallback;
