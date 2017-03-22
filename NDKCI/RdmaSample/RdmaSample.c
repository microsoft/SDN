/*++
Copyright (c) Microsoft Corporation

Module Name:

    RdmaSample.c

Abstract:

    This file contains a sample upper level driver that uses the sample RDMA
    subsystem contained in the other files to create a client socket and a 
    listen socket.  
    
    This sample upper level driver assumes you have 2 RDMA capable NICs connected
    back to back on the same host.  The IfIndexes of these RNICs are hard-coded
    in this sample and should be changed as appropriate.
    
    This sample upper level driver connects the client socket to the listen socket
    using hard-coded IP addresses and port numbers and performs RDMA operations 
    (Send, Receive, Read, and Write) between the two sockets and checks that 
    the data is transferred successfully.

--*/

#include "precomp.h"

//
// Hard coded IfIndex of the RNIC to use for the client and listener
// TODO: Change these values to ones specific to your system
//
#define CLIENT_IF_INDEX         12
#define LISTEN_IF_INDEX         15

// Hard coded IP address for the client and listener
#define CLIENT_ADDRESS          L"10.0.0.1"
#define LISTEN_ADDRESS          L"10.0.0.2:54321"

// Hard code the amount of data is sent between them
#define SEND_DATA_LEN           (8 * 1024)  // 8K
#define LISTEN_DATA_LEN         (64 * 1024) // 64K

DRIVER_OBJECT *RdmaDriverObject = NULL;

RDMA_SOCKET_CONTEXT ClientSocket = { 0 };
RDMA_SOCKET_CONTEXT ServerSocket = { 0 };
RDMA_LISTEN_SOCKET_CONTEXT ListenSocket = { 0 };

SOCKADDR_IN ClientAddress = { 0 };
SOCKADDR_IN ListenAddress = { 0 };

//
// Main entry point of the sample RDMA driver.  It creates a client socket
// and a listen socket and exercises some basic RDMA operations between the
// two.
//
// @param[in] DriverObject Pointer to this samples Driver object.
//
// @param[in] RegistryPath Not used.
//
// @retval STATUS_SUCCESS
///
// @retval "An NTSTATUS error code" An error occurred.
//
// @irql <= PASSIVE_LEVEL
//
_Use_decl_annotations_
NTSTATUS
DriverEntry(
    DRIVER_OBJECT *DriverObject,
    UNICODE_STRING *RegistryPath)
{
    NTSTATUS status;
    RDMA_COMPLETION_CONTEXT ctx;
    LONG ret;
    ULONG i;

    MDL *ClientMdl = NULL, *ListenMdl = NULL;
    UCHAR *ClientBuffer = NULL, *ListenBuffer = NULL;
    RDMA_REGISTERED_BUFFER *RdmaListenBuffer = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    RdmaDriverObject = DriverObject;

    //
    // The sample doesn't handle any IRPs.  A real driver would fill this out with real functions
    //
    RtlZeroMemory(DriverObject->MajorFunction, (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof(PDRIVER_DISPATCH));
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DummyIrpHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DummyIrpHandler;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DummyIrpHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DummyIrpHandler;

    KeInitializeEvent(&ctx.CompletionEvent, NotificationEvent, FALSE);

    //
    // Set up ClientAddress and ListenAddress
    //
    ClientAddress.sin_family = AF_INET;
    ret = RtlIpv4StringToAddressExW(CLIENT_ADDRESS, TRUE, &ClientAddress.sin_addr, &ClientAddress.sin_port);
    if (ret != 0)
    {
        status = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    ListenAddress.sin_family = AF_INET;
    ret = RtlIpv4StringToAddressExW(LISTEN_ADDRESS, TRUE, &ListenAddress.sin_addr, &ListenAddress.sin_port);
    if (ret != 0)
    {
        status = STATUS_UNSUCCESSFUL;
        goto exit;
    }

    //
    // Initialize NDK subsystem
    //
    status = NdkInitialize();
    VERIFY_NTSUCCESS(status);

    //
    // Create a client socket
    //
    status = RdmaCreateClientSocket(
        CLIENT_IF_INDEX,
        DisconnectCallback,
        ReceiveCallback,
        &ClientSocket,
        &ClientSocket.RdmaSocket);
    VERIFY_NTSUCCESS(status);

    //
    // Create a listen socket
    //
    status = RdmaCreateListenSocket(
        LISTEN_IF_INDEX,
        AcceptCallback,
        &ListenSocket,
        &ListenSocket.RdmaListenSocket);
    VERIFY_NTSUCCESS(status);

    //
    // Start Listening
    //
    status = RdmaListen(
        ListenSocket.RdmaListenSocket, 
        (SOCKADDR *) &ListenAddress);
    VERIFY_NTSUCCESS(status);

    //
    // Connect client socket to our listen socket
    //
    status = RdmaConnect(
        ClientSocket.RdmaSocket,
        (SOCKADDR *) &ClientAddress,
        (SOCKADDR *) &ListenAddress);
    VERIFY_NTSUCCESS(status);

    //
    // Allocate some data to send
    //
    ClientBuffer = RdmaAllocateNpp(SEND_DATA_LEN);
    VERIFY_MALLOC(ClientBuffer);

    ClientMdl = IoAllocateMdl(ClientBuffer, SEND_DATA_LEN, FALSE, FALSE, NULL);
    VERIFY_MALLOC(ClientMdl);

    MmBuildMdlForNonPagedPool(ClientMdl);

    //
    // Fill data buffer with recognizable pattern
    //
    for (i = 0; i < SEND_DATA_LEN; i++)
    {
        ClientBuffer[i] = (UCHAR)(i % 256);
    }

    //
    // Send some data
    //
    status = RdmaSend(
        ClientSocket.RdmaSocket,
        ClientMdl,
        SEND_DATA_LEN,
        FALSE,
        0,
        &ctx,
        CompletionCallback);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.CompletionEvent, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    VERIFY_NTSUCCESS(status);

    IoFreeMdl(ClientMdl);
    RdmaFreeNpp(ClientBuffer);

    ClientMdl = NULL;
    ClientBuffer = NULL;

    //
    // Allocate some data to register as a buffer
    //
    ListenBuffer = RdmaAllocateNpp(LISTEN_DATA_LEN);
    VERIFY_MALLOC(ListenBuffer);

    ListenMdl = IoAllocateMdl(ListenBuffer, LISTEN_DATA_LEN, FALSE, FALSE, NULL);
    VERIFY_MALLOC(ListenMdl);

    MmBuildMdlForNonPagedPool(ListenMdl);

    //
    // Fill data buffer with random data
    //
    for (i = 0; i < LISTEN_DATA_LEN; i++)
    {
        ListenBuffer[i] = (i + 1) % 256;
    }

    //
    // Register the buffer so the client can RDMA read/write to it
    //
    status = RdmaRegisterBuffer(ServerSocket.RdmaSocket, ListenMdl, LISTEN_DATA_LEN, &RdmaListenBuffer);
    VERIFY_NTSUCCESS(status);

    //
    // Allocate enough space so we can RDMA read the server's buffer
    //
    ClientBuffer = RdmaAllocateNpp(LISTEN_DATA_LEN);
    VERIFY_MALLOC(ClientBuffer);

    ClientMdl = IoAllocateMdl(ClientBuffer, LISTEN_DATA_LEN, FALSE, FALSE, NULL);
    VERIFY_MALLOC(ClientMdl);

    MmBuildMdlForNonPagedPool(ClientMdl);

    //
    // RDMA read from the server's buffer into our client buffer
    //
    KeClearEvent(&ctx.CompletionEvent);
    status = RdmaRead(
        ClientSocket.RdmaSocket,
        ClientMdl,
        LISTEN_DATA_LEN,
        (UINT64) RdmaListenBuffer->BaseVirtualAddress,
        RdmaListenBuffer->RemoteToken,
        &ctx,
        CompletionCallback);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.CompletionEvent, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    VERIFY_NTSUCCESS(status);

    //
    // Check that the pattern matches
    //
    NT_ASSERT(RtlCompareMemory(ClientBuffer, ListenBuffer, LISTEN_DATA_LEN));

    //
    // Fill our client buffer with a different pattern
    //
    for (i = 0; i < LISTEN_DATA_LEN; i++)
    {
        ClientBuffer[i] = (i + 2) % 256;
    }

    //
    // RDMA write to the server's buffer from our client buffer
    //
    KeClearEvent(&ctx.CompletionEvent);
    status = RdmaWrite(
        ClientSocket.RdmaSocket,
        ClientMdl,
        LISTEN_DATA_LEN,
        (UINT64) RdmaListenBuffer->BaseVirtualAddress,
        RdmaListenBuffer->RemoteToken,
        &ctx,
        CompletionCallback);
    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&ctx.CompletionEvent, Executive, KernelMode, FALSE, 0);
        status = ctx.Status;
    }

    VERIFY_NTSUCCESS(status);

    //
    // Check that the pattern matches
    //
    NT_ASSERT(RtlCompareMemory(ClientBuffer, ListenBuffer, LISTEN_DATA_LEN));

exit:
    if (RdmaListenBuffer)
    {
        RdmaInvalidateRegisteredBuffer(ServerSocket.RdmaSocket, RdmaListenBuffer);
    }

    if (ListenBuffer)
    {
        RdmaFreeNpp(ListenBuffer);
    }

    if (ListenMdl)
    {
        IoFreeMdl(ListenMdl);
    }

    if (ClientBuffer)
    {
        RdmaFreeNpp(ClientBuffer);
    }

    if (ClientMdl)
    {
        IoFreeMdl(ClientMdl);
    }

    if (!NT_SUCCESS(status))
    {
        DriverUnload(DriverObject);
    }

    return status;
}

//
// This callback is passed to RDMA sample subsystem as the completion callback
// for all the operations the sample does.  Right now it just saves the status
// and signals an event.
//
// @param[in] Status The status of the completed operation.
//
// @param[in] Context Pointer to the completion context passed in when the
// operation was created
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
CompletionCallback(
_In_ NTSTATUS Status,
_In_opt_ VOID *Context)
{
    RDMA_COMPLETION_CONTEXT *ctx = (RDMA_COMPLETION_CONTEXT *)Context;

    NT_ASSERT(ctx);
    
    ctx->Status = Status;
    KeSetEvent(&ctx->CompletionEvent, 0, FALSE);
}

//
// This callback is invoked by the sample RDMA subsystem when the socket gets
// disconnected.  This sample doesn't do anything here.
//
// @param[in] Context Arbitrary context passed in to the RDMA sample subsystem
// upon socket creation
//
// @irql <= DISPATCH_LEVEL
//
_Use_decl_annotations_
VOID
DisconnectCallback(
    PVOID Context)
{
    RDMA_SOCKET_CONTEXT *Socket = (RDMA_SOCKET_CONTEXT *)Context;

    UNREFERENCED_PARAMETER(Socket);
}

//
// This callback is invoked by the sample RDMA subsystem when the socket peer
// sends data via RDMA send.
//
// @param[in] Context Arbitrary context passed in to the RDMA sample subsystem
// upon socket creation
//
// @param[in] Data The data that was sent by the peer
//
// @param[out] BytesReceived Number of bytes that the peer sent
//
// @param[out] PeerInvalidatedMemoryRegion Whether the peer also requested to
// invalidate a memory region (i.e. Send and Invalidate)
//
// @param[out] InvalidatedMemoryRegionToken The token of the memory region to
// invalidate.  Only valid if PeerInvalidatedMemoryRegion is TRUE
//
// @irql <= DISPATCH_LEVEL
//
_Use_decl_annotations_
VOID
ReceiveCallback(
    PVOID Context,
    UCHAR *Data,
    ULONG BytesReceived,
    BOOLEAN PeerInvalidatedMemoryRegion,
    UINT32 InvalidatedMemoryRegionToken)
{
    RDMA_SOCKET_CONTEXT *Socket = (RDMA_SOCKET_CONTEXT *)Context;
    USHORT i;

    UNREFERENCED_PARAMETER(InvalidatedMemoryRegionToken);
    UNREFERENCED_PARAMETER(PeerInvalidatedMemoryRegion);
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Data);
    //
    // This sample only sends from client to server
    //
    NT_ASSERT(Socket == &ServerSocket);

    //
    // Check to make sure we got back what we sent
    //
    NT_ASSERT(PeerInvalidatedMemoryRegion == FALSE);
    NT_ASSERT(InvalidatedMemoryRegionToken == 0);
    NT_ASSERT(BytesReceived == SEND_DATA_LEN);

    for (i = 0; i < BytesReceived; i++)
    {
        NT_ASSERT(Data[i] == (UCHAR)(i % 256));
    }
}

//
// This callback is invoked by the sample RDMA subsystem when an incoming connect
// request comes on a listener socket.  We can accept or reject the connection
//
// @param[in] Context Arbitrary context pointer that passed in upon creation of the
// listen socket on which this connection is coming in
//
// @param[in] Socket The server socket that was created by the sample subsystem for
// the incoming connection
//
// @param[out] DisconnectEventCallback Pointer to a pointer that will be filled out
// with a function for the RDMA sample subsystem to invoke when the socket gets
// disconnected
//
// @param[out] ReceiveEventCallback Pointer to a pointer that will be filled out
// with a function for the RDMA sample subsystem to invoke when the socket receives
// data
//
// @param[out] EventCallbackContext Context to pass back the 2 callback functions above
//
// @retval STATUS_SUCCESS to accept the incoming connection, or an error
// code to reject it
//
// @irql <= DISPATCH_LEVEL
//
_Use_decl_annotations_
NTSTATUS
AcceptCallback(
PVOID Context,
RDMA_SOCKET *Socket,
RDMA_DISCONNECT_EVENT_CALLBACK **DisconnectEventCallback,
RDMA_RECEIVE_EVENT_CALLBACK **ReceiveEventCallback,
VOID **EventCallbackContext
)
{
    NT_ASSERT(Context == &ListenSocket);
    UNREFERENCED_PARAMETER(Context);
    // In this sample we only allow 1 client
    if (InterlockedCompareExchangePointer(&ServerSocket.RdmaSocket, Socket, NULL) == NULL)
    {
        *DisconnectEventCallback = DisconnectCallback;
        *ReceiveEventCallback = ReceiveCallback;
        *EventCallbackContext = &ServerSocket;
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

//
// Called by NT when the driver gets unloaded.  Need to clean up all allocated
// resources
//
// @param[in] DriverObject Not used.
//
// @irql <= PASSIVE_LEVEL
//
_Use_decl_annotations_
VOID DriverUnload(
    DRIVER_OBJECT *DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (ClientSocket.RdmaSocket)
    {
        RdmaCloseSocket(ClientSocket.RdmaSocket);
        ClientSocket.RdmaSocket = NULL;
    }

    if (ServerSocket.RdmaSocket)
    {
        RdmaCloseSocket(ServerSocket.RdmaSocket);
        ServerSocket.RdmaSocket = NULL;
    }

    if (ListenSocket.RdmaListenSocket)
    {
        RdmaCloseListenSocket(ListenSocket.RdmaListenSocket);
        ListenSocket.RdmaListenSocket = NULL;
    }

    NdkDeInitialize();
}

//
// Dummy routine that does nothing accept complete all IRPs with a success code
//
// @param[in] DeviceObject Not used.
//
// @param[in,out] Irp Pointer to the recived Irp
//
// @retval STATUS_SUCCESS This function always succeeds since we don't do
// any IRP processing
//
// @irql <= PASSIVE_LEVEL
//
_Use_decl_annotations_
NTSTATUS
DummyIrpHandler(
    PDEVICE_OBJECT           DeviceObject,
    PIRP                     Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
