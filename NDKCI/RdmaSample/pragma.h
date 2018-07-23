/*++
Copyright (c) Microsoft Corporation

Module Name:

    pragma.h

Abstract:

    Header file for paging out the parts of the driver that don't need to be
    pinned in memory

--*/

#pragma once

#pragma alloc_text(PAGE, NdkInitialize)
#pragma alloc_text(PAGE, NdkDeInitialize)
#pragma alloc_text(PAGE, NdkOpenAdapter)
#pragma alloc_text(PAGE, NdkCloseAdapter)
#pragma alloc_text(PAGE, NdkQueryAdapterInfo)
#pragma alloc_text(PAGE, NdkCreateCompletionQueue)
#pragma alloc_text(PAGE, NdkCloseCompletionQueue)
#pragma alloc_text(PAGE, NdkCreateProtectionDomain)
#pragma alloc_text(PAGE, NdkCloseProtectionDomain)
#pragma alloc_text(PAGE, NdkCreateQueuePair)
#pragma alloc_text(PAGE, NdkCloseQueuePair)
#pragma alloc_text(PAGE, NdkCreateConnector)
#pragma alloc_text(PAGE, NdkCloseConnector)
#pragma alloc_text(PAGE, NdkCreateListener)
#pragma alloc_text(PAGE, NdkListen)
#pragma alloc_text(PAGE, NdkCloseListener)
#pragma alloc_text(PAGE, NdkAccept)
#pragma alloc_text(PAGE, NdkConnect)
#pragma alloc_text(PAGE, NdkCompleteConnect)
#pragma alloc_text(PAGE, NdkCreateFastRegisterMemoryRegion)
#pragma alloc_text(PAGE, NdkInitializeFastRegisterMemoryRegion)
#pragma alloc_text(PAGE, NdkBuildLam)

#pragma alloc_text(PAGE, RdmaAllocateLam)
#pragma alloc_text(PAGE, RdmaAllocateLamChain)
#pragma alloc_text(PAGE, RdmaBuildSglChainForLamChain)
#pragma alloc_text(PAGE, RdmaAllocateLamBuffer)

#pragma alloc_text(PAGE, RdmaOpenAdapter)
#pragma alloc_text(PAGE, RdmaCloseAdapter)

#pragma alloc_text(PAGE, RdmaAllocateSqWorkRequest)

#pragma alloc_text(PAGE, RdmaAllocateOperation)
#pragma alloc_text(PAGE, RdmaBuildSqWorkRequestHelper)
#pragma alloc_text(PAGE, RdmaBuildSqWorkRequests)
#pragma alloc_text(PAGE, RdmaBuildReadWorkRequests)
#pragma alloc_text(PAGE, RdmaBuildWriteWorkRequests)
#pragma alloc_text(PAGE, RdmaBuildSendWorkRequests)

#pragma alloc_text(PAGE, RdmaAllocateRegisteredBuffer)
#pragma alloc_text(PAGE, RdmaInvalidateRegisteredBuffer)

#pragma alloc_text(PAGE, RdmaAllocateAndPostReceives)
#pragma alloc_text(PAGE, RdmaCreateSocket)
#pragma alloc_text(PAGE, RdmaCreateServerSocket)
#pragma alloc_text(PAGE, RdmaCreateClientSocket)
#pragma alloc_text(PAGE, RdmaDisconnect)
#pragma alloc_text(PAGE, RdmaCreateListenSocket)
#pragma alloc_text(PAGE, RdmaListen)
#pragma alloc_text(PAGE, RdmaCloseListenSocket)
#pragma alloc_text(PAGE, RdmaSend)
#pragma alloc_text(PAGE, RdmaWrite)
#pragma alloc_text(PAGE, RdmaRead)
