/*++
Copyright (c) Microsoft Corporation

Module Name:

    WorkRequest.c

Abstract:

    Contains functions for working with SQ_WORK_REQUEST objects that get posted to the Scq

--*/

#include "precomp.h"

//
// This routine allocates an SQ work request that can later be posted to the send queue
//
// @param[in] Type The type of SQ work request to allocate
//
// @returns A pointer to a newly allocated SQ work request or NULL on failure
//
// @irql <= APC_LEVEL
//
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
_Success_(return != NULL)
SQ_WORK_REQUEST *
RdmaAllocateSqWorkRequest(
_In_ _Strict_type_match_ SQ_WORK_REQUEST_TYPE Type)
{
    SQ_WORK_REQUEST *wr;

    PAGED_CODE();

    wr = RdmaAllocateNpp(sizeof(*wr));
    if (wr) 
    {
        RtlZeroMemory(wr, sizeof(*wr));
        wr->Type = Type;
    }

    return wr;
}

//
// This routine frees a previously allocated SQ work request.  An SQ work request
// must not be freed before it gets completed
//
// @param[in] wr Pointer to the work request to free
//
// @irql <= DISPATCH_LEVEL
//
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
RdmaFreeSqWorkRequest(
_In_ _Frees_ptr_ SQ_WORK_REQUEST *wr)
{
    switch (wr->Type)
    {
    case SQSend:
        if (wr->Send.NdkSgl)
        {
            RdmaFreeNpp(wr->Send.NdkSgl);
            wr->Send.NdkSgl = NULL;
        }
        break;

    case SQWrite:
        if (wr->Write.NdkSgl)
        {
            RdmaFreeNpp(wr->Write.NdkSgl);
            wr->Write.NdkSgl = NULL;
        }
        break;

    case SQRead:
        if (wr->Read.NdkSgl)
        {
            RdmaFreeNpp(wr->Read.NdkSgl);
            wr->Read.NdkSgl = NULL;
        }
        break;

    case SQFastRegister:
    case SQInvalidate:
        // Nothing to clean up here
        break;

    default:
        NT_ASSERT(FALSE);
    }

    RdmaFreeNpp(wr);
}

//
// A generic completion callback for SQ work request completions.  It frees the work request,
// saves the status in the completion context, and signals an event.
//
// @param[in] Status The completion status of the work request
//
// @param[in] Context Pointer to a SQ_WORK_REQUEST_ASYNC_CONTEXT struct that was
// supplied by the caller when they queued the work request
//
// @irql <= DISPATCH_LEVEL
//
/* RDMA_COMPLETION_CALLBACK */
_Use_decl_annotations_
VOID
SqGenericCompletionCallback(
NTSTATUS Status,
VOID *Context)
{
    SQ_WORK_REQUEST_ASYNC_CONTEXT *ctx = (SQ_WORK_REQUEST_ASYNC_CONTEXT *)Context;

    NT_ASSERT(ctx);

    RdmaFreeSqWorkRequest(ctx->SqWorkRequest);

    ctx->Status = Status;
    KeSetEvent(&ctx->Event, 0, FALSE);
}
