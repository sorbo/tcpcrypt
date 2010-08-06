#ifndef __PTEXTEND__H
#define __PTEXTEND__H

// Copyright And Configuration Management ----------------------------------
//
//          Header for PassThru Driver Extensions Module - ptextend.h
//
//                  Companion Sample Code for the Article
//
//        "Extending the Microsoft PassThru NDIS Intermediate Driver"
//
//    Copyright (c) 2003 Printing Communications Associates, Inc. (PCAUSA)
//                          http://www.pcausa.com
//
// The right to use this code in your own derivative works is granted so long
// as 1.) your own derivative works include significant modifications of your
// own, 2.) you retain the above copyright notices and this paragraph in its
// entirety within sources derived from this code.
// This product includes software developed by PCAUSA. The name of PCAUSA
// may not be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
//
// End ---------------------------------------------------------------------

//
// MACRO Borrowed From NDISPROT...
//
#define NDIS_STATUS_TO_NT_STATUS(_NdisStatus, _pNtStatus)                           \
{                                                                                   \
    /*                                                                              \
     *  The following NDIS status codes map directly to NT status codes.            \
     */                                                                             \
    if (((NDIS_STATUS_SUCCESS == (_NdisStatus)) ||                                  \
        (NDIS_STATUS_PENDING == (_NdisStatus)) ||                                   \
        (NDIS_STATUS_BUFFER_OVERFLOW == (_NdisStatus)) ||                           \
        (NDIS_STATUS_FAILURE == (_NdisStatus)) ||                                   \
        (NDIS_STATUS_RESOURCES == (_NdisStatus)) ||                                 \
        (NDIS_STATUS_NOT_SUPPORTED == (_NdisStatus))))                              \
    {                                                                               \
        *(_pNtStatus) = (NTSTATUS)(_NdisStatus);                                    \
    }                                                                               \
    else if (NDIS_STATUS_BUFFER_TOO_SHORT == (_NdisStatus))                         \
    {                                                                               \
        /*                                                                          \
         *  The above NDIS status codes require a little special casing.            \
         */                                                                         \
        *(_pNtStatus) = STATUS_BUFFER_TOO_SMALL;                                    \
    }                                                                               \
    else if (NDIS_STATUS_INVALID_LENGTH == (_NdisStatus))                           \
    {                                                                               \
        *(_pNtStatus) = STATUS_INVALID_BUFFER_SIZE;                                 \
    }                                                                               \
    else if (NDIS_STATUS_INVALID_DATA == (_NdisStatus))                             \
    {                                                                               \
        *(_pNtStatus) = STATUS_INVALID_PARAMETER;                                   \
    }                                                                               \
    else if (NDIS_STATUS_ADAPTER_NOT_FOUND == (_NdisStatus))                        \
    {                                                                               \
        *(_pNtStatus) = STATUS_NO_MORE_ENTRIES;                                     \
    }                                                                               \
    else if (NDIS_STATUS_ADAPTER_NOT_READY == (_NdisStatus))                        \
    {                                                                               \
        *(_pNtStatus) = STATUS_DEVICE_NOT_READY;                                    \
    }                                                                               \
    else                                                                            \
    {                                                                               \
        *(_pNtStatus) = STATUS_UNSUCCESSFUL;                                        \
    }                                                                               \
}


typedef
struct _NDIS_REQUEST_EX NDIS_REQUEST_EX, *PNDIS_REQUEST_EX;

typedef
VOID
(*LOCAL_REQUEST_COMPLETE_HANDLER)(
   IN  PADAPT              pAdapt,
   IN  PNDIS_REQUEST_EX    pLocalRequest,
   IN  NDIS_STATUS         Status
   );

typedef
struct _NDIS_REQUEST_EX
{
   NDIS_REQUEST                     Request;
   LOCAL_REQUEST_COMPLETE_HANDLER   RequestCompleteHandler;
   PVOID                            RequestContext;
   NDIS_STATUS                      RequestStatus;
   NDIS_EVENT                       RequestEvent;
}
   NDIS_REQUEST_EX, *PNDIS_REQUEST_EX;


VOID
PtRefAdapter( PADAPT pAdapt );

VOID
PtDerefAdapter( PADAPT pAdapt );

PADAPT
PtLookupAdapterByName(
   IN PUCHAR   pNameBuffer,
   IN USHORT   NameBufferLength,
   IN BOOLEAN  bUseVirtualName
   );

typedef
struct _OPEN_CONTEXT
{
   ULONG                RefCount;
   NDIS_SPIN_LOCK       Lock;
   BOOLEAN              bAdapterClosed;
   PADAPT               pAdapt;

   NDIS_REQUEST_EX      LocalRequest;

// BEGIN_PTEX_FILTER
    //
    // Per-Open-Handle Filter-Specific Area
    //
    ULONG               FilterReserved[16];
// END_PTEX_FILTER

}
   OPEN_CONTEXT, *POPEN_CONTEXT;


VOID
DevRefOpenContext( POPEN_CONTEXT pOpenContext );

VOID
DevDerefOpenContext( POPEN_CONTEXT pOpenContext );

NTSTATUS
DevOpen(
    IN PDEVICE_OBJECT            pDeviceObject,
    IN PIRP                      pIrp
    );

VOID
DevOnUnbindAdapter(
   POPEN_CONTEXT pOpenContext
   );

NTSTATUS
DevCleanup(
    IN PDEVICE_OBJECT            pDeviceObject,
    IN PIRP                      pIrp
    );

NTSTATUS
DevClose(
    IN PDEVICE_OBJECT            pDeviceObject,
    IN PIRP                      pIrp
    );

NTSTATUS
DevIoControl(
    IN PDEVICE_OBJECT            pDeviceObject,
    IN PIRP                      pIrp
    );

#endif // __PTEXTEND__H


