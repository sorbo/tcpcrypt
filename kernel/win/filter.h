#ifndef __FILTER__H
#define __FILTER__H

// Copyright And Configuration Management ----------------------------------
//
//           Header for PassThru Driver Filtering Module - filter.h
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


////////////////////////////////////////////////////////////////////////////
//                        Per-Open Filter Functions                       //
////////////////////////////////////////////////////////////////////////////

NTSTATUS
FltDevIoControl(
   IN PDEVICE_OBJECT    pDeviceObject,
   IN PIRP              pIrp
   );

VOID
FltOnInitOpenContext(
    IN POPEN_CONTEXT pOpenContext
    );

VOID
FltOnDeinitOpenContext(
    IN POPEN_CONTEXT pOpenContext
    );

////////////////////////////////////////////////////////////////////////////
//                      Per-Adapter Filter Functions                      //
////////////////////////////////////////////////////////////////////////////

VOID
FltOnInitAdapter(
    IN PADAPT  pAdapt
    );

VOID
FltOnDeinitAdapter(
    IN PADAPT  pAdapt
    );

////////////////////////////////////////////////////////////////////////////
//                        Send Packet Filter Functions                    //
////////////////////////////////////////////////////////////////////////////

//
// Send Filter "Action" Bitmap
// ---------------------------
// There may be additional actions defined in the future. Actions can be
// or-ed together in some situations.
//
#define  SND_FLT_SIMPLE_PASSTHRU    0x00000000
#define  SND_FLT_BLOCK_PACKET       0x00000001

ULONG
FltFilterSendPacket(
	IN PADAPT         pAdapt,
	IN	PNDIS_PACKET   pSendPacket,
   IN BOOLEAN        DispatchLevel  // TRUE -> IRQL == DISPATCH_LEVEL
	);

////////////////////////////////////////////////////////////////////////////
//                      Receive Packet Filter Functions                   //
////////////////////////////////////////////////////////////////////////////

//
// Receive Filter "Action" Bitmap
// ------------------------------
// There may be additional actions defined in the future. Actions can be
// or-ed together in some situations.
//
#define  RCV_FLT_SIMPLE_PASSTHRU    0x00000000
#define  RCV_FLT_BLOCK_PACKET       0x00000001

ULONG
FltFilterReceivePacket(
	IN PADAPT         pAdapt,
	IN	PNDIS_PACKET   pReceivedPacket
	);

ULONG
FltFilterReceive(
   IN PADAPT         pAdapt,
   IN NDIS_HANDLE    MacReceiveContext,
   IN PVOID          HeaderBuffer,
   IN UINT           HeaderBufferSize,
   IN PVOID          LookAheadBuffer,
   IN UINT           LookAheadBufferSize,
   IN UINT           PacketSize
   );

////////////////////////////////////////////////////////////////////////////
//                            Utility Functions                           //
////////////////////////////////////////////////////////////////////////////

VOID
FltReadOnPacket(
   IN PNDIS_PACKET Packet,
   IN PVOID lpBuffer,
   IN ULONG nNumberOfBytesToRead,
   IN ULONG nOffset,                // Byte Offset, Starting With MAC Header
   OUT PULONG lpNumberOfBytesRead
   );

typedef
int
(*BSEARCH_CMP_FCN)(
   const PVOID pSearchKey,
   const PVOID pElement
   );

PVOID bsearch(
   const PVOID pSearchKey,
   const PVOID pArrayBase,
   ULONG nNumElements,
   ULONG nBytesPerElement,
   BSEARCH_CMP_FCN compare
   );

#define htons(a)     RtlUshortByteSwap(a)
#define ntohs(a)     RtlUshortByteSwap(a)

#define htonl(a)     RtlUlongByteSwap(a)
#define ntohl(a)     RtlUlongByteSwap(a)

////////////////////////////////////////////////////////////////////////////
//                              Debug Functions                           //
////////////////////////////////////////////////////////////////////////////

#if DBG

#endif // DBG

#endif // __FILTER__H

