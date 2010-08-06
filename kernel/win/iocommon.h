#ifndef __IOCOMMON__H
#define __IOCOMMON__H

// Copyright And Configuration Management ----------------------------------
//
//                   User I/O Common Header - iocommon.h
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

#define FSCTL_PTUSERIO_BASE      FILE_DEVICE_NETWORK

#define _PTUSERIO_CTL_CODE(_Function, _Method, _Access)  \
            CTL_CODE(FSCTL_PTUSERIO_BASE, _Function, _Method, _Access)

#define IOCTL_PTUSERIO_ENUMERATE   \
            _PTUSERIO_CTL_CODE(0x201, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_OPEN_ADAPTER   \
            _PTUSERIO_CTL_CODE(0x202, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_QUERY_INFORMATION   \
            _PTUSERIO_CTL_CODE(0x203, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_SET_INFORMATION   \
            _PTUSERIO_CTL_CODE(0x204, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_QUERY_IPv4_BLOCK_STATISTICS   \
            _PTUSERIO_CTL_CODE(0x205, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_RESET_IPv4_BLOCK_STATISTICS   \
            _PTUSERIO_CTL_CODE(0x206, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_SET_IPv4_BLOCK_FILTER   \
            _PTUSERIO_CTL_CODE(0x207, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_QUERY_IPv6_BLOCK_STATISTICS   \
            _PTUSERIO_CTL_CODE(0x208, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_RESET_IPv6_BLOCK_STATISTICS   \
            _PTUSERIO_CTL_CODE(0x209, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
#define IOCTL_PTUSERIO_SET_IPv6_BLOCK_FILTER   \
            _PTUSERIO_CTL_CODE(0x20A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
    
/////////////////////////////////////////////////////////////////////////////
//                     IP Block Definitions and Structures                 //
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
//// SPECIFY STRUCTURE PACKING

#pragma pack(push,4)

typedef
struct _IPv4AddrStats
{
   ULONG    MPSendPktsCt;      // Packets through MPSendPackets.
   ULONG    MPSendPktsDropped; // Packets dropped in MPSendPackets.
   ULONG    PTRcvCt;           // Packets through PTReceive.
   ULONG    PTRcvDropped;      // Packets dropped in PTReceive.
   ULONG    PTRcvPktCt;        // Packets through PTReceivePacket.
   ULONG    PTRcvPktDropped;   // Packets dropped in PTReceivePacket.
}
   IPv4AddrStats, *PIPv4AddrStats;

typedef
struct _PassthruStatistics
{
    // Number of array elements.
    ULONG         NumberElements;

    // The statistics.
    IPv4AddrStats Stats;
}
   PassthruStatistics, *PPassthruStatistics;

typedef
struct _IPv4BlockAddrArray
{
    // Number of array elements.
    ULONG NumberElements;

    // The array.
    ULONG IPAddrArray[1];
}
   IPv4BlockAddrArray, *PIPv4BlockAddrArray, **HIPv4BlockAddrArray;

/////////////////////////////////////////////////////////////////////////////
//// REVERT TO DEFAULT STRUCTURE PACKING

#pragma pack(pop)

#endif // __IOCOMMON__H

