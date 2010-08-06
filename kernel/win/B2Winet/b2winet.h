#ifndef __B2WINET_H
#define __B2WINET_H

// Copyright And Configuration Management ----------------------------------
//
//         BSD 5.0 netinet Master Header Adapted for Windows - B2Winet.h
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
// Header For Windows NT DDK Use Of FreeBSD 5.0 netinet Header Files
// -----------------------------------------------------------------
// These were adopted from Free BSD January 2003 distribution. They
// were taken from the "Live filesystem" CD. The text was converted
// to Windows format (\r\n line ending) using a text file conversion
// utility.
//
// The BSD files were edited to remove function prototypes and BSD
// KERNEL definitions. Data type definitions were changed to common
// Windows data types (See appology below).
//
// Only a few of the more commonly used headers are included here. In
// addition, the IPv6 suite is totally ignored for this sample.
//
// The resulting headers provide valuable definitions for manipulating
// Internet packets.
//

#ifdef MY_APPOLOGY

I originally intended to make minimal modifications to the BSD 5.0 headers.
The plan was to include type definitions here that would prevent the need
to make global replacements of type definitions.

HOWEVER, below there are five (5) definitions of a USHORT - and more for
char, int, long...

This nomenclature is probably valuable to some folks. However, I grew tired
of it early on and just did global search-and-replace. In the end there
are only UCHAR, USHORT, UINT and ULONG.

If I had a little more time I would have probably adopted the .NET type
definitions.

Thomas F. Divine
September 2, 2003

typedef unsigned short  u_short;
typedef unsigned short  u_short_t;
typedef unsigned short  uint16_t;
typedef unsigned short  u_int16_t;
typedef unsigned short  n_short;

#endif // MY_APPOLOGY

/////////////////////////////////////////////////////////////////////////////
//// Windows System Definitions

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#define LITTLE_ENDIAN 1234
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN 
#endif

/*
 * Basic system type definitions, taken from the BSD file sys/types.h.
 */

typedef ULONG		in_addr_t;
#define _IN_ADDR_T_DECLARED

typedef USHORT		in_port_t;
#define _IN_PORT_T_DECLARED

/////////////////////////////////////////////////////////////////////////////
//// Internet Protocol (IP)

/*
 * Internet address (old style... should be updated)
 */
struct in_addr {
        union {
                struct { UCHAR s_b1,s_b2,s_b3,s_b4; } S_un_b;
                struct { USHORT s_w1,s_w2; } S_un_w;
                ULONG S_addr;
        } S_un;
#define s_addr  S_un.S_addr
                                /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2
                                /* host on imp */
#define s_net   S_un.S_un_b.s_b1
                                /* network */
#define s_imp   S_un.S_un_w.s_w2
                                /* imp */
#define s_impno S_un.S_un_b.s_b4
                                /* imp # */
#define s_lh    S_un.S_un_b.s_b3
                                /* logical host */
};

//
// Specify Structure Packing
//
#pragma pack(push,1)

/////////////////////////////////////////////////////////////////////////////
//// Data Link

#include "ethernet.h"

#include "in.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "igmp.h"
#include "ip_icmp.h"

//
// Restore Default Structure Packing
//
#pragma pack(pop)

#endif // __B2WINET_H

