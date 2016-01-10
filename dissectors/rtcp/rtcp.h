/* rtcp.h
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef __RTCP_H__
#define __RTCP_H__

#include "packet.h"

/* packets trashold to check rtp header */
#define RTCP_PKT_LIMIT             20

/* packets check */
#define RTCP_PKT_CHECK             6

/* packets limit for RtpVerify, RtpCheck */
#define RTCP_PKT_VER_LIMIT        (RTCP_PKT_LIMIT + RTCP_PKT_CHECK)


typedef enum {
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204
} rtcp_type;
 
typedef enum {
    RTCP_SDES_END = 0,
    RTCP_SDES_CNAME = 1,
    RTCP_SDES_NAME = 2,
    RTCP_SDES_EMAIL = 3,
    RTCP_SDES_PHONE = 4,
    RTCP_SDES_LOC = 5,
    RTCP_SDES_TOOL = 6,
    RTCP_SDES_NOTE = 7,
    RTCP_SDES_PRIV = 8,
    RTCP_SDES_MAX = 9
} rtcp_sdes_type;
 

typedef struct _rtcp_common rtcp_common;
struct _rtcp_common {
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned short version:2; /**< version */
    unsigned short pad:1;     /**< padding flag */
    unsigned short cnt:5;     /**< varies by packet type */
    unsigned short pt:8;      /**< paket type */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short cnt:5;     /**< varies by packet type */
    unsigned short pad:1;     /**< padding flag */
    unsigned short version:2; /**< version  */
    unsigned short pt:8;      /**< paket type */
#else
# error "Please fix <bits/endian.h>"
#endif
    unsigned short length; /**< packet length */
};


typedef struct _rtcp_sdes_item rtcp_sdes_item;
struct _rtcp_sdes_item {
    unsigned char type;    /* type of SDES item              */
    unsigned char length;  /* length of SDES item (in bytes) */
    char data[1];    /* text, not zero-terminated      */
};


typedef struct _rtcp_sdes rtcp_sdes;
struct _rtcp_sdes {
    rtcp_common common;      /* header */
    unsigned int identif;    /* ssrc or csrc */
    rtcp_sdes_item item[1];  /* sdes start items */
};


typedef struct _rtcp_priv rtcp_priv;
struct _rtcp_priv {
    bool port_diff;         /* connection with different port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip_s;             /* ip source */
    ftval ip_d;             /* ip destination */
    unsigned short port_s;  /* source port */
    unsigned short port_d;  /* destination port */
    const pstack_f *stack;  /* protocol stack */
};

#endif /* __RTCP_H__ */
