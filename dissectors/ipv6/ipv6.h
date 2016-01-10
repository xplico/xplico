/* ipv6.h
 * Definitions for IPv6 packet disassembly
 *
 * $Id: ipv6.h,v 1.1 2007/06/05 06:12:28 costa Exp $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __IPV6_H__
#define __IPV6_H__


#include <arpa/inet.h>


/*
 * Definition for internet protocol version 6.
 * RFC 1883
 */
struct ipv6hdr {
    unsigned char prio:4;  /* 4 bits priority */
    unsigned char ver:4;   /* 4 bits version */
    unsigned char flow[3]; /* 20 bits of flow-ID */
    unsigned short plen;   /* payload length */
    unsigned char  nxt;	   /* next header */
    unsigned char  hlim;   /* hop limit */
    struct in6_addr saddr; /* source address */
    struct in6_addr daddr; /* destination address */
};

struct ipv6ext {
    unsigned char nxt; /* next header */
    unsigned char len; /* ext payload length = (len + 1)^3 */
};

#endif /* __IPV6_H__ */
