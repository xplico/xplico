/* dns.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: ettercap -- dissector DNS -- UDP 53
 *   Copyright ALoR & NaGA. Web http://ettercap.sourceforge.net/
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


#ifndef __DNS_H__
#define __DNS_H__

/* standard port */
#define UDP_PORT_DNS        53
#define TCP_PORT_DNS        53
#define UDP_PORT_MDNS       5353
#define TCP_PORT_MDNS       5353

/* path buffer size */
#define DNS_FILENAME_PATH_SIZE        256
#define DNS_IP_STR_SIZE               100
#define DNS_USER_PWD_DIM              256
#define DNS_DATA_BUFFER               20480
#define DNS_CMD_NAME                  20
#define DNS_PKT_TIMEOUT               100

/* packets limit for DnsVerify, DnsCheck */
#define DNS_PKT_VER_LIMIT             6


/*
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */


typedef struct _dns_hdr dns_hdr;
struct _dns_hdr {
   unsigned short id;                /**< DNS packet ID */
#if __BYTE_ORDER == __BIG_ENDIAN
   unsigned char  qr: 1;             /**< response flag */
   unsigned char  opcode: 4;         /**< purpose of message */
   unsigned char  aa: 1;             /**< authoritative answer */
   unsigned char  tc: 1;             /**< truncated message */
   unsigned char  rd: 1;             /**< recursion desired */
   unsigned char  ra: 1;             /**< recursion available */
   unsigned char  unused: 1;         /**< unused bits */
   unsigned char  ad: 1;             /**< authentic data from named */
   unsigned char  cd: 1;             /**< checking disabled by resolver */
   unsigned char  rcode: 4;          /**< response code */
#else /* WORDS_LITTLEENDIAN */
   unsigned char  rd: 1;             /**< recursion desired */
   unsigned char  tc: 1;             /**< truncated message */
   unsigned char  aa: 1;             /**< authoritative answer */
   unsigned char  opcode: 4;         /**< purpose of message */
   unsigned char  qr: 1;             /**< response flag */
   unsigned char  rcode: 4;          /**< response code */
   unsigned char  cd: 1;             /**< checking disabled by resolver */
   unsigned char  ad: 1;             /**< authentic data from named */
   unsigned char  unused: 1;         /**< unused bits */
   unsigned char  ra: 1;             /**< recursion available */
#endif
   unsigned short num_q;             /**< Number of questions */
   unsigned short num_answer;        /**< Number of answer resource records */
   unsigned short num_auth;          /**< Number of authority resource records */
   unsigned short num_res;           /**< Number of additional resource records */
};

typedef struct _uca_priv uca_priv;
struct _uca_priv {
    bool port_diff;         /* connection with different port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip_s;             /* ip source */
    ftval ip_d;             /* ip destination */
    unsigned short port_s;  /* source port */
    unsigned short port_d;  /* destination port */
    const pstack_f *stack;  /* protocol stack */
    size_t bsent;
    size_t breceiv;
    unsigned long pkt_sent;
    unsigned long pkt_receiv;
    size_t *tarce_sent;
    size_t *tarce_receiv;
};


#endif /* __DNS_H__ */
