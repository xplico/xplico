/* arp.h
 * ARP and RARP dissector
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: ettercap -- ARP decoder module
 *   Copyright ALoR & NaGA. Web http://ettercap.sourceforge.net/
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


#ifndef __ARP_H__
#define __ARP_H__

#define ARPOP_REQUEST       1    /* ARP request.  */
#define ARPOP_REPLY         2    /* ARP reply.  */
#define ARPOP_RREQUEST      3    /* RARP request.  */
#define ARPOP_RREPLY        4    /* RARP reply.  */

#define MEDIA_ADDR_LEN      6
#define IP_ADDR_LEN         4
#define ARP_IP_STR_SIZE     100

struct arp_header {
   unsigned short ar_hrd;          /* Format of hardware address.  */
   unsigned short ar_pro;          /* Format of protocol address.  */
   unsigned char  ar_hln;          /* Length of hardware address.  */
   unsigned char  ar_pln;          /* Length of protocol address.  */
   unsigned short ar_op;           /* ARP opcode (command).  */
};


struct arp_eth_header {
   unsigned char arp_sha[MEDIA_ADDR_LEN];     /* sender hardware address */
   unsigned char arp_spa[IP_ADDR_LEN];      /* sender protocol address */
   unsigned char arp_tha[MEDIA_ADDR_LEN];     /* target hardware address */
   unsigned char arp_tpa[IP_ADDR_LEN];      /* target protocol address */
};


#endif

