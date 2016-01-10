/* packet.h
 * Definitions of packet struture and topology
 *
 * $Id: $
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


#ifndef __PACKET_H__
#define __PACKET_H__

#include <time.h>

#include "istypes.h"
#include "ftypes.h"


/** protocol stack frame */
typedef struct _pstack_f pstack_f;
struct _pstack_f {
    int pid;          /**< protocol id */
    bool flow;        /**< true if protocol is a protocol that generate flow */
    int flow_id;      /**< flow id for flow equal to true */
    pstack_f *pfp;    /**< pre frame pointer */
    pstack_f *gstack; /**< next stack in group */
    ftval attr[2];    /**< protocol attribute */
};


/** packet type, all memory allocation must be executed whit dmalloc */
typedef struct _packet_t packet;
struct _packet_t {
    pstack_f *stk;           /**< protocol stack */
    time_t cap_sec;          /**< capture time sec */
    time_t cap_usec;         /**< capture time usec */
    unsigned long serial;    /**< serial number of packet (will be used in PEI) */
    char *raw;               /**< raw pkt if exist */
    unsigned long raw_len;   /**< raw packet size */
    packet *list;            /**< list of packet (raw and not) that compose this packet */
    char *dat_base;          /**< if data is an offset of this, for free memory */
    char *data;              /**< data extracted from previous dissection */
    unsigned long len;       /**< data len */
    packet *next;            /**< next packet */
};


void PktFree(packet *pkt);
packet *PktNew(void);
packet *PktCp(const packet *pkt);

#endif /* __PACKET_H__ */
