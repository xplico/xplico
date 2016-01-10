/* ip_frag.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#ifndef __IP_FRAG_H__
#define __IP_FRAG_H__

#include <netinet/ip.h>

#include "packet.h"
#include "istypes.h"

/* not swaped */
#define IP_FRG_MASK    0xff1f
#define IP_FRG_DF      0x40
#define IP_FRG_MF      0x20
#define IP_FRG_HSH     0x00ff


#define IP_HSH_TBL      256
#define IP_TO_SEC       60
#define IP_PKT_MAX_DIM  (10*1024)

typedef struct _ipv4_frag_t  ipv4_frag;
struct _ipv4_frag_t {
    struct iphdr *ip;
    bool last;
    packet *pkt;
    ipv4_frag *frg;
    ipv4_frag *nxt;
};


#endif
