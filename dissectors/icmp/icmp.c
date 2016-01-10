/* icmp.c
 * ICMP dissector
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

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ipproto.h"
#include "in_cksum.h"
#include "log.h"

static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int prot_id;


static packet* IcmpDissector(packet *pkt)
{
#warning "to be implement"

    PktFree(pkt);
    pkt = NULL;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Internet Control Message Protocol", "icmp");

    /* info */
    #warning "to be implement"

    /* dep: IP */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_ICMP;
    ProtDep(&dep);

 
    /* dissectors registration */
    ProtDissectors(IcmpDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    prot_id = ProtId("icmp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");

    return 0;
}
