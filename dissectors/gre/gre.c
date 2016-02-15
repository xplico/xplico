/* gre.c
 * Generic Routing Encapsulation (GRE) dissector
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2016 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>

#include "proto.h"
#include "ipproto.h"
#include "ppptypes.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "configs.h"

/* info id */
static int prot_id;
static int proto_id;
static int ip_id;
static int ipv6_id;

/* bit positions for flags in header */
#define GRE_CHECKSUM            0x8000
#define GRE_ROUTING             0x4000
#define GRE_KEY                 0x2000
#define GRE_SEQUENCE            0x1000
#define GRE_VERSION             0x0007


static packet* GreDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    unsigned short rt_len;
    unsigned short flags_and_ver;
    unsigned short protocol_type;
    unsigned short *dt;

    if (pkt->len < 4) {
        LogPrintf(LV_WARNING, "Gre size error");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }
    dt = (unsigned short *)pkt->data;
    flags_and_ver = ntohs(dt[0]);
    protocol_type = ntohs(dt[1]);
    rt_len = 4;
    if (flags_and_ver & GRE_CHECKSUM || flags_and_ver & GRE_ROUTING) {
        rt_len += 4;
    }
    if (flags_and_ver & GRE_KEY) {
        rt_len += 4;
    }
    if (flags_and_ver & GRE_SEQUENCE) {
        rt_len += 4;
    }
    
    /* pdu */
    pkt->data += rt_len;
    pkt->len -= rt_len;

    /* add frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* set attributes */
    val.uint16 = protocol_type;
    ProtInsAttr(frame, proto_id, &val);
    
    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Generic Routing Encapsulation", "gre");
    
    /* label */
    info.name = "Protocol Type";
    info.abbrev = "gre.proto";
    info.type = FT_UINT16;
    proto_id = ProtInfo(&info);

    /* ip dependence */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_GRE;
    ProtDep(&dep);

    /* dep: IPv6 */
    dep.name = "ipv6";
    dep.attr = "ipv6.nxt";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_GRE;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(GreDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("gre");
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    
    return 0;
}
