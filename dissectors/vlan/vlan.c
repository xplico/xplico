/* vlan.c
 * vlan dissector
 * VLAN 802.1Q ethernet header disassembly
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

#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"

static int prot_id;
static int vid_id;
static int proto_id;

#warning "VLAN dissector must be flow dissector and node dissector"
static packet* VlanDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    int proto_offset;
    unsigned short proto, vid;
    unsigned short data;

    /* header */
    data = ntohs(*((uint16_t *)pkt->data));
    proto_offset = 2;

    /* vid */
    vid = data & 0x0FFF;
    
    /* protocol */
    proto = ntohs(*(uint16_t *)(pkt->data + proto_offset));
    proto_offset += 2;

    if (proto <= IEEE_802_3_MAX_LEN) {
        /* to be implemented */
        LogPrintf(LV_DEBUG, "Unknow protocol:%i ", proto);
        PktFree(pkt);
        
        return NULL;
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    val.uint16 = vid;
    ProtInsAttr(frame, vid_id, &val);
    val.uint16 = proto;
    ProtInsAttr(frame, proto_id, &val);

    /* pdu */
    pkt->data += proto_offset;
    pkt->len -= proto_offset;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("802.1Q Virtual LAN", "vlan");
    
    /* Tunnel ID */
    info.name = "Vlan ID";
    info.abbrev = "vlan.id";
    info.type = FT_UINT16;
    vid_id = ProtInfo(&info);

    /* protocol */
    info.name = "Ethertype";
    info.abbrev = "vlan.type";
    info.type = FT_UINT16;
    proto_id = ProtInfo(&info);

    /* dep: udp */
    dep.name = "eth";
    dep.attr = "eth.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_VLAN;
    ProtDep(&dep);

    /* rule */
    /*ProtAddRule("(vlan.id == pkt.vlan.id)");*/
#warning "deadlock"

    /* dissectors registration */
    ProtDissectors(VlanDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("vlan");

    return 0;
}
