/* eth.c
 * Ethernet dissector
 *
 * $Id: eth.c,v 1.11 2007/06/05 17:57:11 costa Exp $
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

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"


static int hweth_len;
static int prot_id;
static int etype_id;
static int mac_src_id;


static packet* EthDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    struct ethhdr *eth;

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    eth = (struct ethhdr *)pkt->data;

    /* set attribute */
    memcpy(val.mac, eth->h_source, FT_ETH_LEN);
    ProtInsAttr(frame, mac_src_id, &val);
    val.uint16 = ntohs(eth->h_proto);
    ProtInsAttr(frame, etype_id, &val);

    /* pdu */
    pkt->data += hweth_len;
    pkt->len -= hweth_len;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Ethernet", "eth");
    
    /* Ethertype */
    info.name = "Source Hardware Address";
    info.abbrev = "eth.src";
    info.type = FT_ETHER;
    mac_src_id = ProtInfo(&info);

    /* Ethertype */
    info.name = "Ethertype";
    info.abbrev = "eth.type";
    info.type = FT_UINT16;
    etype_id = ProtInfo(&info);
    
    /* pcapf */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_EN10MB;
    ProtDep(&dep);
    
    /* pol */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_EN10MB;
    ProtDep(&dep);

    /* llc dependence */
    dep.name = "llc";
    dep.attr = "llc.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_EN10MB;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(EthDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    hweth_len = sizeof(struct ethhdr);
    prot_id = ProtId("eth");

    return 0;
}
