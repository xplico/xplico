/* llc.c
 * Routines for IEEE 802.2 LLC layer
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <sys/socket.h>

#include "proto.h"
#include "dmemory.h"
#include "ppptypes.h"
#include "log.h"
#include "llc.h"

static int prot_id;
static int type_id;

static packet* LlcDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    unsigned short type;
    int hlen;
    struct llchdr *llc;

    /* check minimal size */
    hlen = sizeof(struct llchdr);
    if (hlen > pkt->len) {
        return NULL;
    }
    
    llc = (struct llchdr *)pkt->data;

    /* it is snap */
    if (llc->dsnap != SAP_SNAP || llc->ssap != SAP_SNAP) {
        /* no snap */                
        return NULL;
    }
    
    /* check control */
    if (llc->control != 0x03) {
        /* possible xdlc_control */
        return NULL;
    }
    
    /* ethertype */
    if (llc->org_control == 0x0C28000) { /* Ethernet packet type as protocol ID */
        type = DLT_EN10MB;
        hlen += 2; /* offset to add */
    }
    else
        type = ntohs(llc->ethertype);
    
    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    val.uint16 = type;
    ProtInsAttr(frame, type_id, &val);

    /* pdu */
    pkt->data += hlen;
    pkt->len -= hlen;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Logical-Link Control", "llc");
    
    /* Protocol */
    info.name = "Type";
    info.abbrev = "llc.type";
    info.type = FT_UINT16;
    type_id = ProtInfo(&info);
    
    /* dep: ppp */
    dep.name = "ppp";
    dep.attr = "ppp.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = PPP_LLC;
    ProtDep(&dep);

    /* pcapf */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_ATM_RFC1483;
    ProtDep(&dep);
    
    /* pol */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_ATM_RFC1483;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(LlcDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("llc");

    return 0;
}
