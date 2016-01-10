/* ppp.c
 * PPP dissector
 * RFC 1661, RFC 1662
 *
 * $Id: ppp.c,v 1.3 2007/06/05 17:57:09 costa Exp $
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
#include "ppptypes.h"
#include "log.h"


static int prot_id;
static int proto_id;

/* Protocol field compression */
#define PFC_BIT 0x01

static packet* PppDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    int len;
    unsigned char prot;
    int proto_offset;
    unsigned short ppp_prot;

    len = 0;

    /* PPP HDLC encapsulation */
    if (*((unsigned char *)pkt->data) == 0xff) {
        proto_offset = 2;
    }
    else {
        /* address and control are compressed (NULL) */
        proto_offset = 0;
    }
    
    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    prot = *(pkt->data + proto_offset);
    if (prot & PFC_BIT) {
        /* Compressed protocol field - just the byte we fetched. */
        ppp_prot = prot;
        len = 1;
    }
    else {
        ppp_prot = ntohs(*((uint16_t *)(pkt->data + proto_offset)));
        len = 2;
    }
    val.uint16 = ppp_prot;
    ProtInsAttr(frame, proto_id, &val);

    /* pdu */
    pkt->data += len + proto_offset;
    pkt->len -= len + proto_offset;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Point-to-Point Protocol", "ppp");
    
    /* Protocol */
    info.name = "Protocol";
    info.abbrev = "ppp.protocol";
    info.type = FT_UINT16;
    proto_id = ProtInfo(&info);
    
    /* dep: pcapf */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_PPP;
    ProtDep(&dep);
    
    /* dep: pol */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_PPP;
    ProtDep(&dep);

    /* dep: l2tp */
    dep.name = "l2tp";
    dep.attr = "l2tp.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = 3;
    ProtDep(&dep);

    /* dep: pppoe */
    dep.name = "pppoe";
    dep.attr = "pppoe.code";
    dep.type = FT_UINT8;
    dep.val.uint8 = 0; /* data code */
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(PppDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("ppp");

    return 0;
}
