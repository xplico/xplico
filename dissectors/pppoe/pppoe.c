/* pppoe.c
 * PPPoE dissector
 * Routines for PPP Over Ethernet (PPPoE) packet disassembly (RFC2516)
 *
 * $Id: $
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

#include "proto.h"
#include "dmemory.h"
#include "pppoe.h"
#include "log.h"
#include "etypes.h"


static int prot_id;
static int type_id;
static int code_id;
static int ses_id;


static packet* PppoeDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    unsigned short len;
    pppoe_hdr *pppoeh;

    /* simple verify */
    if (sizeof(pppoe_hdr) > pkt->len) {
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }
    len = 0;
    pppoeh = (pppoe_hdr*)pkt->data;
    len = ntohs(pppoeh->len);
    
    if (len > pkt->len - sizeof(pppoe_hdr)) {
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* set attribute */
    /* type */
    val.uint8 = pppoeh->type;
    ProtInsAttr(frame, type_id, &val);
    
    /* code */
    val.uint8 = pppoeh->code;
    ProtInsAttr(frame, code_id, &val);

    /* session id */
    val.uint16 = ntohs(pppoeh->sess_id);
    ProtInsAttr(frame, ses_id, &val);

    /* pdu */
    pkt->data += sizeof(pppoe_hdr);
    pkt->len = len;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("PPP-over-Ethernet Session", "pppoe");
    
    /* Type */
    info.name = "Type";
    info.abbrev = "pppoe.type";
    info.type = FT_UINT8;
    type_id = ProtInfo(&info);
    
    /* Code */
    info.name = "Code";
    info.abbrev = "pppoe.code";
    info.type = FT_UINT8;
    code_id = ProtInfo(&info);

    /* Session ID */
    info.name = "Session ID";
    info.abbrev = "pppoe.session_id";
    info.type = FT_UINT16;
    ses_id = ProtInfo(&info);
    
    /* ethernet dependence */
    dep.name = "eth";
    dep.attr = "eth.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_PPPOES;
    ProtDep(&dep);
    
    /* vlan dependence */
    dep.name = "vlan";
    dep.attr = "vlan.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_PPPOES;
    ProtDep(&dep);

    /* rule */
    /*ProtAddRule("(pppoe.session_id == pkt.pppoe.session_id)");*/
#warning "deadlock"

    /* dissectors registration */
    ProtDissectors(PppoeDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("pppoe");

    return 0;
}
