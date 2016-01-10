/* l2tp.c
 * l2tp dissector
 * RFC 2661
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

#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "l2tp.h"
#include "ipproto.h"

static int prot_id;
static int tunnel_id;
static int session_id;
static int proto_id;


static void L2tpPrintHdr(l2tphdr *l2tp_h)
{
    LogPrintf(LV_DEBUG, "Type: %i", l2tp_h->t);
    LogPrintf(LV_DEBUG, "Lenght: %i", l2tp_h->l);
    LogPrintf(LV_DEBUG, "Seq: %i", l2tp_h->s);
    LogPrintf(LV_DEBUG, "Offset: %i", l2tp_h->o);
    LogPrintf(LV_DEBUG, "Priority: %i", l2tp_h->p);
    LogPrintf(LV_DEBUG, "Version: %i", l2tp_h->ver);
}


#warning "L2TP dissector must be flow dissector and node dissector"
static packet* L2tpDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    int proto_offset;
    l2tphdr *l2tp_h;
    unsigned short length, tunnel, session, offset;

    /* header */
    l2tp_h = (l2tphdr *)pkt->data;
    proto_offset = 0;

    /* l2tp version */
    if (l2tp_h->ver != 2) {
        LogPrintf(LV_WARNING, "L2TP version error (ver:%i)", l2tp_h->ver);
        L2tpPrintHdr(l2tp_h);
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }
    proto_offset += 2;

    /* control message */
    if (l2tp_h->t == 1) {
        LogPrintf(LV_DEBUG, "Control message l2tp ver:%i ", l2tp_h->ver);
        PktFree(pkt);

        return NULL;
    }
    
    /* length */
    if (l2tp_h->l == 1) {
        length = ntohs(*(uint16_t *)(pkt->data + proto_offset));
        //LogPrintf(LV_DEBUG, "Length message: %i", length);
        proto_offset += 2;
    }

    /* tunnel and session id */
    tunnel = ntohs(*(uint16_t *)(pkt->data + proto_offset));
    proto_offset += 2;
    session = ntohs(*(uint16_t *)(pkt->data + proto_offset));
    proto_offset += 2;

    /* Ns and Nr fields */
    if (l2tp_h->s == 1) {
        LogPrintf(LV_DEBUG, "Ns and Nr fields");
        ProtStackFrmDisp(pkt->stk, TRUE);
        proto_offset += 4;
    }
    
    /* offset size field */
    if (l2tp_h->o == 1) {
        offset = ntohs(*(uint16_t *)(pkt->data + proto_offset));
        //ProtStackFrmDisp(pkt->stk, TRUE);
        proto_offset += (offset + 2);
    }
    
    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    val.uint16 = tunnel;
    ProtInsAttr(frame, tunnel_id, &val);
    val.uint16 = session;
    ProtInsAttr(frame, session_id, &val);
    val.uint16 = 3; /* forced to be PPP */
    ProtInsAttr(frame, proto_id, &val);

    /* pdu */
    pkt->data += proto_offset;
    pkt->len -= proto_offset;

    return pkt;
}


static int L2tpDissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Layer 2 Tunneling Protocol", "l2tp");
    
    /* Tunnel ID */
    info.name = "Tunnel ID";
    info.abbrev = "l2tp.tunnel";
    info.type = FT_UINT16;
    tunnel_id = ProtInfo(&info);

    /* Session ID */
    info.name = "Session ID";
    info.abbrev = "l2tp.session";
    info.type = FT_UINT16;
    session_id = ProtInfo(&info);

    /* protocol */
    info.name = "Protocol";
    info.abbrev = "l2tp.protocol";
    info.type = FT_UINT16;
    proto_id = ProtInfo(&info);

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = 1701;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(L2tpDissector, NULL, NULL, NULL);

    return 0;
}


int DissecRegist(const char *file_cfg)
{
    return L2tpDissecRegist(file_cfg);
}


int DissectInit(void)
{
    prot_id = ProtId("l2tp");

    return 0;
}
