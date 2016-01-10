/* sll.c
 * Linux "cooked mode" captures dissector
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
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ppptypes.h"
#include "log.h"
#include "configs.h"
#include "sll.h"

/* info id */
static int prot_id;
static int pkttype_id;
static int hatype_id;
static int halen_id;
static int protocol_id;

static packet* SllDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    struct sll_header *psll;
    unsigned short addr_len;

    /* check consistence */
    if (pkt->len < sizeof(struct sll_header)) {
        LogPrintf(LV_WARNING, "SLL packet dimension overflow the real dimension of packet");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }
    psll = (struct sll_header *)pkt->data;
    addr_len = ntohs(psll->sll_halen);
    if (addr_len > SLL_ADDRLEN) {
        LogPrintf(LV_WARNING, "SLL frame error");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
#if 0
    val.uint16 = ntohs(psll->sll_pkttype);
    ProtInsAttr(frame, pkttype_id, &val);
    val.uint16 = ntohs(psll->sll_hatype);
    ProtInsAttr(frame, hatype_id, &val);
    val.uint16 = addr_len;
    ProtInsAttr(frame, halen_id, &val);
#endif
    val.uint16 = ntohs(psll->sll_protocol);
    ProtInsAttr(frame, protocol_id, &val);

    /* pdu */
    pkt->data += sizeof(struct sll_header);
    pkt->len -= sizeof(struct sll_header);

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));
    pkttype_id = -1;
    hatype_id = -1;
    halen_id = -1;
    protocol_id = -1;
    
    /* protocol name */
    ProtName("Linux cooked-mode capture", "sll");
    
#if 0
    /* packet type  */
    info.name = "Packet type";
    info.abbrev = "sll.pkttype";
    info.type = FT_UINT16;
    pkttype_id = ProtInfo(&info);

    /* link-layer address type */
    info.name = "Link-layer address type";
    info.abbrev = "sll.hatype";
    info.type = FT_UINT16;
    hatype_id = ProtInfo(&info);

    /* link-layer address length */
    info.name = "Link-layer address length";
    info.abbrev = "sll.halen";
    info.type = FT_UINT16;
    halen_id = ProtInfo(&info);

    /* link-layer address */
#endif

    /* protocol */
    info.name = "Protocol type";
    info.abbrev = "sll.protocol";
    info.type = FT_UINT16;
    protocol_id = ProtInfo(&info);

    /* pcapf dependence */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_LINUX_SLL;
    ProtDep(&dep);

    /* pol dependence */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_LINUX_SLL;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(SllDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("sll");
    
    return 0;
}
