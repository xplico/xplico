/* null.c
 * null packet dissector
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2013 Gianluca Costa. Web: www.xplico.org
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
#include "log.h"
#include "configs.h"

/* info id */
static int prot_id;
static int family_id;

static packet* NullDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    unsigned int null_hdr;
    unsigned short len;

    /* check consistence */
    if (pkt->len < 4) {
        LogPrintf(LV_WARNING, "Null packet dimension overflow the real dimension of packet");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }

    /* check if there is PPP */
    if (ntohs(*((unsigned short *)pkt->data)) == 0xFF03) {
        LogPrintf(LV_WARNING, "Null packet contents is PPP (to develop)");
        return NULL;
    }
    len = sizeof(unsigned int);
    memcpy(&null_hdr, pkt->data, len);
    if ((null_hdr & 0xFFFF0000) != 0) {
        /* swap bytes */
#warning "to complete"
        return NULL;
    }

    if (null_hdr > IEEE_802_3_MAX_LEN) {
#warning "to complete"
        return NULL;
    }
    
    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    val.uint32 = null_hdr;
    ProtInsAttr(frame, family_id, &val);

    /* pdu */
    pkt->data += len;
    pkt->len -= len;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));
    family_id = -1;
    
    /* protocol name */
    ProtName("Null/Loopback", "null");
   
    /* protocol */
    info.name = "family type";
    info.abbrev = "null.family";
    info.type = FT_UINT32;
    family_id = ProtInfo(&info);

    /* pcapf dependence */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_NULL;
    ProtDep(&dep);

    /* pol dependence */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_NULL;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(NullDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("null");
    
    return 0;
}
