/* ppi.c
 * PPI Packet Header dissection
 * Routines for PPI Packet Header dissection
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include "ntoh.h"
#include "log.h"
#include "ppi.h"


static int prot_id;
static int dlt_id;

static packet *PpiDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    unsigned int offset;
    ppi_header *ppih;
    
    offset = 0;
    
    if (pkt->len < sizeof(ppi_header)) {
        PktFree(pkt);
        return NULL;
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    ppih = (ppi_header *)pkt->data;
    offset = kswaps(&ppih->len);
    val.uint32 = kswapsl(&ppih->dlt);
    ProtInsAttr(frame, dlt_id, &val);
    
    /* pdu */
    pkt->data += offset;
    pkt->len -= offset;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("PPI Packet Header", "ppi");
    
    /* Protocol */
    info.name = "Data Link Type (DLT)";
    info.abbrev = "ppi.dlt";
    info.type = FT_UINT32;
    dlt_id = ProtInfo(&info);
    
    /* dep: pcapf */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_PPI;
    ProtDep(&dep);
    
    /* dep: pol */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_PPI;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(PpiDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("ppi");

    return 0;
}
