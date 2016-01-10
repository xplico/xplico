/* pcapf.c
 * Pcap file dissector
 *
 * $Id:  $
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

#include <stdio.h>
#include <pcap.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"

static int prot_id;
static int layer1_id;
#ifdef XPL_CHECK_CODE
static int count_id;
static int file_id;
#endif

static packet* PcapfDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    unsigned long pktlen;
#ifdef XPL_CHECK_CODE
    int len;
#endif

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* align 4b */
    pktlen = pkt->raw_len;
    pktlen = pktlen + 4 - (pktlen%4);

    /* set attribute */
    val.uint32 = *((unsigned long *)&(pkt->raw[pktlen]));
    ProtInsAttr(frame, layer1_id, &val);

#ifdef XPL_CHECK_CODE
    val.uint32 = *((unsigned long *)&(pkt->raw[pktlen+sizeof(unsigned long)]));
    ProtInsAttr(frame, count_id, &val);

    len = strlen(*(char **)&(pkt->raw[pktlen+sizeof(unsigned long)*2]))+1;
    val.str = DMemMalloc(len);
    strcpy(val.str, *(char **)&(pkt->raw[pktlen+sizeof(unsigned long)*2]));
    ProtInsAttr(frame, file_id, &val);
    DMemFree(val.str);
#endif
    /* null terminating */ 
    pkt->raw[pkt->raw_len] = '\0';

    /* pdu */
    pkt->dat_base = pkt->raw;
    pkt->data = pkt->raw;
    pkt->len = pkt->raw_len;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Pcap file", "pcapf");
    
    /* Physical Layer */
    info.name = "Physical Layer";
    info.abbrev = "pcapf.layer1";
    info.type = FT_UINT16;
    layer1_id = ProtInfo(&info);

#ifdef XPL_CHECK_CODE
    /* Packet counter */
    info.name = "Packet number";
    info.abbrev = "pcapf.count";
    info.type = FT_UINT32;
    count_id = ProtInfo(&info);

    /* File name */
    info.name = "File name";
    info.abbrev = "pcapf.file";
    info.type = FT_STRING;
    file_id = ProtInfo(&info);
#endif

    /* dissectors registration */
    ProtDissectors(PcapfDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    /* protocol id */
    prot_id = ProtId("pcapf");
    
    return 0;
}
