/* prism.c
 * Prism capture header dissector
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include "prism.h"
#include "ipproto.h"


static int prot_id;
static int wlan_id;



static void PrismPrintHdrVal(const prism_val *val)
{
    LogPrintf(LV_DEBUG, "     did: 0x%x", val->did);
    LogPrintf(LV_DEBUG, "     status: 0x%x", val->status);
    LogPrintf(LV_DEBUG, "     len: 0x%x", val->len);
    LogPrintf(LV_DEBUG, "     data: 0x%x", val->data);
}


static void PrismPrintHdr(const prism_hdr *prism_h)
{
    char dname[PRISM_DNAMELEN+1];

    LogPrintf(LV_DEBUG, "Prism pkt:");
    LogPrintf(LV_DEBUG, "  code: %i", prism_h->msgcode);
    LogPrintf(LV_DEBUG, "  length: %i", prism_h->msglen);
    memcpy(dname, prism_h->devname, PRISM_DNAMELEN);
    dname[PRISM_DNAMELEN] = '\0';
    LogPrintf(LV_DEBUG, "  dev name: %s",dname);
    LogPrintf(LV_DEBUG, "  hosttime");
    PrismPrintHdrVal(&(prism_h->hosttime));
    LogPrintf(LV_DEBUG, "  mactime");
    PrismPrintHdrVal(&(prism_h->mactime));
    LogPrintf(LV_DEBUG, "  channel");
    PrismPrintHdrVal(&(prism_h->channel));
    LogPrintf(LV_DEBUG, "  rssi");
    PrismPrintHdrVal(&(prism_h->rssi));
    LogPrintf(LV_DEBUG, "  sq");
    PrismPrintHdrVal(&(prism_h->sq));
    LogPrintf(LV_DEBUG, "  signal");
    PrismPrintHdrVal(&(prism_h->signal));
    LogPrintf(LV_DEBUG, "  noise");
    PrismPrintHdrVal(&(prism_h->noise));
    LogPrintf(LV_DEBUG, "  rate");
    PrismPrintHdrVal(&(prism_h->rate));
    LogPrintf(LV_DEBUG, "  istx");
    PrismPrintHdrVal(&(prism_h->istx));
    LogPrintf(LV_DEBUG, "  frmlen");
    PrismPrintHdrVal(&(prism_h->frmlen));
}


static packet *PrismDissector(packet *pkt)
{
    pstack_f *frame;
    prism_hdr *prism_h;
    unsigned int offset;

    if (pkt->len < sizeof(prism_hdr)) {
        LogPrintf(LV_WARNING, "Prism header size error");
        PktFree(pkt);
        return NULL;
    }
    
    /* header */
    prism_h = (prism_hdr *)pkt->data;
    //PrismPrintHdr(prism_h);

    offset = prism_h->msglen;

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* pdu */
    pkt->data += offset;
    pkt->len -= offset;

    //ProtStackFrmDisp(pkt->stk, TRUE);
    if (wlan_id != -1)
        return ProtDissecPkt(wlan_id, pkt);
    return pkt;
}


static int PrismDissecRegist(void)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Prism capture header", "prism");
    
    /* dep: pcapf */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_PRISM_HEADER;
    ProtDep(&dep);
    
    /* dep: pol */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_PRISM_HEADER;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(PrismDissector, NULL, NULL, NULL);
    
    return 0;
}


int DissecRegist(const char *file_cfg)
{
    return PrismDissecRegist();
}


int DissectInit(void)
{
    prot_id = ProtId("prism");
    wlan_id = ProtId("wlan");

    return 0;
}
