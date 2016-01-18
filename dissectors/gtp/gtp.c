/* gtp.c
 * GPRS Tunneling Protocol (GTP) dissector
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
#include "gtp.h"
#include "ipproto.h"

#define UDP_PORT_GTPv0  3386
#define UDP_PORT_GTPv1C 2123    /* 3G Control PDU */
#define UDP_PORT_GTPv1U 2152    /* 3G T-PDU */

static int prot_id;
static int tunnel_id;
static int proto_id;


static void GtpPrintHdr(gtphdr *gtp_h)
{
    LogPrintf(LV_DEBUG, "GTP");
    LogPrintf(LV_DEBUG, "  Version: %i", gtp_h->ver);
    LogPrintf(LV_DEBUG, "  Protocol Type: %i", gtp_h->prot);
    LogPrintf(LV_DEBUG, "  Extension Flag: %i", gtp_h->ext);
    LogPrintf(LV_DEBUG, "  Sequence Flag: %i", gtp_h->seq);
    LogPrintf(LV_DEBUG, "  N-PDU Flag: %i", gtp_h->npdu);
    LogPrintf(LV_DEBUG, "  Message Type: 0x%x", gtp_h->mtype);
    LogPrintf(LV_DEBUG, "  Length: %i", ntohs(gtp_h->len));
    LogPrintf(LV_DEBUG, "  TEID: 0x%x", gtp_h->teid);
    if (gtp_h->ext || gtp_h->seq || gtp_h->npdu) {
        LogPrintf(LV_DEBUG, "  Sequence: 0x%x", ntohs(gtp_h->seq_num));
        LogPrintf(LV_DEBUG, "  N-PDU: 0x%x", gtp_h->npdu_num);
        LogPrintf(LV_DEBUG, "  Extension: 0x%x", gtp_h->neht);
    }
}


static packet *GtpDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    gtphdr *gtp_h;
    unsigned short offset;
    unsigned char neht, nhlen;

    if (pkt->len < GTP_MIN_HEADER_SIZE) {
        LogPrintf(LV_WARNING, "GTP V1 size error");
        PktFree(pkt);
        return NULL;
    }
    
    /* header */
    gtp_h = (gtphdr *)pkt->data;
    /* gtp version */
    if (gtp_h->ver != 1) {
        LogPrintf(LV_WARNING, "GTP version error (ver:%i)", gtp_h->ver);
        GtpPrintHdr(gtp_h);
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }
    offset = 8;
    if (gtp_h->ext || gtp_h->seq || gtp_h->npdu) {
        offset += 4;
        if (gtp_h->ext) {
            /* decode extension header */
            neht = gtp_h->neht;
            while (neht != 0) {
                nhlen = pkt->data[offset];
                offset += nhlen;
                neht = pkt->data[offset-1];
            }
        }
        //GtpPrintHdr(gtp_h);

        /* new frame */
        frame = ProtCreateFrame(prot_id);
        ProtSetNxtFrame(frame, pkt->stk);
        pkt->stk = frame;
        
        /* set attribute */
        val.uint32 = gtp_h->teid;
        ProtInsAttr(frame, tunnel_id, &val);
        val.uint8 = gtp_h->mtype;
        ProtInsAttr(frame, proto_id, &val);
        
        /* pdu */
        pkt->data += offset;
        pkt->len -= offset;

        //LogPrintf(LV_DEBUG, "data: 0x%x 0x%x", pkt->data[0], pkt->data[1]);

        return pkt;
    }
    
    //ProtStackFrmDisp(pkt->stk, TRUE);
    PktFree(pkt);

    return NULL;

#if 0
    /* gtp version */
    if (gtp_h->ver != 1) {
        LogPrintf(LV_WARNING, "GTP version error (ver:%i)", gtp_h->ver);
        GtpPrintHdr(gtp_h);
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }
    proto_offset += 2;

    /* control message */
    if (gtp_h->t == 1) {
        LogPrintf(LV_DEBUG, "Control message gtp ver:%i ", gtp_h->ver);
        PktFree(pkt);

        return NULL;
    }
    
    /* length */
    if (gtp_h->l == 1) {
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
    if (gtp_h->s == 1) {
        LogPrintf(LV_DEBUG, "Ns and Nr fields");
        ProtStackFrmDisp(pkt->stk, TRUE);
        proto_offset += 4;
    }
    
    /* offset size field */
    if (gtp_h->o == 1) {
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
#endif
}


static int GtpDissecRegist(void)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("GPRS Tunneling Protocol", "gtp");
    
    /* tunnel endpoint identifier (TEID) */
    info.name = "Tunnel endpoint identifier";
    info.abbrev = "gtp.teid";
    info.type = FT_UINT32;
    tunnel_id = ProtInfo(&info);

    /* message type */
    info.name = "Message Type";
    info.abbrev = "gtp.msg";
    info.type = FT_UINT8;
    proto_id = ProtInfo(&info);

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = UDP_PORT_GTPv1U;
    ProtDep(&dep);

    /* rule (gtp is a node) */
    //ProtAddRule("gtp.teid == pkt.gtp.teid");
    
    /* dissectors registration */
    ProtDissectors(GtpDissector, NULL, NULL, NULL);
    
    return 0;
}


int DissecRegist(const char *file_cfg)
{
    return GtpDissecRegist();
}


int DissectInit(void)
{
    prot_id = ProtId("gtp");

    return 0;
}
