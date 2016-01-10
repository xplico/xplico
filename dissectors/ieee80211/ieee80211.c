/* ieee80211.c
 * Routines for Wireless LAN (IEEE 802.11) dissection
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
#include "ppptypes.h"
#include "log.h"
#include "ieee80211.h"

/* ************************************************************************* */
/*              Constants used to identify cooked frame types                */
/* ************************************************************************* */
#define MGT_FRAME            0x00  /* Frame type is management */
#define CONTROL_FRAME        0x01  /* Frame type is control */
#define DATA_FRAME           0x02  /* Frame type is Data */

#define DATA_SHORT_HDR_LEN     24
#define DATA_LONG_HDR_LEN      30
#define MGT_FRAME_HDR_LEN      24  /* Length of Managment frame-headers */


/*
 * COMPOSE_FRAME_TYPE() values for data frames.
 */
#define DATA                        0x20  /* Data                       */
#define DATA_CF_ACK                 0x21  /* Data + CF-Ack              */
#define DATA_CF_POLL                0x22  /* Data + CF-Poll             */
#define DATA_CF_ACK_POLL            0x23  /* Data + CF-Ack + CF-Poll    */
#define DATA_NULL_FUNCTION          0x24  /* Null function (no data)    */
#define DATA_CF_ACK_NOD             0x25  /* CF-Ack (no data)           */
#define DATA_CF_POLL_NOD            0x26  /* CF-Poll (No data)          */
#define DATA_CF_ACK_POLL_NOD        0x27  /* CF-Ack + CF-Poll (no data) */

#define DATA_QOS_DATA               0x28  /* QoS Data                   */
#define DATA_QOS_DATA_CF_ACK        0x29  /* QoS Data + CF-Ack        */
#define DATA_QOS_DATA_CF_POLL       0x2A  /* QoS Data + CF-Poll      */
#define DATA_QOS_DATA_CF_ACK_POLL   0x2B  /* QoS Data + CF-Ack + CF-Poll    */
#define DATA_QOS_NULL               0x2C  /* QoS Null        */
#define DATA_QOS_CF_POLL_NOD        0x2E  /* QoS CF-Poll (No Data)      */
#define DATA_QOS_CF_ACK_POLL_NOD    0x2F  /* QoS CF-Ack + CF-Poll (No Data) */

#define DATA_QOS_MASK               0x08
#define DATA_NULL_MASK              0x04

static int llc_id;
static int prot_id;
static int bss_id;

static packet* Ieee80211Dissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    int len;
    struct ieee80211hdr *ie80211;
    
    /* check minimal len (only data frame) */
    if (pkt->len < sizeof(struct ieee80211hdr))
        return NULL;
    
    len = 0;
    ie80211 = (struct ieee80211hdr *)pkt->data;
    
    /* only data frame with data */
    if (ie80211->u1.fc.type != DATA_FRAME ||
        (ie80211->u1.fc.subtype & DATA_NULL_MASK) == DATA_NULL_MASK) {
        return NULL;
    }

    /* Handle QoS */
    if ((ie80211->u1.fc.subtype & DATA_QOS_MASK) == DATA_QOS_MASK) {
        len += 2;
    }

    /* data addr */
    if (ie80211->u1.fc.to_ds == 0 && ie80211->u1.fc.from_ds == 0) {
        memcpy(val.mac, ie80211->addr3, FT_ETH_LEN);
        len += DATA_SHORT_HDR_LEN;
    } else if (ie80211->u1.fc.to_ds == 0 && ie80211->u1.fc.from_ds == 1) {
        memcpy(val.mac, ie80211->addr2, FT_ETH_LEN);
        len += DATA_SHORT_HDR_LEN;
    } else if (ie80211->u1.fc.to_ds == 1 && ie80211->u1.fc.from_ds == 0) {
        memcpy(val.mac, ie80211->addr1, FT_ETH_LEN);
        len += DATA_SHORT_HDR_LEN;
    } else if (ie80211->u1.fc.to_ds == 1 && ie80211->u1.fc.from_ds == 1) {
        memcpy(val.mac, ie80211->addr2, FT_ETH_LEN);
        len += DATA_LONG_HDR_LEN;
    }
    if (pkt->len < len)
        return NULL;

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    ProtInsAttr(frame, bss_id, &val);

    /* pdu */
    pkt->data += len;
    pkt->len -= len;

    if (llc_id != -1)
        return ProtDissecPkt(llc_id, pkt);
    
    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("IEEE 802.11 wireless LAN", "wlan");
    
    /* BSS ID */
    info.name = "BSS Id";
    info.abbrev = "wlan.bssid";
    info.type = FT_ETHER;
    bss_id = ProtInfo(&info);
    
    /* dep: pcapf */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_IEEE802_11;
    ProtDep(&dep);
    
    /* dep: pol */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_IEEE802_11;
    ProtDep(&dep);
    
    /* dep: ppi */
    dep.name = "ppi";
    dep.attr = "ppi.dlt";
    dep.type = FT_UINT32;
    dep.val.uint16 = DLT_IEEE802_11;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(Ieee80211Dissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("wlan");
    llc_id = ProtId("llc");

    return 0;
}
