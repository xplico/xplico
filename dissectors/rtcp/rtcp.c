/* rtp.c
 * Dissector of RTCP protocol
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "rtcp.h"


/* info id */
static int ppp_id;
static int eth_id;
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ip_offset_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int udp_id;
static int uport_src_id;
static int uport_dst_id;
static int rtcp_id;
static int phone_id;


static volatile unsigned int incr;


static packet *RtcpPktDissector(packet *pkt)
{
    rtcp_common *rtcp;
    rtcp_sdes *sdes;
    rtcp_sdes_item *sitem;
    char *data;
    unsigned long len, plen;
    char phone[256];
    packet **ppkt_rtcp;
    packet *pkt_rtcp;
    pstack_f *frame;
    ftval info;
    
    data = pkt->data;
    len = pkt->len;
    pkt_rtcp = NULL;
    ppkt_rtcp = &pkt_rtcp;
    do {
        if (len >= sizeof(rtcp_common)) {
            rtcp = (rtcp_common *)data;
            if (rtcp->version != 2) {
                LogPrintf(LV_ERROR, "Packet version!");
                break;
            }
            plen = (ntohs(rtcp->length) + 1) * 4;
            if (plen > len) {
                LogPrintf(LV_ERROR, "Packet content length!");
                break;
            }
            /* find only phone numeber */
            if (rtcp->pt == RTCP_SDES) {
                sdes = (rtcp_sdes *)data;
                sitem = sdes->item;
                while (sitem->type != RTCP_SDES_END) {
                    if (sitem->type == RTCP_SDES_PHONE) {
                        memcpy(phone, sitem->data, sitem->length);
                        phone[sitem->length] = '\0';
                        *ppkt_rtcp = PktCp(pkt);
                        if (*ppkt_rtcp != NULL) {
                            /* end pdu */
                            (*ppkt_rtcp)->data = NULL;
                            (*ppkt_rtcp)->len = 0;
                            /* new frame */
                            frame = ProtCreateFrame(rtcp_id);
                            ProtSetNxtFrame(frame, (*ppkt_rtcp)->stk);
                            (*ppkt_rtcp)->stk = frame;
                            /* set attribute */
                            info.str = phone;
                            ProtInsAttr((*ppkt_rtcp)->stk, phone_id, &info);
                            /* next rtcp packet */
                            ppkt_rtcp = &((*ppkt_rtcp)->next);
                        }
                    }
                    /* next item */
                    sitem = (rtcp_sdes_item *)((char *)sitem + sitem->length + 2);
                }
            }
        }
        else {
            LogPrintf(LV_ERROR, "Packet length!!");
            break;
        }
        len -= plen;
        if (len != 0)
            data += plen;
        else
            data = NULL;
    } while (data != NULL);

    PktFree(pkt);
    
    return pkt_rtcp;
}


static bool RtpClientPkt(rtcp_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, uport_src_id, &port);
        if (port.uint16 == priv->port_s)
            ret = TRUE;
    }
    else {
        if (priv->ipv6 == TRUE) {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ipv6_src_id, &ip);
            type = FT_IPv6;
        }
        else {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ip_src_id, &ip);
            type = FT_IPv4;
        }
        if (FTCmp(&priv->ip_s, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }
    
    return ret;
}


static packet* RtcpDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *udp, *ip;
    ftval port_src, port_dst;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    rtcp_priv *priv;
    packet *pkt;

    LogPrintf(LV_DEBUG, "RTCP id: %d", flow_id);
    
    priv = DMemMalloc(sizeof(rtcp_priv));
    memset(priv, 0, sizeof(rtcp_priv));
    udp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(udp);
    ProtGetAttr(udp, uport_src_id, &port_src);
    ProtGetAttr(udp, uport_dst_id, &port_dst);
    priv->port_s = port_src.uint16;
    priv->port_d = port_dst.uint16;
    priv->stack = udp;
    if (priv->port_s != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    if (ProtFrameProtocol(ip) == ip_id)
        priv->ipv6 = FALSE;
    
    if (priv->ipv6 == FALSE) {
        ProtGetAttr(ip, ip_src_id, &priv->ip_s);
        ProtGetAttr(ip, ip_dst_id, &priv->ip_d);
        ip_addr.s_addr = priv->ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv->ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &priv->ip_d);
        memcpy(ipv6_addr.s6_addr, priv->ip_s.ipv6, sizeof(priv->ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv->ip_d.ipv6, sizeof(priv->ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    pkt = FlowGetPkt(flow_id);
    while (pkt != NULL) {
        pkt = RtcpPktDissector(pkt);
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    /* free */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "RTCP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool RtcpCheck(int flow_id)
{
    return FALSE;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_heury_dep hdep;
    
    memset(&info, 0, sizeof(proto_info));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    
    /* protocol name */
    ProtName("RTP control protocol", "rtcp");

    /* info: Phone */
    info.name = "Phone number";
    info.abbrev = "rtcp.phone";
    info.type = FT_STRING;
    phone_id = ProtInfo(&info);
    
    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = RtcpCheck;
    hdep.pktlim = RTCP_PKT_VER_LIMIT;
    //ProtHeuDep(&hdep);

    /* dissectors registration */
    ProtDissectors(RtcpPktDissector, RtcpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    /* part of file name */
    incr = 0;

    /* info id */
    ppp_id = ProtId("ppp");
    eth_id = ProtId("eth");
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ip_offset_id = ProtAttrId(ip_id, "ip.offset");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    udp_id = ProtId("udp");
    uport_dst_id = ProtAttrId(udp_id, "udp.dstport");
    uport_src_id = ProtAttrId(udp_id, "udp.srcport");
    rtcp_id = ProtId("rtcp");

    return 0;
}
