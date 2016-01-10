/* ip.c
 * IPv6 dissector
 *
 * $Id:  $
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
#include <arpa/inet.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ipproto.h"
#include "ppptypes.h"
#include "log.h"
#include "ipv6.h"
#include "configs.h"


static int prot_id;
static int nxt_hdr_id;
static int src_id;
static int dst_id;
static int offset_id;
#if SNIFFER_EVASION
static int hlim_id;
#endif

static int Ipv6NxtHd(const char *data, unsigned long len, unsigned char *nhid)
{
    struct ipv6ext *exthdr;

    if (len < sizeof(struct ipv6ext)) {
        return -1;
    }

    exthdr = (struct ipv6ext *)data;
    *nhid = exthdr->nxt;
    return (exthdr->len + 1)<<3;
}


static packet* Ipv6Dissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    struct ipv6hdr *ipv6;
    size_t ipv6hdr_len;
    size_t ipv6_len;
    unsigned char nhid;
    int len;
    bool ext_hdr;
    
    ipv6 = (struct ipv6hdr *)pkt->data;
    ipv6hdr_len = sizeof(struct ipv6hdr);
    ipv6_len = ipv6hdr_len + ntohs(ipv6->plen);

    /* check consistence */
    if (ipv6_len > pkt->len) {
        LogPrintf(LV_WARNING, "IPv6 packet dimension overflow the real dimension of packet");
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }
    
    nhid = ipv6->nxt;
    do {
        ext_hdr = TRUE;
        switch (nhid) {
        case IP_PROTO_HOPOPTS: /* hop-by-hop option */
            len = Ipv6NxtHd(pkt->data+ipv6hdr_len, ipv6_len - ipv6hdr_len, &nhid);
            if (len == -1) {
                LogPrintf(LV_WARNING, "IPv6 ext packet dimension overflow the real dimension of packet");
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                return NULL;
            }
            ipv6hdr_len += len;
            break;
            
        case IP_PROTO_ROUTING:
            len = Ipv6NxtHd(pkt->data+ipv6hdr_len, ipv6_len - ipv6hdr_len, &nhid);
            if (len == -1) {
                LogPrintf(LV_WARNING, "IPv6 ext packet dimension overflow the real dimension of packet");
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                return NULL;
            }
            ipv6hdr_len += len;
            break;
            
        case IP_PROTO_FRAGMENT:    
#warning "we have to be implement the fragment ipv6"
            LogPrintf(LV_WARNING, "Fragment IPv6 ext packet !!");
            ext_hdr = FALSE;
            break;
            
        case IP_PROTO_ESP:
            len = Ipv6NxtHd(pkt->data+ipv6hdr_len, ipv6_len - ipv6hdr_len, &nhid);
            if (len == -1) {
                LogPrintf(LV_WARNING, "IPv6 ext packet dimension overflow the real dimension of packet");
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                return NULL;
            }
            ipv6hdr_len += len;
            break;
            
        case IP_PROTO_AH:
            len = Ipv6NxtHd(pkt->data+ipv6hdr_len, ipv6_len - ipv6hdr_len, &nhid);
            if (len == -1) {
                LogPrintf(LV_WARNING, "IPv6 ext packet dimension overflow the real dimension of packet");
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                return NULL;
            }
            ipv6hdr_len += len;
            break;
            
        case IP_PROTO_DSTOPTS:
            len = Ipv6NxtHd(pkt->data+ipv6hdr_len, ipv6_len - ipv6hdr_len, &nhid);
            if (len == -1) {
                LogPrintf(LV_WARNING, "IPv6 ext packet dimension overflow the real dimension of packet");
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                return NULL;
            }
            ipv6hdr_len += len;
            break;
            
        case IP_PROTO_MIPV6:
            len = Ipv6NxtHd(pkt->data+ipv6hdr_len, ipv6_len - ipv6hdr_len, &nhid);
            if (len == -1) {
                LogPrintf(LV_WARNING, "IPv6 ext packet dimension overflow the real dimension of packet");
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                return NULL;
            }
            ipv6hdr_len += len;
            break;
            
        case IP_PROTO_NONE:
        default:
            ext_hdr = FALSE;
            break;
        }
    } while (ext_hdr == TRUE);
    
    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;    

    /* set attribute */
    val.uint8 = nhid;
    ProtInsAttr(frame, nxt_hdr_id, &val);
    memcpy(val.ipv6, ipv6->saddr.s6_addr, sizeof(val.ipv6));
    ProtInsAttr(frame, src_id, &val);
    memcpy(val.ipv6, ipv6->daddr.s6_addr, sizeof(val.ipv6));
    ProtInsAttr(frame, dst_id, &val);
    val.uint32 = (pkt->data - pkt->raw);
    ProtInsAttr(frame, offset_id, &val);
#if SNIFFER_EVASION
    val.uint8 = ipv6->hlim;
    ProtInsAttr(frame, hlim_id, &val);
#endif

    /* pdu */
    pkt->data += ipv6hdr_len;
    pkt->len = ipv6_len - ipv6hdr_len;

    return pkt;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Internet Protocol Version 6", "ipv6");
    
    /* protocol */
    info.name = "Next header";
    info.abbrev = "ipv6.nxt";
    info.type = FT_UINT8;
    nxt_hdr_id = ProtInfo(&info);

    /* source */
    info.name = "Source";
    info.abbrev = "ipv6.src";
    info.type = FT_IPv6;
    src_id = ProtInfo(&info);

    /* destination */
    info.name = "Destination";
    info.abbrev = "ipv6.dst";
    info.type = FT_IPv6;
    dst_id = ProtInfo(&info);

    /* packet offset */
    info.name = "Packet Offset";
    info.abbrev = "ipv6.offset";
    info.type = FT_UINT32;
    offset_id = ProtInfo(&info);

#if SNIFFER_EVASION
    /* hop limit */
    info.name = "Hop limit";
    info.abbrev = "ipv6.hlim";
    info.type = FT_UINT8;
    hlim_id = ProtInfo(&info);
#endif

    /* ethernet dependence */
    dep.name = "eth";
    dep.attr = "eth.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_IPv6;
    ProtDep(&dep);

    /* llc dependence */
    dep.name = "llc";
    dep.attr = "llc.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_IPv6;
    ProtDep(&dep);

    /* sll dependence */
    dep.name = "sll";
    dep.attr = "sll.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_IPv6;
    ProtDep(&dep);

    /* ppp dependence */
    dep.name = "ppp";
    dep.attr = "ppp.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = PPP_IPV6;
    ProtDep(&dep);

    dep.name = "ppp";
    dep.attr = "ppp.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_IPv6;
    ProtDep(&dep);
    /* pcapf dependence */
    dep.name = "pcapf";
    dep.attr = "pcapf.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_IPV6;
    ProtDep(&dep);
    
    /* pol dependence */
    dep.name = "pol";
    dep.attr = "pol.layer1";
    dep.type = FT_UINT16;
    dep.val.uint16 = DLT_IPV6;
    ProtDep(&dep);

    /* ip dependence */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_IPV6;
    ProtDep(&dep);

    /* vlan dependence */
    dep.name = "vlan";
    dep.attr = "vlan.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_IPv6;
    ProtDep(&dep);

    /* chdlc dependence */
    dep.name = "chdlc";
    dep.attr = "chdlc.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_IPv6;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(Ipv6Dissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("ipv6");

    return 0;
}
