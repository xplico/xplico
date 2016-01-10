/* udp.c
 * UDP dissector
 *
 * $Id: $
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

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ipproto.h"
#include "in_cksum.h"
#include "log.h"
#include "configs.h"

static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int prot_id;
static int src_id;
static int dst_id;

static unsigned short udphdr_len;


typedef struct _oflow oflow;
struct _oflow {
    bool ipv4;
    ftval ip_mx;
    unsigned short port_mx;
    ftval ip_mn;
    unsigned short port_mn;
};


static packet* UdpDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val, ipv6_src, ipv6_dst;
    struct udphdr *udp;
    unsigned short len;
    unsigned int src, dst;
#if (XPL_DIS_IP_CHECKSUM == 0)
    vec_t cksum_vec[4];
    unsigned int phdr[2];
    unsigned short computed_cksum;
#endif

    /* packet len */
    if (pkt->len < udphdr_len) {
        LogPrintf(LV_WARNING, "UDP malformed packet");
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }

    udp = (struct udphdr *)pkt->data;
    len =  ntohs(udp->len);

    /* check lenght packet */
    if (pkt->len < len || len < sizeof(struct udphdr)) {
        LogPrintf(LV_WARNING, "UDP packet length error (udp:%i pkt:%i udp_header:%i)", len, pkt->len, sizeof(struct udphdr));
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }

    /* udp packet do not require a checksum when the cksum is == 0 */
    if (udp->check != 0) {
        /* check consistence and checksum */
        if (ProtFrameProtocol(pkt->stk) == ip_id) {
            /* IPV4 */
            ProtGetAttr(pkt->stk, ip_src_id, &val);
            src = val.uint32;
            ProtGetAttr(pkt->stk, ip_dst_id, &val);
            dst = val.uint32;
#if (XPL_DIS_IP_CHECKSUM == 0)
            cksum_vec[0].ptr = (const unsigned char *)&src;
            cksum_vec[0].len = 4;
            cksum_vec[1].ptr = (const unsigned char *)&dst;
            cksum_vec[1].len = 4;
            cksum_vec[2].ptr = (const unsigned char *)&phdr;
            phdr[0] = htonl((IP_PROTO_UDP<<16) + pkt->len);
            cksum_vec[2].len = 4;
            cksum_vec[3].ptr = (unsigned char *)pkt->data;
            cksum_vec[3].len = pkt->len;
            computed_cksum = in_cksum(&cksum_vec[0], 4);
            if (computed_cksum != 0) {
                LogPrintf(LV_WARNING, "UDP packet chechsum error 0x%x", computed_cksum);
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                
                return NULL;
            }
#endif
        }
        else {
            /* IPv6 */
            ProtGetAttr(pkt->stk, ipv6_src_id, &ipv6_src);
            ProtGetAttr(pkt->stk, ipv6_dst_id, &ipv6_dst);
#if (XPL_DIS_IP_CHECKSUM == 0)
            cksum_vec[0].ptr = (const unsigned char *)&ipv6_src.ipv6;
            cksum_vec[0].len = 16;
            cksum_vec[1].ptr = (const unsigned char *)&ipv6_dst.ipv6;
            cksum_vec[1].len = 16;
            cksum_vec[2].ptr = (const unsigned char *)&phdr;
            phdr[0] = htonl(pkt->len);
            phdr[1] = htonl(IP_PROTO_UDP);
            cksum_vec[2].len = 8;
            
            cksum_vec[3].ptr = (unsigned char *)pkt->data;
            cksum_vec[3].len = pkt->len;
            computed_cksum = in_cksum(&cksum_vec[0], 4);
            if (computed_cksum != 0) {
                LogPrintf(LV_WARNING, "UDP packet chechsum error 0x%x", computed_cksum);
                ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                
                return NULL;
            }
#endif
        }
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* set attribute */
    val.uint32 = ntohs(udp->source);
    ProtInsAttr(frame, src_id, &val);
    val.uint32 = ntohs(udp->dest);
    ProtInsAttr(frame, dst_id, &val);
        
    /* pdu */
    pkt->data += udphdr_len;
    pkt->len = len - udphdr_len;

    return pkt;
}


int DissectFlowHash(cmpflow *fd, unsigned long *hashs)
{
    oflow *o;
    ftval tmp;
    const pstack_f *ip;
    int cmpret;
    
    fd->priv = xmalloc(sizeof(oflow));
    memset(fd->priv, 0, sizeof(oflow));
    o = fd->priv;
    
    ip = ProtGetNxtFrame(fd->stack);
    if (ProtFrameProtocol(ip) == ip_id) {
        o->ipv4 = TRUE;
        hashs[0] = 0;
        ProtGetAttr(ip, ip_dst_id, &o->ip_mx);
        ProtGetAttr(ip, ip_src_id, &o->ip_mn);
        ProtGetAttr(fd->stack, dst_id, &tmp);
        o->port_mx = tmp.uint16;
        ProtGetAttr(fd->stack, src_id, &tmp);
        o->port_mn = tmp.uint16;
        hashs[1] = o->ip_mx.uint32 + o->ip_mn.uint32;
        hashs[1] += o->port_mx + o->port_mn;
        if (o->ip_mx.uint32 < o->ip_mn.uint32 || (o->ip_mx.uint32 == o->ip_mn.uint32 && o->port_mx < o->port_mn)) {
            tmp = o->ip_mn;
            o->ip_mn = o->ip_mx;
            o->ip_mx = tmp;
            tmp.uint16 = o->port_mn;
            o->port_mn = o->port_mx;
            o->port_mx = tmp.uint16;
        }
    }
    else {
        o->ipv4 = FALSE;
        hashs[0] = 1;
        ProtGetAttr(ip, ipv6_dst_id, &o->ip_mx);
        ProtGetAttr(ip, ipv6_src_id, &o->ip_mn);
        ProtGetAttr(fd->stack, dst_id, &tmp);
        o->port_mx = tmp.uint16;
        ProtGetAttr(fd->stack, src_id, &tmp);
        o->port_mn = tmp.uint16;
        hashs[1] = FTHash(&o->ip_mx, FT_IPv6);
        hashs[1] += FTHash(&o->ip_mn, FT_IPv6);
        hashs[1] += o->port_mx + o->port_mn;
        cmpret = memcmp(o->ip_mx.ipv6, o->ip_mn.ipv6, 16);
        if (cmpret < 0 || (cmpret == 0 && o->port_mx < o->port_mn)) {
            tmp = o->ip_mn;
            o->ip_mn = o->ip_mx;
            o->ip_mx = tmp;
            tmp.uint16 = o->port_mn;
            o->port_mn = o->port_mx;
            o->port_mx = tmp.uint16;
        }
    }
    
    return 0;
}


int DissectFlowCmpFree(cmpflow *fd)
{
    xfree(fd->priv);
    
    return 0;
}


int DissectFlowCmp(const cmpflow *fd_a, const cmpflow *fd_b)
{
    oflow *fa, *fb;
    
    fa = (oflow *)fd_a->priv;
    fb = (oflow *)fd_b->priv;
    
    if (fa->ipv4) {
        if (fa->ip_mn.uint32 < fb->ip_mn.uint32)
            return -1;
        else {
            if (fa->ip_mn.uint32 > fb->ip_mn.uint32)
                return 1;
        }
        if (fa->port_mn < fb->port_mn)
            return -1;
        else {
            if (fa->port_mn > fb->port_mn)
                return 1;
        }
        if (fa->ip_mx.uint32 < fb->ip_mx.uint32)
            return -1;
        else {
            if (fa->ip_mx.uint32 > fb->ip_mx.uint32)
                return 1;
        }
        if (fa->port_mx < fb->port_mx)
            return -1;
        else {
            if (fa->port_mx > fb->port_mx)
                return 1;
        }
    }
    else {
        if (memcmp(fa->ip_mn.ipv6, fb->ip_mn.ipv6, 16) < 0)
            return -1;
        else {
            if (memcmp(fa->ip_mn.ipv6, fb->ip_mn.ipv6, 16) > 0)
                return 1;
        }
        if (fa->port_mn < fb->port_mn)
            return -1;
        else {
            if (fa->port_mn > fb->port_mn)
                return 1;
        }
        if (memcmp(fa->ip_mx.ipv6, fb->ip_mx.ipv6, 16) < 0)
            return -1;
        else {
            if (memcmp(fa->ip_mx.ipv6, fb->ip_mx.ipv6, 16) > 0)
                return 1;
        }
        if (fa->port_mx < fb->port_mx)
            return -1;
        else {
            if (fa->port_mx > fb->port_mx)
                return 1;
        }
    }

    return 0;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("User Datagram Protocol", "udp");

    /* source */
    info.name = "Source port";
    info.abbrev = "udp.srcport";
    info.type = FT_UINT16;
    src_id = ProtInfo(&info);

    /* destination */
    info.name = "Destination port";
    info.abbrev = "udp.dstport";
    info.type = FT_UINT16;
    dst_id = ProtInfo(&info);

    /* dep: IP */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_UDP;
    ProtDep(&dep);

    /* dep: IPv6 */
    dep.name = "ipv6";
    dep.attr = "ipv6.nxt";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_UDP;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(UdpDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    prot_id = ProtId("udp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    
    udphdr_len = sizeof(struct udphdr);

    return 0;
}
