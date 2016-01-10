/* ipsec.c
 * ESP dissector
 *
 * $Id:$
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012-2013 Gianluca Costa. Web: www.xplico.org
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

#define SEP_HEADER_SIZE          8

static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int prot_id;


typedef struct _oflow oflow;
struct _oflow {
    bool ipv4;
    ftval ip_mx;
    ftval ip_mn;
};


static packet* IpSecDissector(packet *pkt)
{
    pstack_f *frame;

    /* check size */
    if (pkt->len < SEP_HEADER_SIZE) {
        PktFree(pkt);
        
        return NULL;
    }

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* set attribute */
        
    /* pdu */
    pkt->data += SEP_HEADER_SIZE;
    pkt->len -= SEP_HEADER_SIZE;


    return pkt;
}


int DissectFlowHash(cmpflow *fd, unsigned long *hashs)
{
    oflow *o;
    ftval tmp;
    const pstack_f *ip;
    
    fd->priv = xmalloc(sizeof(oflow));
    memset(fd->priv, 0, sizeof(oflow));
    o = fd->priv;
    
    ip = ProtGetNxtFrame(fd->stack);
    if (ProtFrameProtocol(ip) == ip_id) {
        o->ipv4 = TRUE;
        hashs[0] = 0;
        ProtGetAttr(ip, ip_dst_id, &o->ip_mx);
        ProtGetAttr(ip, ip_src_id, &o->ip_mn);
        hashs[1] = o->ip_mx.uint32 + o->ip_mn.uint32;
        if (o->ip_mx.uint32 < o->ip_mn.uint32) {
            tmp = o->ip_mn;
            o->ip_mn = o->ip_mx;
            o->ip_mx = tmp;
        }
    }
    else {
        o->ipv4 = FALSE;
        hashs[0] = 1;
        ProtGetAttr(ip, ipv6_dst_id, &o->ip_mx);
        ProtGetAttr(ip, ipv6_src_id, &o->ip_mn);
        hashs[1] = FTHash(&o->ip_mx, FT_IPv6);
        hashs[1] += FTHash(&o->ip_mn, FT_IPv6);
        if (memcmp(o->ip_mx.ipv6, o->ip_mn.ipv6, 16) < 0) {
            tmp = o->ip_mn;
            o->ip_mn = o->ip_mx;
            o->ip_mx = tmp;
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
        if (fa->ip_mx.uint32 < fb->ip_mx.uint32)
            return -1;
        else {
            if (fa->ip_mx.uint32 > fb->ip_mx.uint32)
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
        if (memcmp(fa->ip_mx.ipv6, fb->ip_mx.ipv6, 16) < 0)
            return -1;
        else {
            if (memcmp(fa->ip_mx.ipv6, fb->ip_mx.ipv6, 16) > 0)
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
    ProtName("Encapsulating Security Payload", "esp");

    /* dep: IP */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_ESP;
    ProtDep(&dep);

    /* dep: IPv6 */
    dep.name = "ipv6";
    dep.attr = "ipv6.nxt";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_ESP;
    ProtDep(&dep);

    /* rule ipv4 */
    ProtAddRule("(((ip.src == pkt.ip.src) AND (ip.dst == pkt.ip.dst)) OR ((ip.dst == pkt.ip.src)  AND (ip.src == pkt.ip.dst)))");
    
    /* rule: ipv6 */
    ProtAddRule("(((ipv6.src == pkt.ipv6.src)  AND (ipv6.dst == pkt.ipv6.dst)) OR ((ipv6.dst == pkt.ipv6.src) AND (ipv6.src == pkt.ipv6.dst)))");


    /* dissectors registration */
    ProtDissectors(IpSecDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    prot_id = ProtId("esp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    
    return 0;
}
