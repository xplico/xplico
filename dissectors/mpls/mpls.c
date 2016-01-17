/* mpls.c
 * mpls dissector
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2016 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <sys/types.h>

#include "proto.h"
#include "ipproto.h"
#include "ppptypes.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "configs.h"

/* info id */
static int prot_id;
static int label_id;
static int ip_id;
static int ipv6_id;
static unsigned short rt_len;

typedef struct _mpls_hd mpls_hd;
struct _mpls_hd {
	unsigned int label;
	unsigned char exp;
	unsigned char bos;
	unsigned char ttl;
};


static void DecodeMpls(unsigned char *data, mpls_hd *mpls)
{
    unsigned char octet0 = data[0];
    unsigned char octet1 = data[1];
    unsigned char octet2 = data[2];

    mpls->label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
    mpls->exp = (octet2 >> 1) & 0x7;
    mpls->bos = (octet2 & 0x1);
    mpls->ttl = data[3];
}


static packet* MplsDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val;
    mpls_hd hd;
    unsigned char first_nibble;
    unsigned int label;

    if (pkt->len < sizeof(mpls_hd)) {
        LogPrintf(LV_WARNING, "Mpls size error");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }
    DecodeMpls(pkt->data, &hd);
    label = hd.label;
    /* pdu */
    pkt->data += rt_len;
    pkt->len -= rt_len;
    while (pkt->len >= rt_len && hd.bos == 0) {
        DecodeMpls(pkt->data, &hd);
        label = hd.label;
        /* pdu */
        pkt->data += rt_len;
        pkt->len -= rt_len;
    }

    /* add frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;
    
    /* set attributes */
    val.uint32 = label;
    ProtInsAttr(frame, label_id, &val);
    
    first_nibble = (pkt->data[0] >> 4) & 0x0F;
    
    switch (first_nibble) {
    case 4:
        if (ip_id != -1) {
            return ProtDissecPkt(ip_id, pkt);
        }
        break;
        
    case 6:
        if (ipv6_id != -1) {
            return ProtDissecPkt(ipv6_id, pkt);
        }
        break;
    }
    
    PktFree(pkt);
    
    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Multi Protocol Label Switching", "mpls");
    
    /* label */
    info.name = "Label";
    info.abbrev = "mpls.label";
    info.type = FT_UINT32;
    label_id = ProtInfo(&info);

    /* ethernet dependence */
    dep.name = "eth";
    dep.attr = "eth.type";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_MPLS;
    ProtDep(&dep);
    dep.val.uint16 = ETHERTYPE_MPLS_MULTI;
    ProtDep(&dep);

    /* ppp dependence */
    dep.name = "ppp";
    dep.attr = "ppp.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = PPP_MPLS_UNI;
    ProtDep(&dep);
    dep.val.uint16 = PPP_MPLS_MULTI;
    ProtDep(&dep);
    
    /* ipv6 dependence */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_MPLS_IN_IP;
    ProtDep(&dep);

    /* chdlc dependence */
    dep.name = "chdlc";
    dep.attr = "chdlc.protocol";
    dep.type = FT_UINT16;
    dep.val.uint16 = ETHERTYPE_MPLS;
    ProtDep(&dep);
    dep.val.uint16 = ETHERTYPE_MPLS_MULTI;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(MplsDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    rt_len = 4;
    prot_id = ProtId("mpls");
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    
    return 0;
}
