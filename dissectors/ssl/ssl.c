/* ssl.c
 * Dissector to extract SSL information
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2013 Gianluca Costa. Web: www.xplico.org
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
#include <linux/tcp.h>
#include <dirent.h>
#include <ctype.h>

#include "ntoh.h"
#include "proto.h"
#include "dmemory.h"
#include "config_file.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "ssl.h"
#include "pei.h"


#define SSL_TMP_DIR       "ssl"

static int ip_id;
static int ipv6_id;
static int tcp_id;
static int ip_src_id;
static int ip_dst_id;
static int ip_offset_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int ssl_id;
static volatile int serial = 0;

/* pei id */
static int pei_ssl_sn_id;
 
static const unsigned short std_ports[] = TCP_PORTS_SSL;
static unsigned short std_ports_dim;
static volatile unsigned int incr;


static unsigned char *SslPacketRecontruct(ssl_rcnst *msgs, packet *pkt)
{
    unsigned char *ret, *data;
    unsigned short res;
    ssl_rcnst *nxt, *elab;
    unsigned long len;
    ret = NULL;

    if (pkt != NULL) {
        elab = msgs;
        len = 0;
        data = (unsigned char *)pkt->data;
        do {
            if (elab->dim == 0) {
                if (elab->len == 0) {
                    if (pkt->len > 4) {
                        elab->dim = ntohs(getu16(data, 3)) + 5; /* 5 byte of header */
                        elab->msg = xmalloc(elab->dim+1);
                        elab->msg[elab->dim] = '\0';
                    }
                    else {
                        elab->msg = xmalloc(pkt->len - len);
                        memcpy(elab->msg, data, pkt->len - len);
                        elab->len = pkt->len - len;
                        len = pkt->len;
                    }
                }
                else {
                    if (pkt->len - len + elab->len > 4) {
                        elab->msg = xrealloc(elab->msg, 100);
                        memcpy(elab->msg+elab->len, data, 5 - elab->len);
                        
                        elab->dim = ntohs(getu16(elab->msg, 3)) + 5; /* 5 byte of header */
                        elab->msg = xrealloc(elab->msg, elab->dim+1);
                        elab->msg[elab->dim] = '\0';
                    }
                    else {
                        elab->msg = xrealloc(elab->msg, 100);
                        memcpy(elab->msg+elab->len, data, pkt->len - len);
                        elab->len += pkt->len - len;
                        len = pkt->len;
                    }
                }
            }
            if (elab->dim != 0) {
                res = elab->dim - elab->len;
                if (res > pkt->len - len) {
                    memcpy(elab->msg+elab->len, data, pkt->len - len);
                    elab->len += pkt->len - len;
                    len = pkt->len;
                }
                else {
                    memcpy(elab->msg+elab->len, data, res);
                    len += res;
                    elab->len += res;
                    data = ((unsigned char *)pkt->data) + len;
                    elab->nxt = xmalloc(sizeof(ssl_rcnst));
                    memset(elab->nxt, 0, sizeof(ssl_rcnst));
                    elab = elab->nxt;
                }
            }
        } while (len != pkt->len);
    }

    if (msgs->dim != 0 && msgs->len == msgs->dim) {
        ret = msgs->msg;
        if (msgs->nxt != NULL) {
            nxt = msgs->nxt;
            memcpy(msgs, nxt, sizeof(ssl_rcnst));
            xfree(nxt);
        }
        else {
            memset(msgs, 0, sizeof(ssl_rcnst));
        }
    }
    
    return ret;
}


static void SslPacketRecFree(ssl_rcnst *msgs)
{
    ssl_rcnst *nxt, *tmp;
    
    if (msgs == NULL)
        return;
    if (msgs->msg != NULL) {
        xfree(msgs->msg);
        msgs->msg = NULL;
        msgs->dim = 0;
        msgs->len = 0;
    }
    tmp = msgs->nxt;

    while (tmp != NULL) {
        nxt = tmp->nxt;
        if (tmp->msg != NULL)
            xfree(tmp->msg);
        xfree(tmp);
        tmp = nxt;
    }
}


static char *SslServiceName(unsigned char *ssl_raw)
{
    char *name, *sname;
    unsigned short len, lstr, i;
    
    /* only Handshake */
    if (ssl_raw[0] != 0x16)
        return NULL;

    len = ntohs(getu16(ssl_raw, 3));
    
    /* only Certificate */
    if (len == 0 || ssl_raw[5] != 0x0b)
        return NULL;
    
    len +=5; /* add header size */
    name = NULL;
    
    for (i=5; i!=len; i++) {
        if (ssl_raw[i] == 0x55 && ssl_raw[i+1] == 0x04 && ssl_raw[i+2] == 0x03 && (ssl_raw[i+3] == 0x0c || ssl_raw[i+3] == 0x14 || ssl_raw[i+3] == 0x13)) {
            break;
        }
    }
    if (i != len) {
        i += 4;
        lstr = ssl_raw[i];
        i++;
        sname = (char *)&(ssl_raw[i]);
        while (i != len && isprint(*sname)==0 && lstr != 0) {
            sname++;
            i++;
            lstr--;
        }
        if (lstr) {
            name = xmalloc(lstr+1);
            for (i=0; i!=lstr; i++) {
                name[i] = sname[i];
            }
            name[lstr] = '\0';
        }
    }
    
    return name;
}


static bool SslVerifyCheck(int flow_id, bool check)
{
    packet *pkt; 
    ftval lost;
    ssl_rcnst msg;
    unsigned char *ssl_raw;

    pkt = FlowGetPktCp(flow_id);
    while (pkt != NULL && pkt->len == 0) {
        PktFree(pkt);
        pkt = FlowGetPktCp(flow_id);
    }
    if (pkt != NULL) {
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            if (pkt->len > 5) {
                if (pkt->data[0] == 0x16 && pkt->data[1] == 0x03 &&
                    (pkt->data[2] == 0x00 || pkt->data[2] == 0x01 || pkt->data[2] == 0x02)) {
                    if (check == FALSE) {
                        PktFree(pkt);
                        return TRUE;
                    }
                    memset(&msg, 0, sizeof(ssl_rcnst));
                    do {
                        ssl_raw = SslPacketRecontruct(&msg, pkt);
                        if (ssl_raw)
                            break;
                        PktFree(pkt);
                        pkt = FlowGetPktCp(flow_id);
                        if (pkt != NULL) {
                            ProtGetAttr(pkt->stk, lost_id, &lost);
                            if (lost.uint8 == TRUE) {
                                PktFree(pkt);
                                pkt = NULL;
                            }
                        }
                    } while (pkt != NULL);
                    SslPacketRecFree(&msg);
                    if (ssl_raw != NULL) { /* we consider the handshake fase */
                        xfree(ssl_raw);
                        
                        if (pkt != NULL)
                            PktFree(pkt);
                        pkt = FlowGetPktCp(flow_id);
                        while (pkt != NULL && pkt->len == 0) {
                            PktFree(pkt);
                            pkt = FlowGetPktCp(flow_id);
                        }
                        if (pkt != NULL) {
                            ProtGetAttr(pkt->stk, lost_id, &lost);
                            if (lost.uint8 == FALSE) {
                                if (pkt->len > 5) {
                                     if (pkt->data[0] == 0x16 && pkt->data[1] == 0x03 &&
                                         (pkt->data[2] == 0x00 || pkt->data[2] == 0x01 || pkt->data[2] == 0x02)) {
                                         PktFree(pkt);
                                         return TRUE;
                                     }
                                 }
                            }
                        }
                    }
                }
            }
        }
        if (pkt != NULL)
            PktFree(pkt);
    }

    return FALSE;
}


static bool SslVerify(int flow_id)
{
    return SslVerifyCheck(flow_id, FALSE);
}


static bool SslCheck(int flow_id)
{
    return SslVerifyCheck(flow_id, TRUE);
}


static void SslPei(pei *ppei, const char *server_name, time_t *cap_sec, time_t *end_cap)
{
}


static bool SslClientPkt(ssl_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
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


packet *SslDissector(int flow_id)
{
    packet *pkt;
    ssl_priv priv;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, lost;
    bool ipv4, clnt;
    pei *ppei;
    time_t cap_sec, end_cap;
    bool clost, slost, end;
    unsigned char *ssl_raw;
    ssl_rcnst msg_c, msg_s;
    char *service, *sid;

    LogPrintf(LV_DEBUG, "SSL flowid: %i", flow_id);
    
    /* init */
    memset(&priv, 0, sizeof(ssl_priv));
    memset(&msg_c, 0, sizeof(ssl_rcnst));
    memset(&msg_s, 0, sizeof(ssl_rcnst));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv.port_s = port_src.uint16;
    priv.stack = tcp;
    if (priv.port_s != port_dst.uint16)
        priv.port_diff = TRUE;
    priv.ipv6 = TRUE;
    ipv4 = FALSE;
    clost = slost = end = FALSE;
    service = sid = NULL;
    if (ProtFrameProtocol(ip) == ip_id) {
        ipv4 = TRUE;
        priv.ipv6 = FALSE;
    }
    if (ipv4) {
        ProtGetAttr(ip, ip_src_id, &priv.ip_s);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv.ip_s);
    }
    
    pkt = NULL;
    ppei = NULL;
    do {
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == FALSE) {
                /* create pei */
                PeiNew(&ppei, ssl_id);
                PeiCapTime(ppei, pkt->cap_sec);
                PeiMarker(ppei, pkt->serial);
                PeiStackFlow(ppei, tcp);
                cap_sec = pkt->cap_sec;
                end_cap = pkt->cap_sec;
                break;
            }
            else {
                clnt = SslClientPkt(&priv, pkt);
                if (clnt)
                    clost = TRUE;
                else
                    slost = TRUE;
            }
        }
    } while (pkt != NULL);
    while (pkt != NULL && end == FALSE) {
        clnt = SslClientPkt(&priv, pkt);
        //ProtStackFrmDisp(pkt->stk, TRUE);
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            if (clnt) {
                if (clost) {
                    /* resync */
                    if (pkt->len > 5) {
                        if (pkt->data[0] == 0x16 && pkt->data[1] == 0x03 &&
                            (pkt->data[2] == 0x00 || pkt->data[2] == 0x01 || pkt->data[2] == 0x02)) {
                            clost = FALSE;
                        }
                    }
                }
                if (!clost)
                    ssl_raw = SslPacketRecontruct(&msg_c, pkt);
                    
                /* analyse ssl packet */
                while (ssl_raw != NULL) {
                    xfree(ssl_raw);
                    ssl_raw = SslPacketRecontruct(&msg_c, NULL);
                }
            }
            else {
                if (slost) {
                    /* resync */
                    if (pkt->len > 5) {
                        if (pkt->data[0] == 0x16 && pkt->data[1] == 0x03 &&
                            (pkt->data[2] == 0x00 || pkt->data[2] == 0x01 || pkt->data[2] == 0x02)) {
                            slost = FALSE;
                        }
                    }
                }
                if (!slost)
                    ssl_raw = SslPacketRecontruct(&msg_s, pkt);
            
                /* analyse ssl packet */
                while (ssl_raw != NULL) {
                    service = SslServiceName(ssl_raw);
                    xfree(ssl_raw);
                    if (service != NULL) {
                        end = TRUE;
                        break;
                    }
                    ssl_raw = SslPacketRecontruct(&msg_s, NULL);
                }
            }
        }
        else {
            if (clnt)
                clost = TRUE;
            else
                slost = TRUE;
#if CA_CHECK_LOST
            LogPrintf(LV_WARNING, "Packet Lost (size:%lu)", pkt->len);
            ProtStackFrmDisp(pkt->stk, TRUE);
#endif
        }
        
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    while (pkt != NULL) {
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    SslPacketRecFree(&msg_c);
    SslPacketRecFree(&msg_s);
    
    /* insert data */
    SslPei(ppei, service, &cap_sec, &end_cap);
    if (service != NULL) {
        LogPrintf(LV_DEBUG, "Site: %s", service);
        xfree(service);
    }
    else if (sid == NULL) {
        ProtStackFrmDisp(tcp, TRUE);
    }
    
    /* insert pei */
    PeiIns(ppei);
    
    /* end */
    LogPrintf(LV_DEBUG, "SSL bye bye.");

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;
    unsigned short i;
    
    /* init */
    std_ports_dim = sizeof(std_ports)/sizeof(unsigned short);
    
    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
 
    /* protocol name */
    ProtName("SSL Analysis", "ssl");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.ProtCheck = SslVerify;
    dep.pktlim = TCP_SSL_PKT_LIMIT;
    for (i=0; i!=std_ports_dim; i++) {
        dep.val.uint16 = std_ports[i];
        ProtDep(&dep);
    }
    
    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = SslCheck;
    hdep.pktlim = TCP_SSL_PKT_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "sn";
    peic.desc = "Server name";
    ProtPeiComponent(&peic);
    
    /* dissectors subdissectors registration */
    ProtDissectors(NULL, SslDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tmp_dir[256];

    /* part of file name */
    incr = 0;

    /* info id */
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    tcp_id = ProtId("tcp");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
        ip_offset_id = ProtAttrId(ip_id, "ip.offset");
    }
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
        ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    }
    if (tcp_id != -1) {
        port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
        port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
        lost_id = ProtAttrId(tcp_id, "tcp.lost");
    }
    ssl_id = ProtId("ssl");
    
    /* pei id */
    pei_ssl_sn_id = ProtPeiComptId(ssl_id, "sn");

    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), SSL_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    return 0;
}
