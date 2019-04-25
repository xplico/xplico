/* tcp_analysis.c
 * Dissector to extract TCP informations
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012-2014 Gianluca Costa. Web: www.xplico.org
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
#include <dirent.h>
#include <ctype.h>

#include "proto.h"
#include "dmemory.h"
#include "config_file.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "dnsdb.h"
#include "tcp_analysis.h"
#include "pei.h"
#include "geoiploc.h"
#include "png.h"

/* nDPI library */
#include <libndpi/ndpi_main.h>


#define CA_CHECK_LOST     0           /* check lost data */
#define TCP_CA_TMP_DIR    "tcp_ca"
#define NDPI_TICK_RES     1000        /* Hz */
#define IMG_WIDTH         100         /* pixel */
#define IMG_HEIGHT        400         /* pixel */
#define IMG_P_SIZE        4           /* pixel size */

static int ppp_id;
static int eth_id;
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
static int syn_id;
static int tcp_ca_id;
static volatile int serial = 0;

/* pei id */
static int pei_ip_src_id;
static int pei_ip_dst_id;
static int pei_dns_id;
static int pei_port_src_id;
static int pei_port_dst_id;
static int pei_l7protocol_id;
static int pei_lat_id;
static int pei_long_id;
static int pei_country_code_id;
static int pei_bsent_id;
static int pei_brecv_id;
static int pei_blost_sent_id;
static int pei_blost_recv_id;
static int pei_pkt_sent_id;
static int pei_pkt_recv_id;
static int pei_trace_sent;
static int pei_trace_recv;
static int pei_trace_img;
static int pei_metadata;

static volatile unsigned int incr;
/* ndpi */
static struct ndpi_detection_module_struct *ndpi = NULL;
static unsigned int ndpi_flow_struct_size;
static unsigned int ndpi_proto_size;
static long limit_pkts;

static bool grpdis;
static tca_flow **prl_thrs;
static char *prl_thrs_en; /* 0->free, 1->starting, 2->running */
static int pthrs_dim;
static int pthrs_ins;
static pthread_mutex_t pthrs_mux;


static ndpi_protocol nDPIPacket(packet *pkt, struct ndpi_flow_struct *l7flow, struct ndpi_id_struct *l7src, struct ndpi_id_struct *l7dst, bool ipv6)
{
    void *data;
    size_t offset, size;
    ftval voffset;
    const pstack_f *ip;
    unsigned long when;
    ndpi_protocol l7prot_id;

    if (ipv6) {
        ip = ProtStackSearchProt(pkt->stk, ipv6_id);
        ProtGetAttr(ip, ipv6_offset_id, &voffset);
        offset = voffset.uint32;
        data = pkt->raw + offset;
        size = pkt->raw_len - offset;
    }
    else {
        ip = ProtStackSearchProt(pkt->stk, ip_id);
        ProtGetAttr(ip, ip_offset_id, &voffset);
        offset = voffset.uint32;
        data = pkt->raw + offset;
        size = pkt->raw_len - offset;
    }
    
    when = pkt->cap_sec;
    when = when * NDPI_TICK_RES;
    when += pkt->cap_usec/1000;  /* (1000000 / NDPI_TICK_RES) */;
    l7prot_id = ndpi_detection_process_packet(ndpi, l7flow, data, size, when, l7src, l7dst);

    return l7prot_id;
}


static bool TcpCaCheck(int flow_id)
{
    unsigned long pkt_num;
    
    pkt_num = FlowPktNum(flow_id);
    if (pkt_num > limit_pkts || (pkt_num > 0 && FlowIsClose(flow_id) == TRUE)) {
        return TRUE;
    }

    return FALSE;
}


static bool TcpCaCheckGrp(int flow_id)
{
    unsigned long pkt_num;
    bool elab;
    tca_flow *niflw;
    
    pkt_num = FlowPktNum(flow_id);
    if (pkt_num > limit_pkts || (pkt_num > 0 && FlowIsClose(flow_id) == TRUE)) {
        niflw = xmalloc(sizeof(tca_flow));
        if (niflw == NULL) {
            return FALSE;
        }
        memset(niflw, 0, sizeof(tca_flow));
        niflw->nxt = NULL;
        niflw->pre = NULL;
        niflw->flow_id = flow_id;
        niflw->pkt_elb = 0;
        
        pthread_mutex_lock(&pthrs_mux);
        niflw->nxt = prl_thrs[pthrs_ins];
        prl_thrs[pthrs_ins] = niflw;
        if (prl_thrs_en[pthrs_ins] != 0) {
            elab = TRUE;
        }
        else {
            prl_thrs_en[pthrs_ins] = 1;
            elab = FALSE;
        }
        pthrs_ins++;
        if (pthrs_dim == pthrs_ins) {
            pthrs_ins = 0;
        }
        pthread_mutex_unlock(&pthrs_mux);
        
        if (elab) {
            FlowSetElab(flow_id, -1);
        }

        return TRUE;
    }

    return FALSE;
}


static void CaPei(pei *ppei, const char *prot_name,  tca_priv *priv, time_t *cap_sec, time_t *end_cap)
{
    char val[TCP_CA_FILENAME_PATH_SIZE];
    char dns[TCP_CA_FILENAME_PATH_SIZE];
    float latitude;
    float longitude;
    pei_component *cmpn;
    char *cc;

    latitude = longitude = 0;
    cc = NULL;
    dns[0] = '\0';
    /* pei components */
    if (priv->ipv6) {
        FTString(&priv->ip_s, FT_IPv6, val);
        PeiNewComponent(&cmpn, pei_ip_src_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddStingBuff(cmpn, val);
        PeiAddComponent(ppei, cmpn);

        FTString(&priv->ip_d, FT_IPv6, val);
        PeiNewComponent(&cmpn, pei_ip_dst_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddStingBuff(cmpn, val);
        PeiAddComponent(ppei, cmpn);
        
        DnsDbSearch(&priv->ip_d, FT_IPv6, dns, TCP_CA_FILENAME_PATH_SIZE);
        GeoIPLocIP(&priv->ip_d, FT_IPv6, &latitude, &longitude, &cc);
    }
    else {
        FTString(&priv->ip_s, FT_IPv4, val);
        PeiNewComponent(&cmpn, pei_ip_src_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddStingBuff(cmpn, val);
        PeiAddComponent(ppei, cmpn);

        FTString(&priv->ip_d, FT_IPv4, val);
        PeiNewComponent(&cmpn, pei_ip_dst_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddStingBuff(cmpn, val);
        PeiAddComponent(ppei, cmpn);

        DnsDbSearch(&priv->ip_d, FT_IPv4, dns, TCP_CA_FILENAME_PATH_SIZE);
        GeoIPLocIP(&priv->ip_d, FT_IPv4, &latitude, &longitude, &cc);
    }
    
    PeiNewComponent(&cmpn, pei_dns_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, dns);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%i", priv->port_s);
    PeiNewComponent(&cmpn, pei_port_src_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%i", priv->port_d);
    PeiNewComponent(&cmpn, pei_port_dst_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    PeiNewComponent(&cmpn, pei_l7protocol_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, prot_name);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%f", latitude);
    PeiNewComponent(&cmpn, pei_lat_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%f", longitude);
    PeiNewComponent(&cmpn, pei_long_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    if (cc != NULL) {
        PeiNewComponent(&cmpn, pei_country_code_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        cmpn->strbuf = cc;
        PeiAddComponent(ppei, cmpn);
    }

    sprintf(val, "%zu", priv->bsent);
    PeiNewComponent(&cmpn, pei_bsent_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%zu", priv->breceiv);
    PeiNewComponent(&cmpn, pei_brecv_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%zu", priv->blost_sent);
    PeiNewComponent(&cmpn, pei_blost_sent_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%zu", priv->blost_receiv);
    PeiNewComponent(&cmpn, pei_blost_recv_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

    sprintf(val, "%lu", priv->pkt_sent);
    PeiNewComponent(&cmpn, pei_pkt_sent_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);
    
    sprintf(val, "%lu", priv->pkt_receiv);
    PeiNewComponent(&cmpn, pei_pkt_recv_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);
    
    if (priv->img1[0] != '\0') {
        PeiNewComponent(&cmpn, pei_trace_img);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddFile(cmpn, "client.png", priv->img1, 0);
        PeiAddComponent(ppei, cmpn);
    }
    
    if (priv->img2[0] != '\0') {
        PeiNewComponent(&cmpn, pei_trace_img);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddFile(cmpn, "server.png", priv->img2, 0);
        PeiAddComponent(ppei, cmpn);
    }
}


static bool TcpCaClientPkt(tca_priv *priv, packet *pkt)
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


static int TcpCaDisFlowInit(tca_flow *ifw)
{
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];

    LogPrintf(LV_DEBUG, "TCP analysis id: %d", ifw->flow_id);

    /* ndpi init */ 
    ifw->l7flow = xcalloc(1, ndpi_flow_struct_size);
    if (ifw->l7flow == NULL) {
        LogPrintf(LV_ERROR, "Out of memory");
        ifw->l7src = NULL;
        ifw->l7dst = NULL;
    }
    else {
        ifw->l7src = xcalloc(1, ndpi_proto_size);
        if (ifw->l7src != NULL) {
            ifw->l7dst = xcalloc(1, ndpi_proto_size);
            if (ifw->l7dst == NULL) {
                xfree(ifw->l7src);
                xfree(ifw->l7flow);
                ifw->l7src = NULL;
                ifw->l7flow = NULL;
            }
        }
        else {
            xfree(ifw->l7flow);
            ifw->l7flow = NULL;
            ifw->l7dst = NULL;
        }
    }
    
    /* init */
    memset(&ifw->priv, 0, sizeof(tca_priv));
    tcp = FlowStack(ifw->flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    ifw->priv.port_s = port_src.uint16;
    ifw->priv.port_d = port_dst.uint16;
    ifw->priv.stack = tcp;
    if (ifw->priv.port_s != port_dst.uint16)
        ifw->priv.port_diff = TRUE;
    ifw->priv.ipv6 = TRUE;
    ifw->first_lost = FALSE;
    ifw->stage = 0;
    if (ProtFrameProtocol(ip) == ip_id) {
        ifw->priv.ipv6 = FALSE;
    }
    if (!ifw->priv.ipv6) {
        ProtGetAttr(ip, ip_src_id, &ifw->priv.ip_s);
        ProtGetAttr(ip, ip_dst_id, &ifw->priv.ip_d);
        ip_addr.s_addr = ifw->priv.ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = ifw->priv.ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &ifw->priv.ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &ifw->priv.ip_d);
        memcpy(ipv6_addr.s6_addr, ifw->priv.ip_s.ipv6, sizeof(ifw->priv.ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, ifw->priv.ip_d.ipv6, sizeof(ifw->priv.ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    ifw->l7prot_type = NULL;
    ifw->flow_size = 0;
    ifw->count = 0;
    ifw->ppei = NULL;

    FlowSetTimeOut(ifw->flow_id, 0);

    return 0;
}


static int TcpCaDisFlow(tca_flow *ifw, packet *pkt)
{
    ftval lost, syn;
    bool clnt, ins;
    
    clnt = TcpCaClientPkt(&ifw->priv, pkt);
    ifw->flow_size += pkt->len;
    //ProtStackFrmDisp(pkt->stk, TRUE);
    ProtGetAttr(pkt->stk, lost_id, &lost);
    if (lost.uint8 == FALSE) {
        ins = TRUE;
        /* data */
        if (pkt->len != 0) {
            if (clnt) {
                ifw->priv.bsent += pkt->len;
                ifw->priv.pkt_sent++;
            }
            else {
                ifw->priv.breceiv += pkt->len;
                ifw->priv.pkt_receiv++;
            }
        }
        else {
            ProtGetAttr(pkt->stk, syn_id, &syn);
            if (clnt) {
                if (syn.uint8 == TRUE) {
                    if (ifw->syn_clt == FALSE)
                        ifw->syn_clt = TRUE;
                    else
                        ins = FALSE;
                }
            }
            else {
                if (syn.uint8 == TRUE) {
                    if (ifw->syn_srv == FALSE)
                        ifw->syn_srv = TRUE;
                    else
                        ins = FALSE;
                }
            }
        }
        ifw->count++;
        ifw->end_cap = pkt->cap_sec;
        
        /* protocol type -ndpi- */
        if (ifw->stage != 4 && (ifw->l7prot_type == NULL || ifw->l7prot_id.master_protocol == NDPI_PROTOCOL_HTTP) && ifw->l7flow != NULL && ins == TRUE) {
            if (clnt) {
                ifw->l7prot_id = nDPIPacket(pkt, ifw->l7flow, ifw->l7src, ifw->l7dst, ifw->priv.ipv6);
            }
            else {
                ifw->l7prot_id = nDPIPacket(pkt, ifw->l7flow, ifw->l7dst, ifw->l7src, ifw->priv.ipv6);
            }
            if (ifw->l7prot_id.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
                ifw->stage++;
                ifw->l7prot_type = ndpi_protocol2name(ndpi, ifw->l7prot_id, ifw->buff, TCP_CA_LINE_MAX_SIZE);
            }
        }
#ifdef XPL_CHECK_CODE
        if (pkt->raw_len != 0 && ((pkt->raw + pkt->raw_len) < pkt->data)) {
            LogPrintf(LV_OOPS, "TCP data location error %p %p %lu %lu", pkt->raw, pkt->data, pkt->raw_len, pkt->len);
            ProtStackFrmDisp(pkt->stk, TRUE);
            exit(-1);
        }
        if (pkt->raw_len != 0 && (pkt->data + pkt->len) > (pkt->raw + pkt->raw_len)) {
            LogPrintf(LV_OOPS, "TCP data dim error %p %p %lu %lu", pkt->raw, pkt->data, pkt->raw_len, pkt->len);
            ProtStackFrmDisp(pkt->stk, TRUE);
            exit(-1);
        }
#endif
    }
    else {
#if CA_CHECK_LOST
        LogPrintf(LV_WARNING, "Packet Lost (size:%lu)", pkt->len);
        ProtStackFrmDisp(pkt->stk, TRUE);
#endif
        if (clnt) {
            ifw->priv.blost_sent += pkt->len;
            if (ifw->priv.blost_sent == 0)
                ifw->priv.blost_sent = 1;
        }
        else {
            ifw->priv.blost_receiv += pkt->len;
            if (ifw->priv.blost_receiv == 0)
                ifw->priv.blost_receiv = 1;
        }
    }
        
    PktFree(pkt);

    return 0;
}


static int TcpCaDisFlowSetUp(tca_flow *ifw, packet *pkt)
{
    ftval lost;
    bool clnt;
    
    if (pkt != NULL) {
        clnt = TcpCaClientPkt(&ifw->priv, pkt);
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            /* create pei */
            PeiNew(&ifw->ppei, tcp_ca_id);
            PeiCapTime(ifw->ppei, pkt->cap_sec);
            PeiMarker(ifw->ppei, pkt->serial);
            PeiStackFlow(ifw->ppei, FlowStack(ifw->flow_id));
            ifw->cap_sec = pkt->cap_sec;
            ifw->end_cap = pkt->cap_sec;
            TcpCaDisFlow(ifw, pkt);
            return 0;
        }
        else {
            ifw->first_lost = TRUE;
            if (clnt) {
                ifw->priv.blost_sent += pkt->len;
                if (ifw->priv.blost_sent == 0)
                    ifw->priv.blost_sent = 1;
            }
            else {
                ifw->priv.blost_receiv += pkt->len;
                if (ifw->priv.blost_receiv == 0)
                    ifw->priv.blost_receiv = 1;
            }
        }
        PktFree(pkt);
    }
    
    return 1;
}


static packet *TcpCaDisFlowEnd(tca_flow *ifw)
{
    if (ifw->l7prot_type == NULL) {
        if (ifw->priv.ipv6)
            ifw->l7prot_id = ndpi_guess_undetected_protocol(ndpi, ifw->l7flow, IPPROTO_TCP, 0, 0, ifw->priv.port_s, ifw->priv.port_d);
        else
            ifw->l7prot_id = ndpi_guess_undetected_protocol(ndpi, ifw->l7flow, IPPROTO_TCP, ifw->priv.ip_s.uint32, ifw->priv.ip_d.uint32, ifw->priv.port_s, ifw->priv.port_d);
        
        if (ifw->l7prot_id.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            ifw->l7prot_type = ndpi_protocol2name(ndpi, ifw->l7prot_id, ifw->buff, TCP_CA_LINE_MAX_SIZE);
        }
        else {
            ifw->l7prot_type = "Unknown";
        }
    }
    /* ndpi free */
    if (ifw->l7flow != NULL) {
        xfree(ifw->l7flow);
        xfree(ifw->l7src);
        xfree(ifw->l7dst);
    }
    
    /* tcp reset */
    if (!(ifw->first_lost && (ifw->count < 5 || ifw->flow_size == 0))) {
        /* insert data */
        CaPei(ifw->ppei, ifw->l7prot_type, &ifw->priv, &ifw->cap_sec, &ifw->end_cap);
        /* insert pei */
        PeiIns(ifw->ppei);
    }
    /* end */
    
    LogPrintf(LV_DEBUG, "TCP->%s analysis... bye bye  fid:%d count:%i", ifw->l7prot_type, ifw->flow_id, ifw->count);

    if (grpdis) {
        FlowDelete(ifw->flow_id);
        xfree(ifw);
    }
    
    return NULL;
}


static packet *TcpCaDissector(int flow_id)
{
    packet *pkt;
    tca_flow flw;
    
    /* init */
    memset(&flw, 0, sizeof(tca_flow));
    flw.flow_id = flow_id;
    
    TcpCaDisFlowInit(&flw);
    FlowSetTimeOut(flow_id, -1);

    pkt = FlowGetPkt(flow_id);
    while (pkt != NULL) {
        if (TcpCaDisFlowSetUp(&flw, pkt) == 0) {
            pkt = NULL;
            break;
        }
        pkt = FlowGetPkt(flow_id);
    }
    
    pkt = FlowGetPkt(flow_id);
    while (pkt != NULL) {
        TcpCaDisFlow(&flw, pkt);
        pkt = FlowGetPkt(flow_id);
    }
    
    TcpCaDisFlowEnd(&flw);
    
    return NULL;
}


static void FlowEval(tca_flow **list, tca_flow *elem)
{
    tca_flow *par;

    if (*list == elem)
        return;
        
    par = elem->pre;
    while (par != NULL && par->pkt_elb < elem->pkt_elb)
        par = par->pre;
        
    if (par == elem->pre)
        return;
        
    elem->pre->nxt = elem->nxt;
    if (elem->nxt != NULL) {
        elem->nxt->pre = elem->pre;
    }
    if (par == NULL) {
        elem->pre = NULL;
        elem->nxt = *list;
        elem->nxt->pre = elem;
        *list = elem;
    }
    else {
        elem->pre = par;
        elem->nxt = par->nxt;
        par->nxt = elem;
        elem->nxt->pre = elem;
    }
}


static packet *TcpCaDissectorGrp(int flow_id)
{
    int id;
    packet *pkt;
    tca_flow *init;
    tca_flow *setup;
    tca_flow *runing;
    tca_flow *elem, *tmp;
    bool loop, wpkt, all;
    unsigned int flow_t;
    struct timespec req;
    unsigned long pkt_num;
    
    /* init */
    init = setup = runing = NULL;
    loop = all = TRUE;
    flow_t = 0;
    req.tv_sec = 0;
    req.tv_nsec = 50000000;
    
    pthread_mutex_lock(&pthrs_mux);
    for (id=0; id!=pthrs_dim; id++) {
        if (prl_thrs_en[id] == 1) {
            if (flow_id == prl_thrs[id]->flow_id)
                break;
            elem = prl_thrs[id]->nxt;
            while (elem != NULL) {
                if (flow_id == elem->flow_id) {
                    break;
                }
                elem = elem->nxt;
            }
            if (elem != NULL)
                break;
        }
    }
    if (id == pthrs_dim) {
        LogPrintf(LV_FATAL, "Thread didn't seleced\n");
        printf("Thread didn't seleced %i\n", flow_id);
        for (id=0; id!=pthrs_dim; id++) {
            if (prl_thrs_en[id] == 1)
                printf("id: %i st: %i flw: %i\n", id, prl_thrs_en[id], prl_thrs[id]->flow_id);
        }
        exit(-1);
    }
    prl_thrs_en[id] = 2;
    pthread_mutex_unlock(&pthrs_mux);

    do {
        wpkt = TRUE;
        /* new flow */
        pthread_mutex_lock(&pthrs_mux);
        init = prl_thrs[id];
        prl_thrs[id] = NULL;
        pthread_mutex_unlock(&pthrs_mux);
        while (init != NULL) {
            flow_t++;
            tmp = init->nxt;
            init->nxt = setup;
            if (setup != NULL) {
                setup->pre = init;
            }
            setup = init;
            TcpCaDisFlowInit(init);
            
            init = tmp;
        }

        /* flow setup */
        elem = setup;
        while (elem != NULL) {
            tmp = elem->nxt;
            pkt = FlowGetPkt(elem->flow_id);
            if (pkt != NULL) {
                wpkt = FALSE;
                do {
                    if (TcpCaDisFlowSetUp(elem, pkt) == 0) {
                        if (elem->nxt != NULL) {
                            elem->nxt->pre = elem->pre;
                        }
                        if (elem->pre != NULL) {
                            elem->pre->nxt = elem->nxt;
                            elem->pre = NULL;
                        }
                        else if (elem == setup) {
                            setup = elem->nxt;
                        }
                        elem->nxt = runing;
                        if (runing != NULL) {
                            runing->pre = elem;
                        }
                        runing = elem;
                        break;
                    }
                    pkt = FlowGetPkt(elem->flow_id);
                } while (pkt != NULL);
            }
            else {
                if (FlowIsEmpty(elem->flow_id)) {
                    flow_t--;
                    if (elem->nxt != NULL) {
                        elem->nxt->pre = elem->pre;
                    }
                    if (elem->pre != NULL) {
                        elem->pre->nxt = elem->nxt;
                        elem->pre = NULL;
                    }
                    else if (elem == setup) {
                        setup = elem->nxt;
                    }
                    TcpCaDisFlowEnd(elem);
                }
            }
            elem = tmp;
        }
        
        /* flow elaboration */
        elem = runing;
        while (elem != NULL) {
            if (all == FALSE) {
                if (elem->pkt_elb == 0)
                    break;
            }
            tmp = elem->nxt;
            pkt = FlowGetPkt(elem->flow_id);
            if (pkt != NULL) {
                pkt_num = 0;
                wpkt = FALSE;
                do {
                    pkt_num++;
                    TcpCaDisFlow(elem, pkt);
                    pkt = FlowGetPkt(elem->flow_id);
                } while (pkt != NULL);
                elem->pkt_elb = pkt_num;
                FlowEval(&runing, elem);
            }
            else {
                if (FlowIsEmpty(elem->flow_id)) {
                    flow_t--;
                    if (elem->nxt != NULL) {
                        elem->nxt->pre = elem->pre;
                    }
                    if (elem->pre != NULL) {
                        elem->pre->nxt = elem->nxt;
                        elem->pre = NULL;
                    }
                    else if (elem == runing) {
                        runing = elem->nxt;
                    }
                    TcpCaDisFlowEnd(elem);
                }
            }
            elem = tmp;
        }
        all = FALSE;
        
        /* check */
        if (runing == NULL && setup == NULL) {
            pthread_mutex_lock(&pthrs_mux);
            if (prl_thrs[id] == NULL) {
                prl_thrs_en[id] = 0;
                loop = FALSE;
            }
            pthread_mutex_unlock(&pthrs_mux);
        }
        else if (wpkt) {
            nanosleep(&req, NULL);
            all = TRUE;
        }
    } while (loop);
    
    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;
    long tmp;
    
    pthrs_dim = TCP_CA_DEFUALT_PARAL_THR;
    grpdis = TRUE;
    
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* threads parallel */
    if (file_cfg != NULL) {
        if (CfgParamInt(file_cfg, TCP_CA_CFG_PARAL_THR, &tmp) == 0) {
            if (tmp > 0)
                pthrs_dim = tmp;
            else
                grpdis = FALSE;
        }
    }
    
    /* protocol name */
    ProtName("TCP Analysis", "tcp-ca");

    /* dep: tcp */
    hdep.name = "tcp";
    if (grpdis == TRUE)
        hdep.ProtCheck = TcpCaCheckGrp;
    else
        hdep.ProtCheck = TcpCaCheck;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "ip.src";
    peic.desc = "IP source";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "ip.dst";
    peic.desc = "IP destination";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "dns";
    peic.desc = "dns name request";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "port.src";
    peic.desc = "Port source";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "port.dst";
    peic.desc = "Port destination";
    ProtPeiComponent(&peic);

    peic.abbrev = "l7prot";
    peic.desc = "L7 protocol march";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "lat";
    peic.desc = "Latitude";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "long";
    peic.desc = "Longitude";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "country_code";
    peic.desc = "Country Code";
    ProtPeiComponent(&peic);

    peic.abbrev = "byte.sent";
    peic.desc = "Byte sent";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "byte.receiv";
    peic.desc = "Byte received";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "byte.lost.sent";
    peic.desc = "Lost bytes sent";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "byte.lost.receiv";
    peic.desc = "Lost bytes received";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "pkt.sent";
    peic.desc = "Packet sent";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "pkt.receiv";
    peic.desc = "Packet received";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "trace.sent";
    peic.desc = "Trace sent";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "trace.receiv";
    peic.desc = "Trace recived";
    ProtPeiComponent(&peic);

    peic.abbrev = "trace.img";
    peic.desc = "Trace the bytes with an image";
    ProtPeiComponent(&peic);

    peic.abbrev = "metadata";
    peic.desc = "Metadata: JSON file with metadata";
    ProtPeiComponent(&peic);

    limit_pkts = TCP_CA_PKT_LIMIT;
    
    /* dissectors subdissectors registration */
    if (grpdis == TRUE) {
        ProtDissectors(NULL, TcpCaDissectorGrp, NULL, NULL);
    }
    else {
        ProtDissectors(NULL, TcpCaDissector, NULL, NULL);
    }

    return 0;
}


int DissectInit(void)
{
    char tmp_dir[256];
    int i;
    NDPI_PROTOCOL_BITMASK all;

    /* part of file name */
    incr = 0;
    pthrs_ins = 0;
    pthread_mutex_init(&pthrs_mux, NULL);
    
    prl_thrs = xmalloc(pthrs_dim*sizeof(tca_flow *));
    prl_thrs_en = xmalloc(pthrs_dim*sizeof(char));
    if (prl_thrs != NULL) {
        memset(prl_thrs, 0, pthrs_dim*sizeof(tca_flow *));
        for (i=0; i!=pthrs_dim; i++) {
            prl_thrs_en[i] = 0;
        }
    }
    
    /* info id */
    ppp_id = ProtId("ppp");
    eth_id = ProtId("eth");
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
        syn_id = ProtAttrId(tcp_id, "tcp.syn");
    }
    tcp_ca_id = ProtId("tcp-ca");
    
    /* pei id */
    pei_ip_src_id = ProtPeiComptId(tcp_ca_id, "ip.src");
    pei_ip_dst_id = ProtPeiComptId(tcp_ca_id, "ip.dst");
    pei_dns_id = ProtPeiComptId(tcp_ca_id, "dns");
    pei_port_src_id = ProtPeiComptId(tcp_ca_id, "port.src");
    pei_port_dst_id = ProtPeiComptId(tcp_ca_id, "port.dst");
    pei_l7protocol_id = ProtPeiComptId(tcp_ca_id, "l7prot");
    pei_lat_id = ProtPeiComptId(tcp_ca_id, "lat");
    pei_long_id = ProtPeiComptId(tcp_ca_id, "long");
    pei_country_code_id = ProtPeiComptId(tcp_ca_id, "country_code");
    pei_bsent_id = ProtPeiComptId(tcp_ca_id, "byte.sent");
    pei_brecv_id = ProtPeiComptId(tcp_ca_id, "byte.receiv");
    pei_blost_sent_id = ProtPeiComptId(tcp_ca_id, "byte.lost.sent");
    pei_blost_recv_id = ProtPeiComptId(tcp_ca_id, "byte.lost.receiv");
    pei_pkt_sent_id = ProtPeiComptId(tcp_ca_id, "pkt.sent");
    pei_pkt_recv_id = ProtPeiComptId(tcp_ca_id, "pkt.receiv");
    pei_trace_sent = ProtPeiComptId(tcp_ca_id, "trace.sent");
    pei_trace_recv = ProtPeiComptId(tcp_ca_id, "trace.receiv");
    pei_metadata = ProtPeiComptId(tcp_ca_id, "metadata");
    pei_trace_img = ProtPeiComptId(tcp_ca_id, "trace.img");

    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), TCP_CA_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    /* ndpi */
    ndpi = ndpi_init_detection_module();
    if (ndpi == NULL) {
        LogPrintf(LV_ERROR, "nDPi initializzation failed");

        return -1;
    }
    /* enable all protocols */
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi, &all);
    ndpi_proto_size = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_flow_struct_size = ndpi_detection_get_sizeof_ndpi_flow_struct();

    return 0;
}
