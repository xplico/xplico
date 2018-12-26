/* udp_analysis.c
 * Dissector extracts UDP informations
 *
 * $Id:  $
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <ctype.h>
#include <dirent.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "dnsdb.h"
#include "udp_analysis.h"
#include "pei.h"
#include "geoiploc.h"

/* nDPI library */
#include <libndpi/ndpi_main.h>
#include <libndpi/ndpi_api.h>

#define UDP_CA_TMP_DIR    "udp_ca"
#define NDPI_TICK_RES      1000        /* Hz */

static int ppp_id;
static int eth_id;
static int ip_id;
static int ipv6_id;
static int udp_id;
static int ip_src_id;
static int ip_dst_id;
static int ip_offset_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int port_src_id;
static int port_dst_id;
static int udp_ca_id;
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
static pthread_mutex_t ndpi_mux;  /* mutex to access the ndpi handler */
static unsigned int ndpi_flow_struct_size;
static unsigned int ndpi_proto_size;
static long limit_pkts;


static ndpi_protocol nDPIPacket(packet *pkt, struct ndpi_flow_struct *l7flow, struct ndpi_id_struct *l7src, struct ndpi_id_struct *l7dst, bool ipv4)
{
    void *data;
    size_t offset, size;
    ftval voffset;
    const pstack_f *ip;
    unsigned long when;
    ndpi_protocol l7prot_id;

    if (ipv4) {
        ip = ProtStackSearchProt(pkt->stk, ip_id);
        ProtGetAttr(ip, ip_offset_id, &voffset);
        offset = voffset.uint32;
        data = pkt->raw + offset;
        size = pkt->raw_len - offset;
    }
    else {
        ip = ProtStackSearchProt(pkt->stk, ipv6_id);
        ProtGetAttr(ip, ipv6_offset_id, &voffset);
        offset = voffset.uint32;
        data = pkt->raw + offset;
        size = pkt->raw_len - offset;
    }
    when = pkt->cap_sec;
    when = when * NDPI_TICK_RES;
    when += pkt->cap_usec/1000;  /* (1000000 / NDPI_TICK_RES) */;
    pthread_mutex_lock(&ndpi_mux);
    l7prot_id = ndpi_detection_process_packet(ndpi, l7flow, data, size, when, l7src, l7dst);
    pthread_mutex_unlock(&ndpi_mux);

    return l7prot_id;
}

static bool UdpCaCheck(int flow_id)
{
    if (FlowPktNum(flow_id) > limit_pkts || FlowIsClose(flow_id) == TRUE) {
        return TRUE;
    }

    return FALSE;
}


static void CaPei(pei *ppei, const char *prot_name, uca_priv *priv, time_t *cap_sec, time_t *end_cap)
{
    char val[UDP_CA_FILENAME_PATH_SIZE];
    char dns[UDP_CA_FILENAME_PATH_SIZE];
    float latitude;
    float longitude;
    char *cc;
    pei_component *cmpn;
    
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
        
        DnsDbSearch(&priv->ip_d, FT_IPv6, dns, UDP_CA_FILENAME_PATH_SIZE);
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

        DnsDbSearch(&priv->ip_d, FT_IPv4, dns, UDP_CA_FILENAME_PATH_SIZE);
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
        PeiCompAddStingBuff(cmpn, cc);
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


static bool UdpCaClientPkt(uca_priv *priv, packet *pkt)
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


static packet *UdpCaDissector(int flow_id)
{
    packet *pkt;
    uca_priv priv;
    const pstack_f *udp, *ip;
    ftval port_src, port_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    bool ipv4, clnt;
    unsigned int count;
    pei *ppei;
    time_t cap_sec, end_cap;
    size_t flow_size;
    char buff[UDP_CA_LINE_MAX_SIZE];
    char *l7prot_type;
    struct ndpi_flow_struct *l7flow;
    struct ndpi_id_struct *l7src, *l7dst;
    ndpi_protocol l7prot_id;

    LogPrintf(LV_DEBUG, "UDP analysis id: %d", flow_id);

    /* ndpi init */ 
    l7flow = xcalloc(1, ndpi_flow_struct_size);
    if (l7flow == NULL) {
        LogPrintf(LV_ERROR, "Out of memory");
        l7src = NULL;
        l7dst = NULL;
    }
    else {
        l7src = xcalloc(1, ndpi_proto_size);
        if (l7src != NULL) {
            l7dst = xcalloc(1, ndpi_proto_size);
            if (l7dst == NULL) {
                xfree(l7src);
                xfree(l7flow);
                l7src = NULL;
                l7flow = NULL;
            }
        }
        else {
            xfree(l7flow);
            l7flow = NULL;
            l7dst = NULL;
        }
    }

    /* init */
    memset(&priv, 0, sizeof(uca_priv));
    udp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(udp);
    ProtGetAttr(udp, port_src_id, &port_src);
    ProtGetAttr(udp, port_dst_id, &port_dst);
    priv.port_s = port_src.uint16;
    priv.port_d = port_dst.uint16;
    priv.stack = udp;
    if (priv.port_s != port_dst.uint16)
        priv.port_diff = TRUE;
    priv.ipv6 = TRUE;
    ipv4 = FALSE;
    if (ProtFrameProtocol(ip) == ip_id) {
        ipv4 = TRUE;
        priv.ipv6 = FALSE;
    }
    if (ipv4) {
        ProtGetAttr(ip, ip_src_id, &priv.ip_s);
        ProtGetAttr(ip, ip_dst_id, &priv.ip_d);
        ip_addr.s_addr = priv.ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv.ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv.ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &priv.ip_d);
        memcpy(ipv6_addr.s6_addr, priv.ip_s.ipv6, sizeof(priv.ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv.ip_d.ipv6, sizeof(priv.ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);    
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    l7prot_type = NULL;
    flow_size = 0;
    count = 0;
    ppei = NULL;
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
        /* create pei */
        PeiNew(&ppei, udp_ca_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, udp);
        cap_sec = pkt->cap_sec;
    }
    while (pkt != NULL) {
        clnt = UdpCaClientPkt(&priv, pkt);
        count++;
        if (clnt) {
            priv.bsent += pkt->len;
            priv.pkt_sent++;
        }
        else {
            priv.breceiv += pkt->len;
            priv.pkt_receiv++;
        }
        flow_size += pkt->len;
        end_cap = pkt->cap_sec;
        /* protocol type -ndpi- */
        if (l7prot_type == NULL && l7flow != NULL) {
            if (clnt) {
                l7prot_id = nDPIPacket(pkt, l7flow, l7src, l7dst, ipv4);
            }
            else {
                l7prot_id = nDPIPacket(pkt, l7flow, l7dst, l7src, ipv4);
            }
            if (l7prot_id.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
                l7prot_type = ndpi_protocol2name(ndpi, l7prot_id, buff, UDP_CA_LINE_MAX_SIZE);
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    if (l7prot_type == NULL) {
        if (priv.ipv6)
            l7prot_id = ndpi_guess_undetected_protocol(ndpi, l7flow, IPPROTO_UDP, 0, 0, priv.port_s, priv.port_d);
        else
            l7prot_id = ndpi_guess_undetected_protocol(ndpi, l7flow, IPPROTO_UDP, priv.ip_s.uint32, priv.ip_d.uint32, priv.port_s, priv.port_d);
        
        if (l7prot_id.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            l7prot_type = ndpi_protocol2name(ndpi, l7prot_id, buff, UDP_CA_LINE_MAX_SIZE);
        }
        else {
            l7prot_type = "Unknown";
        }
    }
    /* ndpi free */
    if (l7flow != NULL) {
        xfree(l7flow);
        xfree(l7src);
        xfree(l7dst);
        l7flow = NULL;
    }

    /* insert data */
    CaPei(ppei, l7prot_type, &priv, &cap_sec, &end_cap);
    /* insert pei */
    PeiIns(ppei);

    /* end */

    LogPrintf(LV_DEBUG, "UDP->%s  analysis... bye bye  fid:%d count: %i", l7prot_type, flow_id, count);

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("UDP Analysis", "udp-ca");

    /* dep: ethernet */
    hdep.name = "udp";
    hdep.ProtCheck = UdpCaCheck;
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

    limit_pkts = UDP_CA_PKT_LIMIT;

    /* dissectors subdissectors registration */
    ProtDissectors(NULL, UdpCaDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tmp_dir[256];
    NDPI_PROTOCOL_BITMASK all;

    /* part of file name */
    incr = 0;

    /* info id */
    ppp_id = ProtId("ppp");
    eth_id = ProtId("eth");
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    udp_id = ProtId("udp");
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
    if (udp_id != -1) {
        port_dst_id = ProtAttrId(udp_id, "udp.dstport");
        port_src_id = ProtAttrId(udp_id, "udp.srcport");
    }
    udp_ca_id = ProtId("udp-ca");
    
    /* pei id */
    pei_ip_src_id = ProtPeiComptId(udp_ca_id, "ip.src");
    pei_ip_dst_id = ProtPeiComptId(udp_ca_id, "ip.dst");
    pei_dns_id = ProtPeiComptId(udp_ca_id, "dns");
    pei_port_src_id = ProtPeiComptId(udp_ca_id, "port.src");
    pei_port_dst_id = ProtPeiComptId(udp_ca_id, "port.dst");
    pei_l7protocol_id = ProtPeiComptId(udp_ca_id, "l7prot");
    pei_lat_id = ProtPeiComptId(udp_ca_id, "lat");
    pei_long_id = ProtPeiComptId(udp_ca_id, "long");
    pei_country_code_id = ProtPeiComptId(udp_ca_id, "country_code");
    pei_bsent_id = ProtPeiComptId(udp_ca_id, "byte.sent");
    pei_brecv_id = ProtPeiComptId(udp_ca_id, "byte.receiv");
    pei_blost_sent_id = ProtPeiComptId(udp_ca_id, "byte.lost.sent");
    pei_blost_recv_id = ProtPeiComptId(udp_ca_id, "byte.lost.receiv");
    pei_pkt_sent_id = ProtPeiComptId(udp_ca_id, "pkt.sent");
    pei_pkt_recv_id = ProtPeiComptId(udp_ca_id, "pkt.receiv");
    pei_trace_sent = ProtPeiComptId(udp_ca_id, "trace.sent");
    pei_trace_recv = ProtPeiComptId(udp_ca_id, "trace.receiv");
    pei_metadata = ProtPeiComptId(udp_ca_id, "metadata");
    pei_trace_img = ProtPeiComptId(udp_ca_id, "trace.img");

    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), UDP_CA_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    /* ndpi */
    pthread_mutex_init(&ndpi_mux, NULL);
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
