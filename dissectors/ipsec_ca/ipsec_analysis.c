/* ipsec_analysis.c
 * Dissector extracts ESP informations
 *
 * $Id:$
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012 Gianluca Costa. Web: www.xplico.org
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

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ipproto.h"
#include "in_cksum.h"
#include "log.h"
#include "configs.h"
#include "pei.h"
#include "dnsdb.h"
#include "geoiploc.h"
#include "ipsec_analysis.h"

static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int esp_ca_id;

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
static int pei_metadata;
static int pei_trace_img;

static volatile unsigned int incr;

static void CaPei(pei *ppei, const char *prot_name, espca_priv *priv, time_t *cap_sec, time_t *end_cap)
{
    char val[ESP_CA_FILENAME_PATH_SIZE];
    char dns[ESP_CA_FILENAME_PATH_SIZE];
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
        
        DnsDbSearch(&priv->ip_d, FT_IPv6, dns, ESP_CA_FILENAME_PATH_SIZE);
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

        DnsDbSearch(&priv->ip_d, FT_IPv4, dns, ESP_CA_FILENAME_PATH_SIZE);
        GeoIPLocIP(&priv->ip_d, FT_IPv4, &latitude, &longitude, &cc);
    }
    
    PeiNewComponent(&cmpn, pei_dns_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, dns);
    PeiAddComponent(ppei, cmpn);

    PeiNewComponent(&cmpn, pei_port_src_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, "0");
    PeiAddComponent(ppei, cmpn);

    PeiNewComponent(&cmpn, pei_port_dst_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, "0");
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
}


static bool IpSecCaClientPkt(espca_priv *priv, packet *pkt)
{
    bool ret;
    ftval ip;
    enum ftype type;
    
    ret = FALSE;
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
    
    return ret;
}


static packet *IpSecDissector(int flow_id)
{
    packet *pkt;
    espca_priv priv;
    const pstack_f *esp, *ip;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    bool ipv4, clnt;
    unsigned int count;
    size_t flow_size;
    pei *ppei;
    time_t cap_sec, end_cap;
    
    LogPrintf(LV_DEBUG, "ESP Analysis id: %d", flow_id);

    memset(&priv, 0, sizeof(espca_priv));
    esp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(esp);
    priv.stack = esp;

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
    LogPrintf(LV_DEBUG, "\tSRC: %s", ips_str);
    LogPrintf(LV_DEBUG, "\tDST: %s", ipd_str);
    
    flow_size = 0;
    count = 0;
    ppei = NULL;
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
        /* create pei */
        PeiNew(&ppei, esp_ca_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, esp);
        cap_sec = pkt->cap_sec;
    }
    while (pkt != NULL) {
        clnt = IpSecCaClientPkt(&priv, pkt);
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
        /* extrac spi */
        //pkt->data
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    /* insert data */
    CaPei(ppei, "ESP", &priv, &cap_sec, &end_cap);
    /* insert pei */
    PeiIns(ppei);

    /* end */

    LogPrintf(LV_DEBUG, "ESP  analysis... bye bye  fid:%d count: %i", flow_id, count);

    return NULL;
}


static bool EspCaCheck(int flow_id)
{
    return TRUE;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&hdep, 0, sizeof(proto_heury_dep));

    /* protocol name */
    ProtName("ESP Analysis", "esp-ca");

    /* dep: IP */
    hdep.name = "esp";
    hdep.ProtCheck = EspCaCheck;
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

    /* dissectors registration */
    ProtDissectors(NULL, IpSecDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    /* info id */
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
    }
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
        ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    }
    esp_ca_id = ProtId("esp-ca");
    
    /* pei id */
    pei_ip_src_id = ProtPeiComptId(esp_ca_id, "ip.src");
    pei_ip_dst_id = ProtPeiComptId(esp_ca_id, "ip.dst");
    pei_dns_id = ProtPeiComptId(esp_ca_id, "dns");
    pei_port_src_id = ProtPeiComptId(esp_ca_id, "port.src");
    pei_port_dst_id = ProtPeiComptId(esp_ca_id, "port.dst");
    pei_l7protocol_id = ProtPeiComptId(esp_ca_id, "l7prot");
    pei_lat_id = ProtPeiComptId(esp_ca_id, "lat");
    pei_long_id = ProtPeiComptId(esp_ca_id, "long");
    pei_country_code_id = ProtPeiComptId(esp_ca_id, "country_code");
    pei_bsent_id = ProtPeiComptId(esp_ca_id, "byte.sent");
    pei_brecv_id = ProtPeiComptId(esp_ca_id, "byte.receiv");
    pei_blost_sent_id = ProtPeiComptId(esp_ca_id, "byte.lost.sent");
    pei_blost_recv_id = ProtPeiComptId(esp_ca_id, "byte.lost.receiv");
    pei_pkt_sent_id = ProtPeiComptId(esp_ca_id, "pkt.sent");
    pei_pkt_recv_id = ProtPeiComptId(esp_ca_id, "pkt.receiv");
    pei_trace_sent = ProtPeiComptId(esp_ca_id, "trace.sent");
    pei_trace_recv = ProtPeiComptId(esp_ca_id, "trace.receiv");
    pei_metadata = ProtPeiComptId(esp_ca_id, "metadata");
    pei_trace_img = ProtPeiComptId(esp_ca_id, "trace.img");

    return 0;
}
