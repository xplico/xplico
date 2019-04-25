/* dns.c
 * dns packet dissection
 * RFC 1034, RFC 1035
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: ettercap -- dissector DNS -- UDP 53
 *   Copyright ALoR & NaGA. Web http://ettercap.sourceforge.net/
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
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "dnsdb.h"
#include "dns.h"
#include "pei.h"
#include "geoiploc.h"


#define C_FLUSH    (1<<15)         /* High bit is set for MDNS cache flush */

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int tcp_port_src_id;
static int tcp_port_dst_id;
static int tcp_lost_id;
static int tcp_clnt_id;
static int udp_id;
static int udp_port_src_id;
static int udp_port_dst_id;
static int dns_id;

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


static void CaPei(pei *ppei, const char *prot_name, uca_priv *priv, time_t *cap_sec, time_t *end_cap)
{
    char val[DNS_FILENAME_PATH_SIZE];
    char dns[DNS_FILENAME_PATH_SIZE];
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
        
        DnsDbSearch(&priv->ip_d, FT_IPv6, dns, DNS_FILENAME_PATH_SIZE);
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

        DnsDbSearch(&priv->ip_d, FT_IPv4, dns, DNS_FILENAME_PATH_SIZE);
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

    if (cc != NULL) {
        PeiNewComponent(&cmpn, pei_country_code_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        cmpn->strbuf = cc;
        PeiAddComponent(ppei, cmpn);
    }

    sprintf(val, "%f", longitude);
    PeiNewComponent(&cmpn, pei_long_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);

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


static bool DnsCaClientPkt(uca_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, udp_port_src_id, &port);
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


static char *DnsEscape(char *cname)
{
    char *host, *esc;
    char esc_str[4];
    int len, esc_num, offset_a, offset_b; 

    len = strlen(cname);
    host = DMemMalloc(len + 1);
    memcpy(host, cname, len);
    host[len] = '\0';
    /* remove escepe chars */
    esc = strchr(host, '\\');
    offset_b = 0;
    while (esc != NULL) {
        esc_str[0] = esc[1];
        esc_str[1] = esc[2];
        esc_str[2] = esc[3];
        esc_str[3] = '\0';
        esc_num = atoi(esc_str);
        offset_a = esc - host;
        offset_b = offset_a + 4;
        if (isprint(esc_num)) {
            esc_str[0] = esc_num;
            offset_a += 1;
        }
        strcpy(host + offset_a, host + offset_b);
        esc = strchr(host, '\\');
    }
    if (offset_b)
        strcpy(cname, host);
    DMemFree(host);

    return cname;
}


static packet *DnsDissector(int flow_id)
{
    packet *pkt;
    uca_priv priv;
    const pstack_f *udp, *ip;
    dns_hdr *dns_h;
    char name[NS_MAXDNAME], dummy[NS_MAXDNAME], cname[NS_MAXDNAME];
    unsigned char *data, *end, *nxt;
    int name_len, len;
    short class;
    unsigned short type, i, dim, rdlen;
    ftval ipv, d_name, port, port_src, port_dst;
    pei *ppei;
    bool mdns = FALSE;
    unsigned long count;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    bool ipv4, clnt;
    const char *l7prot_type;
    time_t cap_sec, end_cap;
 
    LogPrintf(LV_DEBUG, "DNS id: %d", flow_id);
    ppei = NULL;
    count = 0;
    memset(&priv, 0, sizeof(uca_priv));
    udp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(udp);
    ProtGetAttr(udp, udp_port_src_id, &port_src);
    ProtGetAttr(udp, udp_port_dst_id, &port_dst);
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

    /* syncronise decoding */
    FlowSyncr(flow_id, TRUE);
    
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
        /* create pei */
        PeiNew(&ppei, dns_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, udp);
        cap_sec = pkt->cap_sec;
        ProtGetAttr(pkt->stk, udp_port_src_id, &port);
        if (port.uint16 == UDP_PORT_MDNS) {
            mdns = TRUE;
        }
        else {
            ProtGetAttr(pkt->stk, udp_port_dst_id, &port);
            if (port.uint16 == UDP_PORT_MDNS) {
                mdns = TRUE;
            }
        }
    }
    while (pkt != NULL) {
        end_cap = pkt->cap_sec;
        clnt = DnsCaClientPkt(&priv, pkt);
        count++;
        if (clnt) {
            priv.bsent += pkt->len;
            priv.pkt_sent++;
        }
        else {
            priv.breceiv += pkt->len;
            priv.pkt_receiv++;
        }
        if (pkt->len > sizeof(dns_hdr)) {
            dns_h = (dns_hdr *)pkt->data;
            cname[0] = '\0';
            /* we are interested only in DNS answer */
            if (dns_h->qr && dns_h->num_answer != 0 && dns_h->opcode == ns_o_query && dns_h->rcode == ns_r_noerror) {
                /* extract the name from the packet */
                data = (unsigned char *)(dns_h + 1);
                end = (unsigned char *)(pkt->data + pkt->len);
                nxt = data;
                name_len = 0;
                dim = htons(dns_h->num_q);
                for (i=0; i<dim; i++) {
                    if (nxt > end) {
                        LogPrintf(LV_WARNING, "DNS packet wrong [n:%lu]", count);
                        PktFree(pkt);
                        pkt = NULL;
                        return NULL;
                    }
                    if ((*nxt & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
                        nxt += 2;
                    }
                    else {
                        if (name_len == 0) {
                            name_len = dn_expand((unsigned char *)pkt->data, end, data, name, sizeof(name));
                            if (name_len != -1)
                                nxt += name_len;
                            else
                                name_len = 0;
                        }
                        else {
                            len = dn_expand((unsigned char *)pkt->data, end, nxt, dummy, sizeof(dummy));
                            if (len != -1)
                                nxt += len;
                            else
                                len = 0;
                        }
                    }
                    nxt += 4;
                }
                dim = htons(dns_h->num_answer);
                for (i=0; i<dim && (end - (nxt+12) >= 0); i++) {
                    if ((*nxt & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
                        nxt += 2;
                    }
                    else {
                        if (name_len == 0) {
                            name_len = dn_expand((unsigned char *)pkt->data, end, data, name, sizeof(name));
                            if (name_len != -1)
                                nxt += name_len;
                            else
                                name_len = 0;
                        }
                        else {
                            len = dn_expand((unsigned char *)pkt->data, end, nxt, dummy, sizeof(dummy));
                            if (len != -1)
                                nxt += len;
                            else
                                len = 0;
                        }
                    }
                    if (end - (nxt + 10) < 0) {
                        break;
                    }
                    type = htons(*(unsigned short *)nxt);
                    nxt += 2;
                    class = htons(*(unsigned short *)nxt);
                    if (mdns) {
                        class &= ~C_FLUSH;
                    }
                    nxt += 2;
                    nxt += 4; /* ttl */
                    rdlen = htons(*(unsigned short *)nxt);
                    nxt += 2;
                    if (class == ns_c_in) {
                        if (type == ns_t_a && rdlen == NS_INADDRSZ) {
                            ipv.int32 = *(unsigned int *)nxt;
                            name_len = strlen(name);
                            d_name.str = DMemMalloc(name_len + 1);
                            memcpy(d_name.str, name, name_len);
                            d_name.str[name_len] = '\0';
                            DnsEscape(d_name.str);
                            DnsDbInset(&d_name, FT_STRING, &ipv, FT_IPv4);
                        }
                        else if (type == ns_t_aaaa && rdlen == NS_IN6ADDRSZ) {
                            memcpy(ipv.ipv6, nxt, NS_IN6ADDRSZ);
                            name_len = strlen(name);
                            d_name.str = DMemMalloc(name_len + 1);
                            memcpy(d_name.str, name, name_len);
                            d_name.str[name_len] = '\0';
                            DnsEscape(d_name.str);
                            DnsDbInset(&d_name, FT_STRING, &ipv, FT_IPv6);
                        }
                        else if (type == ns_t_cname) {
                            name_len = dn_expand((unsigned char *)pkt->data, end, nxt, cname, sizeof(cname));
                            if (name_len == -1)
                                name_len = 0;
                        }
                    }
                    nxt += rdlen;
                }
            }
        }
        
        /* new packet */
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    if (mdns)
        l7prot_type = "MDNS";
    else
        l7prot_type = "DNS";
    /* insert data */
    CaPei(ppei, l7prot_type, &priv, &cap_sec, &end_cap);
    /* insert pei */
    PeiIns(ppei);
    
    LogPrintf(LV_DEBUG, "DNS count: %lu", count);
    
    return NULL;
}


static bool DnsPktTest(packet *pkt)
{
    dns_hdr *dns_h;
    unsigned char *data, *end, *nxt;
    int name_len, len;
    unsigned short i, dim;
    char name[NS_MAXDNAME], dummy[NS_MAXDNAME];

    dns_h = (dns_hdr *)pkt->data;
    /* extract the name from the packet */
    data = (unsigned char *)(dns_h + 1);
    end = (unsigned char *)(pkt->data + pkt->len);
    nxt = data;
    name_len = 0;
    dim = htons(dns_h->num_q);
    for (i=0; i!=dim; i++) {
        if (nxt > end) {
            return FALSE;
        }
        if ((*nxt & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
            nxt += 2;
        }
        else {
            if (name_len == 0) {
                name_len = dn_expand((unsigned char *)pkt->data, end, data, name, sizeof(name));
                if (name_len != -1)
                    nxt += name_len;
                else
                    name_len = 0;
            }
            else {
                len = dn_expand((unsigned char *)pkt->data, end, nxt, dummy, sizeof(dummy));
                if (len != -1)
                    nxt += len;
                else
                    len = 0;
            }
        }
        nxt += 4;
    }

    return TRUE;
}


static bool DnsVerifyCheck(int flow_id, bool check)
{
    packet *pkt;
    bool udp;
    bool ret;
    dns_hdr *dns_h;
    short cnt, cnt_lim;

    cnt = 0;
    udp = FALSE;
    ret = FALSE;
    pkt = FlowGetPktCp(flow_id);

    /* numer of packet to verify */
    if (FlowIsClose(flow_id) == TRUE)
        cnt_lim = FlowPktNum(flow_id);
    else
        cnt_lim = DNS_PKT_VER_LIMIT - 1;
    if (!check) {
        cnt_lim = 1;
    }
    
    if (pkt != NULL) {
        do {
            /* verify header and data... where posible */
            if (pkt->len < sizeof(dns_hdr))
                break;
            dns_h = (dns_hdr *)pkt->data;
            if (dns_h->opcode > 2)
                break;
            if (dns_h->unused != 0)
                break;
            if (dns_h->rcode > 5)
                break;
            if (DnsPktTest(pkt) == FALSE)
                break;
            cnt++;
            if (check == FALSE) {
                ret = TRUE;
                break;
            }
            else {
                if (dns_h->qr == 0) {
                    if (dns_h->num_answer != 0 || dns_h->num_q == 0)
                        break;
                }
                else if (dns_h->num_q == 0) {
                    break;
                }
                if (cnt == cnt_lim) {
                    ret = TRUE;
                    break;
                }
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
        } while (pkt != NULL);
    }
    
    if (pkt != NULL)
        PktFree(pkt);

    return ret;
}


static bool DnsVerify(int flow_id)
{
    return DnsVerifyCheck(flow_id, FALSE);
}


static bool DnsCheck(int flow_id)
{
    return DnsVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
    
    /* protocol name */
    ProtName("Domain Name Service", "dns-ca");
    
    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = UDP_PORT_DNS;
    dep.ProtCheck = DnsVerify;
    dep.pktlim = DNS_PKT_VER_LIMIT;
    ProtDep(&dep);
    dep.val.uint16 = UDP_PORT_MDNS;
    ProtDep(&dep);

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_DNS;
    dep.ProtCheck = DnsVerify;
    dep.pktlim = DNS_PKT_VER_LIMIT;
    /*ProtDep(&dep);*/
    dep.val.uint16 = TCP_PORT_MDNS;
    /*ProtDep(&dep);*/

    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = DnsCheck;
    hdep.pktlim = DNS_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = DnsCheck;
    hdep.pktlim = DNS_PKT_VER_LIMIT;
    /*ProtHeuDep(&hdep);*/

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

    /* dissectors registration */
    ProtDissectors(NULL, DnsDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    /* protocols and attributes */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    tcp_id = ProtId("tcp");
    tcp_port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    tcp_port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    tcp_lost_id = ProtAttrId(tcp_id, "tcp.lost");
    tcp_clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    udp_id = ProtId("udp");
    udp_port_dst_id = ProtAttrId(udp_id, "udp.dstport");
    udp_port_src_id = ProtAttrId(udp_id, "udp.srcport");
    dns_id = ProtId("dns-ca");

    /* pei id */
    pei_ip_src_id = ProtPeiComptId(dns_id, "ip.src");
    pei_ip_dst_id = ProtPeiComptId(dns_id, "ip.dst");
    pei_dns_id = ProtPeiComptId(dns_id, "dns");
    pei_port_src_id = ProtPeiComptId(dns_id, "port.src");
    pei_port_dst_id = ProtPeiComptId(dns_id, "port.dst");
    pei_l7protocol_id = ProtPeiComptId(dns_id, "l7prot");
    pei_lat_id = ProtPeiComptId(dns_id, "lat");
    pei_long_id = ProtPeiComptId(dns_id, "long");
    pei_country_code_id = ProtPeiComptId(dns_id, "country_code");
    pei_bsent_id = ProtPeiComptId(dns_id, "byte.sent");
    pei_brecv_id = ProtPeiComptId(dns_id, "byte.receiv");
    pei_blost_sent_id = ProtPeiComptId(dns_id, "byte.lost.sent");
    pei_blost_recv_id = ProtPeiComptId(dns_id, "byte.lost.receiv");
    pei_pkt_sent_id = ProtPeiComptId(dns_id, "pkt.sent");
    pei_pkt_recv_id = ProtPeiComptId(dns_id, "pkt.receiv");
    pei_trace_sent = ProtPeiComptId(dns_id, "trace.sent");
    pei_trace_recv = ProtPeiComptId(dns_id, "trace.receiv");

    return 0;
}
