/* dns.c
 * dns packet dissection
 * RFC 1034, RFC 1035
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
static int pei_host_id;
static int pei_ip_id;
static int pei_cname_id;
static int pei_pkt_id;


static pei *DnsNewPei(int flow_id, packet *pkt)
{
    pei *mpei;

    /* create pei */
    PeiNew(&mpei, dns_id);
    PeiCapTime(mpei, pkt->cap_sec);
    PeiMarker(mpei, pkt->serial);
    PeiStackFlow(mpei, FlowStack(flow_id));
    
    return mpei;
}


static void DnsPeiHost(pei *ppei, char *name, int len)
{
    pei_component *cmpn;
    char *host;

    host = DMemMalloc(len + 1);
    memcpy(host, name, len);
    host[len] = '\0';

    /* new component */
    PeiNewComponent(&cmpn, pei_host_id);
    PeiCompCapTime(cmpn, ppei->time_cap);
    PeiCompAddStingBuff(cmpn, host);
    PeiAddComponent(ppei, cmpn);
    DMemFree(host);
}


static void DnsPeiIp(pei *ppei, ftval *ip, enum ftype itype)
{
    pei_component *cmpn;
    char *ips;

    ips = DMemMalloc(DNS_IP_STR_SIZE);
    FTString(ip, itype, ips);

    /* new component */
    PeiNewComponent(&cmpn, pei_ip_id);
    PeiCompCapTime(cmpn, ppei->time_cap);
    PeiCompAddStingBuff(cmpn, ips);
    PeiAddComponent(ppei, cmpn);
    DMemFree(ips);
}


static void DnsPeiId(pei *ppei, unsigned short id)
{
    pei_component *cmpn;
    char *ids;

    ids = DMemMalloc(10);
    sprintf(ids, "%i", id);

    /* new component */
    PeiNewComponent(&cmpn, pei_pkt_id);
    PeiCompCapTime(cmpn, ppei->time_cap);
    PeiCompAddStingBuff(cmpn, ids);
    PeiAddComponent(ppei, cmpn);
    DMemFree(ids);
}


static void DnsPeiCname(pei *ppei, const char *cname)
{
    pei_component *cmpn;
    char *host, *esc;
    char esc_str[4];
    int len, esc_num, offset_a, offset_b;

    len = strlen(cname);
    host = DMemMalloc(len + 1);
    memcpy(host, cname, len);
    host[len] = '\0';
    /* remove escepe chars */
    esc = strchr(host, '\\');
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
    
    /* new component */
    PeiNewComponent(&cmpn, pei_cname_id);
    PeiCompCapTime(cmpn, ppei->time_cap);
    PeiCompAddStingBuff(cmpn, host);
    PeiAddComponent(ppei, cmpn);
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
    dns_hdr *dns_h;
    char name[NS_MAXDNAME], dummy[NS_MAXDNAME], cname[NS_MAXDNAME];
    unsigned char *data, *end, *nxt;
    int name_len, len;
    short class;
    unsigned short type, i, dim, rdlen;
    ftval ip, d_name, port;
    pei *ppei;
    bool mdns = FALSE;
    unsigned long count;

    LogPrintf(LV_DEBUG, "DNS id: %d", flow_id);
    ppei = NULL;
    count = 0;

    /* syncronise decoding */
    FlowSyncr(flow_id, TRUE);
    
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
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
        count++;
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
                if (dim != 0) {
                    ppei = DnsNewPei(flow_id, pkt);
                    if (ppei != NULL && name_len > 0)
                        DnsPeiHost(ppei, name, name_len);
                }
                dim = htons(dns_h->num_answer);
                for (i=0; i<dim && (end - (nxt+12) >= 0); i++) {
                    if ((*nxt & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
                        nxt += 2;
                    }
                    else {
                        if (name_len == 0) {
                            name_len = dn_expand((unsigned char *)pkt->data, end, data, name, sizeof(name));
                            if (name_len != -1) {
                                nxt += name_len;
                                if (ppei == NULL) {
                                    ppei = DnsNewPei(flow_id, pkt);
                                }
                                if (ppei != NULL)
                                    DnsPeiHost(ppei, name, name_len);
                            }
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
                            ip.int32 = *(unsigned int *)nxt;
                            name_len = strlen(name);
                            d_name.str = DMemMalloc(name_len + 1);
                            memcpy(d_name.str, name, name_len);
                            d_name.str[name_len] = '\0';
                            DnsEscape(d_name.str);
                            DnsDbInset(&d_name, FT_STRING, &ip, FT_IPv4);
                            if (ppei != NULL) {
                                DnsPeiIp(ppei, &ip, FT_IPv4);
                                DnsPeiId(ppei, dns_h->id);
                            }
                        }
                        else if (type == ns_t_aaaa && rdlen == NS_IN6ADDRSZ) {
                            memcpy(ip.ipv6, nxt, NS_IN6ADDRSZ);
                            name_len = strlen(name);
                            d_name.str = DMemMalloc(name_len + 1);
                            memcpy(d_name.str, name, name_len);
                            d_name.str[name_len] = '\0';
                            DnsEscape(d_name.str);
                            DnsDbInset(&d_name, FT_STRING, &ip, FT_IPv6);
                            if (ppei != NULL) {
                                DnsPeiIp(ppei, &ip, FT_IPv6);
                                DnsPeiId(ppei, dns_h->id);
                            }
                        }
                        else if (type == ns_t_cname) {
                            name_len = dn_expand((unsigned char *)pkt->data, end, nxt, cname, sizeof(cname));
                            if (name_len != -1) {
                                if (ppei != NULL) {
                                    DnsPeiCname(ppei, cname);
                                    DnsPeiId(ppei, dns_h->id);
                                }
                            }
                            else
                                name_len = 0;
                        }
                    }
                    nxt += rdlen;
                }
            }
            if (ppei != NULL) {
                PeiIns(ppei);
            }
            ppei = NULL;
        }
        
        /* new packet */
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
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
    ProtName("Domain Name Service", "dns");
    
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
    peic.abbrev = "id";
    peic.desc = "Transaction ID";
    ProtPeiComponent(&peic);

    peic.abbrev = "host";
    peic.desc = "Host name";
    ProtPeiComponent(&peic);

    peic.abbrev = "ip";
    peic.desc = "IPv4/IPv6 string format";
    ProtPeiComponent(&peic);

    peic.abbrev = "cname";
    peic.desc = "Canonical name for an alias";
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
    dns_id = ProtId("dns");

    /* pei id */
    pei_host_id = ProtPeiComptId(dns_id, "host");
    pei_ip_id = ProtPeiComptId(dns_id, "ip");
    pei_cname_id = ProtPeiComptId(dns_id, "cname");
    pei_pkt_id = ProtPeiComptId(dns_id, "id");

    return 0;
}
