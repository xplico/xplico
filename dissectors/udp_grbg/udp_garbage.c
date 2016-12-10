/* udp_garbage.c
 * Dissector to group together packet of udp flow that haven't a specific dissector
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include "config_file.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "dnsdb.h"
#include "udp_garbage.h"
#include "pei.h"
#include "pcap_gfile.h"

/* nDPI library */
#include <libndpi/ndpi_main.h>
#include <libndpi/ndpi_api.h>
#include <libndpi/ndpi_typedefs.h>

#define GRB_FILE           0  /* to put (or not) data in to a file */
#define UDP_GRB_TMP_DIR    "udp_grb"
#define NDPI_TICK_RES      1000        /* Hz */
#define GRB_TXT_ENABLE     1

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
static int udp_grb_id;
static volatile int serial = 0;

/* pei id */
static int pei_l7protocol_id;
static int pei_txt_id;
static int pei_size_id;

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

static bool UdpGrbCheck(int flow_id)
{
    if (FlowPktNum(flow_id) > limit_pkts || FlowIsClose(flow_id) == TRUE) {
        return TRUE;
    }

    return FALSE;
}


static bool UdpGrbMajorityText(unsigned char *dat, unsigned int size)
{
    unsigned int perc, i, j;

    if (size == 0)
        return FALSE;

    perc = (size * UDP_GRB_PERCENTAGE)/100;
    
    j = 0;
    for (i=0; i!=size && j!=perc; i++) {
        if (0x1F<dat[i] && dat[i]<0x7F)
            j++;
    }
    if (j == perc)
        return TRUE;
    
    return FALSE;
}


static void UdpGrbText(FILE *fp, unsigned char *dat, unsigned int size)
{
    unsigned int i, j;
    
    j = 0;
    for (i=0; i!=size; i++) {
        if (dat[i]<0x7F)
            dat[j++] = dat[i];
    }
    fwrite(dat, 1, j, fp);
}


static void GrbPei(pei *ppei, const char *prot_name, size_t size, char *txt_file, time_t *cap_sec, time_t *end_cap)
{
    char val[UDP_GRB_FILENAME_PATH_SIZE];
    pei_component *cmpn;
    
    /* pei components */
    PeiNewComponent(&cmpn, pei_l7protocol_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, prot_name);
    PeiAddComponent(ppei, cmpn);
    
    if (txt_file != NULL) {
        PeiNewComponent(&cmpn, pei_txt_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompCapEndTime(cmpn, *end_cap);
        PeiCompAddFile(cmpn, "Text", txt_file, 0);
        PeiAddComponent(ppei, cmpn);
    }

    sprintf(val, "%zu", size);
    PeiNewComponent(&cmpn, pei_size_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, val);
    PeiAddComponent(ppei, cmpn);
}


static bool UdpGrbClientPkt(ugrb_priv *priv, packet *pkt)
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


packet* UdpGrbDissector(int flow_id)
{
    packet *pkt;
    ugrb_priv *priv;
    const pstack_f *udp, *ip;
    ftval port_src, port_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    bool ipv4;
    unsigned int count;
    int threshold;
    bool txt_data;
    FILE *txt_fp;
    char txt_file[UDP_GRB_FILENAME_PATH_SIZE];
    unsigned char *thrs;
    pei *ppei;
    time_t cap_sec, end_cap;
#if GRB_FILE
    int fd_pcap;
    char filename[256];
    int prot;
    struct pcap_file_header fh;
    struct pcappkt_hdr pckt_header;
#endif
    size_t flow_size;
    char buff[UDP_CFG_LINE_MAX_SIZE];
    char *l7prot_type;
    struct ndpi_flow_struct *l7flow;
    struct ndpi_id_struct *l7src, *l7dst;
    ndpi_protocol l7prot_id;

    LogPrintf(LV_DEBUG, "UDP garbage id: %d", flow_id);

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
    priv = DMemMalloc(sizeof(ugrb_priv));
    memset(priv, 0, sizeof(ugrb_priv));
    udp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(udp);
    ProtGetAttr(udp, port_src_id, &port_src);
    ProtGetAttr(udp, port_dst_id, &port_dst);
    priv->port_s = port_src.uint16;
    priv->port_d = port_dst.uint16;
    priv->stack = udp;
    if (priv->port_s != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    ipv4 = FALSE;
    if (ProtFrameProtocol(ip) == ip_id) {
        ipv4 = TRUE;
        priv->ipv6 = FALSE;
    }
    if (ipv4) {
        ProtGetAttr(ip, ip_src_id, &priv->ip_s);
        ProtGetAttr(ip, ip_dst_id, &priv->ip_d);
        ip_addr.s_addr = priv->ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv->ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &priv->ip_d);
        memcpy(ipv6_addr.s6_addr, priv->ip_s.ipv6, sizeof(priv->ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv->ip_d.ipv6, sizeof(priv->ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);    
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    /* file pcap */
#if GRB_FILE
    sprintf(filename, "%s/udp_%d_grb_%s_%s.pcap", ProtTmpDir(), serial, ips_str, ipd_str);
    serial++;
    fd_pcap = open(filename, O_WRONLY | O_CREAT, 0x01B6);
    memset(&fh, 0, sizeof(struct pcap_file_header));
    fh.magic = 0xA1B2C3D4;
    fh.version_major = PCAP_VERSION_MAJOR;
    fh.version_minor = PCAP_VERSION_MINOR;
    fh.snaplen = 65535;
    if (ProtGetNxtFrame(ip) != NULL) {
        prot = ProtFrameProtocol(ProtGetNxtFrame(ip));
        if (prot == eth_id)
            fh.linktype = DLT_EN10MB;
        else if (prot == ppp_id)
            fh.linktype = DLT_PPP;
        else
            fh.linktype = DLT_RAW;
    }
    if (fd_pcap != -1)
        write(fd_pcap, (char *)&fh, sizeof(struct pcap_file_header));
#endif
    
    l7prot_type = NULL;
    flow_size = 0;
    count = 0;
    ppei = NULL;
    txt_data = FALSE;
    txt_fp = NULL;
    threshold = 0;
#if GRB_TXT_ENABLE
    thrs = xmalloc(UDP_GRB_THRESHOLD);
#else
    thrs = NULL;
#endif
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
        /* create pei */
        PeiNew(&ppei, udp_grb_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, udp);
        cap_sec = pkt->cap_sec;
    }
    while (pkt != NULL) {
        count++;
        flow_size += pkt->len;
        end_cap = pkt->cap_sec;
        /* protocol type -ndpi- */
        if (l7prot_type == NULL && l7flow != NULL) {
            if (UdpGrbClientPkt(priv, pkt)) {
                l7prot_id = nDPIPacket(pkt, l7flow, l7src, l7dst, ipv4);
            }
            else {
                l7prot_id = nDPIPacket(pkt, l7flow, l7dst, l7src, ipv4);
            }
            if (l7prot_id.protocol != NDPI_PROTOCOL_UNKNOWN) {
                l7prot_type = ndpi_protocol2name(ndpi, l7prot_id, buff, UDP_CFG_LINE_MAX_SIZE);
            }
        }
#if GRB_FILE
        pckt_header.caplen = pkt->raw_len;
        pckt_header.len = pkt->raw_len;
        pckt_header.tv_sec = pkt->cap_sec;
        pckt_header.tv_usec = pkt->cap_usec;
        if (fd_pcap != -1) {
            write(fd_pcap, (char *)&pckt_header, sizeof(struct pcappkt_hdr));
            write(fd_pcap, (char *)pkt->raw, pkt->raw_len);
        }
#endif
        if (thrs != NULL) {
            /* check stream to find text */
            if (threshold + pkt->len >= UDP_GRB_THRESHOLD) {
                if (txt_data == FALSE) {
                    /* text flow */
                    txt_data = UdpGrbMajorityText(thrs, threshold);
                    if (txt_data == FALSE) {
                        xfree(thrs);
                        thrs = NULL;
                        threshold = 0;
                    }
                    else {
                        sprintf(txt_file, "%s/%s/udp_grb_%lu_%p_%i.txt", ProtTmpDir(), UDP_GRB_TMP_DIR, time(NULL), txt_file, incr++);
                        txt_fp = fopen(txt_file, "w");
                        if (txt_fp != NULL) {
                            UdpGrbText(txt_fp, thrs, threshold);
                            threshold = 0;
                            memcpy(thrs+threshold, pkt->data,  pkt->len);
                            threshold += pkt->len;
                            thrs[threshold] = '\0';
                        }
                        else {
                            LogPrintf(LV_ERROR, "Unable to open file: %s", txt_file);
                            txt_data = FALSE;
                            xfree(thrs);
                            thrs = NULL;
                            threshold = 0;
                        }
                    }
                }
                else {
                    UdpGrbText(txt_fp, thrs, threshold);
                    threshold = 0;
                    if (pkt->len > UDP_GRB_THRESHOLD) {
                        UdpGrbText(txt_fp, (unsigned char *)pkt->data, pkt->len);
                    }
                    else {
                        memcpy(thrs+threshold, pkt->data, pkt->len);
                        threshold += pkt->len;
                    }
                    thrs[threshold] = '\0';
                }
            }
            else {
                memcpy(thrs+threshold, pkt->data,  pkt->len);
                threshold += pkt->len;
                thrs[threshold] = '\0';
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    if (thrs != NULL) {
        if (txt_data == FALSE) {
            if (UdpGrbMajorityText(thrs, threshold) == TRUE) {
                sprintf(txt_file, "%s/%s/udp_grb_%lu_%p_%i.txt", ProtTmpDir(), UDP_GRB_TMP_DIR, time(NULL), txt_file, incr++);
                txt_fp = fopen(txt_file, "w");
            }
        }
        if (txt_fp != NULL) {
            UdpGrbText(txt_fp, thrs, threshold);
        }
        xfree(thrs);
    }
    /* ndpi free */
    if (l7flow != NULL) {
        xfree(l7flow);
        xfree(l7src);
        xfree(l7dst);
        l7flow = NULL;
    }
    if (l7prot_type == NULL)
        l7prot_type = "Unknown";

    if (txt_fp != NULL) {
        fclose(txt_fp);
        /* insert data */
        GrbPei(ppei, l7prot_type, flow_size, txt_file, &cap_sec, &end_cap);
        /* insert pei */
        PeiIns(ppei);
    }
    else {
        /* insert data */
        GrbPei(ppei, l7prot_type, flow_size, NULL, &cap_sec, &end_cap);
        /* insert pei */
        PeiIns(ppei);
    }

    /* end */
#if GRB_FILE
    if (fd_pcap != -1)
        close(fd_pcap);
#endif
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "UDP->%s  garbage... bye bye  fid:%d count: %i", l7prot_type, flow_id, count);

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* load config file data */
    if (CfgParamInt(file_cfg, UDP_GRB_PKT_LIMIT_CFG, &limit_pkts) != 0)
        limit_pkts = UDP_GRB_PKT_LIMIT;

    /* protocol name */
    ProtName("UDP garbage", "udp-grb");

    /* dep: ethernet */
    hdep.name = "udp";
    hdep.ProtCheck = UdpGrbCheck;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "l7prot";
    peic.desc = "L7 protocol march";
    ProtPeiComponent(&peic);

    peic.abbrev = "txt";
    peic.desc = "Text file";
    ProtPeiComponent(&peic);

    peic.abbrev = "size";
    peic.desc = "Flow total size";
    ProtPeiComponent(&peic);

    /* dissectors subdissectors registration */
    ProtDissectors(NULL, UdpGrbDissector, NULL, NULL);

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
    udp_grb_id = ProtId("udp-grb");
    
    /* pei id */
    pei_l7protocol_id = ProtPeiComptId(udp_grb_id, "l7prot");
    pei_txt_id = ProtPeiComptId(udp_grb_id, "txt");
    pei_size_id = ProtPeiComptId(udp_grb_id, "size");
    
    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), UDP_GRB_TMP_DIR);
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
