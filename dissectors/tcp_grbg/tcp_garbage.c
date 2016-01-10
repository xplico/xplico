/* tcp_garbage.c
 * Dissector to group together packet of tcp flow that haven't a specific dissector
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include "tcp_garbage.h"
#include "dig.h"
#include "pei.h"
#include "pcap_gfile.h"

/* nDPI library */
#include "ndpi_main.h"
#include "ndpi_api.h"


#define GRB_FILE           0           /* to put (or not) data in to a pcap file */
#define GRB_CHECK_LOST     0           /* check lost data */
#define TCP_GRB_TMP_DIR    "tcp_grb"
#define NDPI_TICK_RES      1000        /* Hz */
#define GRB_DIG_ENABLE     1
#define GRB_TXT_ENABLE     1

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
static int tcp_grb_id;
static volatile int serial = 0;

/* pei id */
static int pei_l7protocol_id;
static int pei_txt_id;
static int pei_size_id;
static int pei_file_id;
static int pei_file_type_id;

static volatile unsigned int incr;
/* dig */
static volatile unsigned int incr_dig;
static unsigned short dig_type_dim;
static dig_file *dig_tbl;
static bool enable_dig;
/* ndpi */
static struct ndpi_detection_module_struct *ndpi = NULL;
static pthread_mutex_t ndpi_mux;  /* mutex to access the ndpi handler */
static unsigned int ndpi_flow_struct_size;
static unsigned int ndpi_proto_size;
static long limit_pkts;


static void *nDPImalloc(unsigned long size)
{
    return malloc(size);
}


static void nDPIfree(void *freeable)
{
    free(freeable);
}


static void nDPIPrintf(u_int32_t protocol, void *id_struct, ndpi_log_level_t log_level, const char *format, ...)
{
    return;
}


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
    when += pkt->cap_usec/1000;  /* (1000000 / NDPI_TICK_RES) */
    pthread_mutex_lock(&ndpi_mux);
    l7prot_id = ndpi_detection_process_packet(ndpi, l7flow, data, size, when, l7src, l7dst);
    pthread_mutex_unlock(&ndpi_mux);

    return l7prot_id;
}


static bool TcpGrbCheck(int flow_id)
{
    unsigned long pkt_num;

    pkt_num = FlowPktNum(flow_id);
    if (pkt_num > limit_pkts || (pkt_num > 0 && FlowIsClose(flow_id) == TRUE)) {
        return TRUE;
    }

    return FALSE;
}


static bool TcpGrbMajorityText(unsigned char *dat, unsigned int size)
{
    unsigned int perc, i, j;

    if (size == 0)
        return FALSE;
    
    perc = (size * TCP_GRB_PERCENTAGE)/100;
    
    j = 0;
    for (i=0; i!=size && j!=perc; i++) {
        if (0x1F<dat[i] && dat[i]<0x7F)
            j++;
    }
    if (j == perc)
        return TRUE;
    
    return FALSE;
}


static void TcpGrbText(FILE *fp, unsigned char *dat, unsigned int size)
{
    unsigned int i, j;
    
    j = 0;
    for (i=0; i!=size; i++) {
        if (dat[i] < 0x7F)
            dat[j++] = dat[i];
    }
    fwrite(dat, 1, j, fp);
}


static void GrbPei(pei *ppei, const char *prot_name, size_t size, char *txt_file, time_t *cap_sec, time_t *end_cap)
{
    char val[TCP_GRB_FILENAME_PATH_SIZE];
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


static int GrbDigPei(dig *dig_srch, const pstack_f *tcp)
{
    pei *ppei;
    pei_component *cmpn;

    PeiNew(&ppei, tcp_grb_id);

    PeiCapTime(ppei, dig_srch->start_cap);
    PeiMarker(ppei, dig_srch->serial);
    PeiStackFlow(ppei, tcp);
    
    /* compose pei */
    PeiNewComponent(&cmpn, pei_file_id);
    PeiCompCapTime(cmpn, dig_srch->start_cap);
    PeiCompCapEndTime(cmpn, dig_srch->end_cap);
    PeiCompAddFile(cmpn, strrchr(dig_srch->filename, '/')+1, dig_srch->filename, dig_srch->fsize);
    PeiAddComponent(ppei, cmpn);

    PeiNewComponent(&cmpn, pei_file_type_id);
    PeiCompCapTime(cmpn, dig_srch->start_cap);
    PeiCompAddStingBuff(cmpn, dig_srch->ft->ename);
    PeiAddComponent(ppei, cmpn);

    /* insert pei */
    PeiIns(ppei);
    
    return 0;
}


/* from Scalpel Copyright (C) 2005-11 by Golden G. Richard III and */
static unsigned short TcpGrbDigConvert(char *pstr)
{
    char next;
    char *rd = pstr, *wr = pstr, *bad;
    char temp[1 + 3 + 1];
    char ch;
    
    if(!*rd) {			//If it's a null string just return
        return 0;
    }
    
    while (*rd) {
        // Is it an escaped character?
        if(*rd == '\\') {
            rd++;
            switch (*rd) {
            case '\\':
                rd++;
                *(wr++) = '\\';
                break;
                
            case 'a':
                rd++;
                *(wr++) = '\a';
                break;

            case 's':
                rd++;
                *(wr++) = ' ';
                break;

            case 'n':
                rd++;
                *(wr++) = '\n';
                break;

            case 'r':
                rd++;
                *(wr++) = '\r';
                break;

            case 't':
                rd++;
                *(wr++) = '\t';
                break;

            case 'v':
                rd++;
                *(wr++) = '\v';
                break;

            case '#':
                rd++;
                *(wr++) = '#';
                break;

                // Hexadecimal/Octal values are treated in one place using strtoul() 
            case 'x':
            case '0':
            case '1':
            case '2':
            case '3':
                next = *(rd + 1);
                if(next < 48 || (57 < next && next < 65) ||
                   (70 < next && next < 97) || next > 102)
                    break;		//break if not a digit or a-f, A-F 
                next = *(rd + 2);
                if(next < 48 || (57 < next && next < 65) ||
                   (70 < next && next < 97) || next > 102)
                    break;		//break if not a digit or a-f, A-F 
                
                temp[0] = '0';
                bad = temp;
                strncpy(temp + 1, rd, 3);
                temp[4] = '\0';
                ch = strtoul(temp, &bad, 0);
                if(*bad == '\0') {
                    *(wr++) = ch;
                    rd += 3;
                }			// else INVALID CHARACTER IN INPUT ('\\' followed by *rd) 
                break;

            default:		// INVALID CHARACTER IN INPUT (*rd)
                *(wr++) = '\\';
                break;
            }
        }
        // just copy un-escaped characters
        else {
            *(wr++) = *(rd++);
        }
    }
    *wr = '\0';			// null termination
    
    return wr - pstr;  
}


/* -1 nessuna fase, 0 in riconoscimento, 1 corrispondenza */
static int TcpGrbDigMatchStart(dig *state, packet *pkt)
{
    unsigned long i;
    unsigned fs, j, k, h;
    
    fs = state->fs;
    for (i=0; i!=pkt->len; i++) {
        if (pkt->data[i] == state->ft->start[fs]) {
            if (fs == 0) {
                state->pkt = pkt;
                state->pkt_offset = i;
            }
            fs++;
            if (fs == state->ft->slen) {
                /* match */
                state->fs = 0;
                
                return 1;
            }
        }
        else {
            if (fs != 0) {
                fs--;
                if (fs != 0) {
                    for (j=fs; j!=0; j--) {
                        if (state->ft->start[j] != pkt->data[i])
                            continue;
                        k = j;
                        h = fs;
                        while (k) {
                            k--;
                            if (state->ft->start[k] != state->ft->start[h])
                                break;
                            h--;
                        }
                        if (k == 0)
                            break;
                    }
                    if (j != 0)
                        fs = j + 1;
                    else
                        fs = 0;
                }
                else if (state->ft->start[0] == pkt->data[i]) {
                    fs = 1;
                }
            }
        }
    }
    state->fs = fs;
    if (fs != 0)
        return 0;
    return -1;
}


static int TcpGrbDigMatchEnd(dig *state, packet *pkt)
{
    unsigned long i;
    unsigned short fs, j, k, h;

    fs = state->fs;
    for (i=0; i!=pkt->len; i++) {
        if (pkt->data[i] == state->ft->end[fs]) {
            fs++;
            if (fs == state->ft->elen) {
                /* match */
                state->fs = 0;
                state->pkt = NULL;
                state->pkt_offset = i;
                
                return 1;
            }
        }
        else {
            if (fs != 0) {
                fs--;
                if (fs != 0) {
                    for (j=fs; j!=0; j--) {
                        if (state->ft->end[j] != pkt->data[i])
                            continue;
                        k = j;
                        h = fs;
                        while (k) {
                            k--;
                            if (state->ft->end[k] != state->ft->end[h])
                                break;
                            h--;
                        }
                        if (k == 0)
                            break;
                    }
                    if (j != 0)
                        fs = j + 1;
                    else
                        fs = 0;
                }
                else if (state->ft->end[0] == pkt->data[i]) {
                    fs = 1;
                }
            }
        }
    }
    state->fs = fs;
    if (fs != 0)
        return 0;
    return -1;
}


static bool TcpGrbClientPkt(tgrb_priv *priv, packet *pkt)
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


packet *TcpGrbDissector(int flow_id)
{
    packet *pkt, *opkt;
    tgrb_priv *priv;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, lost;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    bool ipv4;
    int dig_s, dig_d, *dig_x;
    int count, i, j, k;
    int threshold;
    bool txt_data;
    FILE *txt_fp;
    char txt_file[TCP_GRB_FILENAME_PATH_SIZE];
    unsigned char *thrs;
    pei *ppei;
    time_t cap_sec, end_cap;
#if GRB_FILE
    int fd_pcap;
    char filename[TCP_GRB_FILENAME_PATH_SIZE];
    int prot;
    struct pcap_file_header fh;
    struct pcappkt_hdr pckt_header;
#endif
    size_t flow_size;
    bool first_lost, dig_end;
    dig *dig_srch_a, *dig_srch_b, *dig_srch;
    char buff[TCP_CFG_LINE_MAX_SIZE];
    char *l7prot_type;
    struct ndpi_flow_struct *l7flow;
    struct ndpi_id_struct *l7src, *l7dst;
    ndpi_protocol l7prot_id;
    unsigned char stage;
    
    LogPrintf(LV_DEBUG, "TCP garbage id: %d", flow_id);

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
    
    /* dig init */
    dig_srch_a = dig_srch_b = NULL;
    if (enable_dig) {
        dig_s = dig_d = -1;
        dig_x = NULL;
        dig_srch_a = xmalloc(sizeof(dig) * dig_type_dim);
        dig_srch_b = xmalloc(sizeof(dig) * dig_type_dim);
        if (dig_srch_a != NULL && dig_srch_b != NULL) {
            memset(dig_srch_a, 0, sizeof(dig) * dig_type_dim);
            memset(dig_srch_b, 0, sizeof(dig) * dig_type_dim);
            for (i=0; i!=dig_type_dim; i++) {
                dig_srch_a[i].ft = &(dig_tbl[i]);
                dig_srch_b[i].ft = &(dig_tbl[i]);
                dig_srch_a[i].dig_sync = -1;
                dig_srch_b[i].dig_sync = -1;
            }
        }
        else {
            if (dig_srch_a != NULL)
                xfree(dig_srch_a);
            if (dig_srch_b != NULL)
                xfree(dig_srch_b);
            dig_srch_a = dig_srch_b = NULL;
        }
    }

    /* init */
    priv = DMemMalloc(sizeof(tgrb_priv));
    memset(priv, 0, sizeof(tgrb_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port_s = port_src.uint16;
    priv->port_d = port_dst.uint16;
    priv->stack = tcp;
    if (priv->port_s != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    ipv4 = FALSE;
    first_lost = FALSE;
    stage = 0;
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
    sprintf(filename, "%s/tcp_%d_grb_%s_%s.pcap", ProtTmpDir(), serial, ips_str, ipd_str);
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
    opkt = pkt = NULL;
    ppei = NULL;
    txt_data = FALSE;
    txt_fp = NULL;
    threshold = 0;
#if GRB_TXT_ENABLE
    thrs = xmalloc(TCP_GRB_THRESHOLD+1);
#else
    thrs = NULL;
#endif
    do {
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == FALSE) {
                /* create pei */
                PeiNew(&ppei, tcp_grb_id);
                PeiCapTime(ppei, pkt->cap_sec);
                PeiMarker(ppei, pkt->serial);
                PeiStackFlow(ppei, tcp);
                cap_sec = pkt->cap_sec;
                end_cap = pkt->cap_sec;
                break;
            }
            else {
                first_lost = TRUE;
            }
        }
    } while (pkt != NULL);
    while (pkt != NULL) {
        flow_size += pkt->len;
        //ProtStackFrmDisp(pkt->stk, TRUE);
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            count++;
            end_cap = pkt->cap_sec;
            /* protocol type -ndpi- */
            if (stage != 4 && (l7prot_type == NULL || l7prot_id.master_protocol == NDPI_PROTOCOL_HTTP) && l7flow != NULL) {
                if (TcpGrbClientPkt(priv, pkt)) {
                    l7prot_id = nDPIPacket(pkt, l7flow, l7src, l7dst, ipv4);
                }
                else {
                    l7prot_id = nDPIPacket(pkt, l7flow, l7dst, l7src, ipv4);
                }
                if (l7prot_id.protocol != NDPI_PROTOCOL_UNKNOWN) {
                    stage++;
                    l7prot_type = ndpi_protocol2name(ndpi, l7prot_id, buff, TCP_CFG_LINE_MAX_SIZE);
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
        }
        else {
#if GRB_FILE || GRB_CHECK_LOST
            LogPrintf(LV_WARNING, "Packet Lost (size:%lu)", pkt->len);
            ProtStackFrmDisp(pkt->stk, TRUE);
#endif
        }
        if (thrs != NULL) {
            /* check stream to find text */
            if (lost.uint8 == FALSE && pkt->len != 0) {
                if (threshold + pkt->len >= TCP_GRB_THRESHOLD) {
                    if (txt_data == FALSE) {
                        /* text flow */
                        txt_data = TcpGrbMajorityText(thrs, threshold);
                        if (txt_data == FALSE) {
                            xfree(thrs);
                            thrs = NULL;
                            threshold = 0;
                        }
                        else {
                            sprintf(txt_file, "%s/%s/tcp_grb_%lu_%p_%i.txt", ProtTmpDir(), TCP_GRB_TMP_DIR, time(NULL), txt_file, incr++);
                            txt_fp = fopen(txt_file, "w");
                            if (txt_fp != NULL) {
                                TcpGrbText(txt_fp, thrs, threshold);
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
                        TcpGrbText(txt_fp, thrs, threshold);
                        threshold = 0;
                        if (pkt->len > TCP_GRB_THRESHOLD) {
                            TcpGrbText(txt_fp, (unsigned char *)pkt->data, pkt->len);
                        }
                        else {
                            memcpy(thrs+threshold, pkt->data,  pkt->len);
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
        }

        /* dig */
        if (dig_srch_a != NULL && pkt->len != 0) {
            if (TcpGrbClientPkt(priv, pkt)) {
                dig_srch = dig_srch_a;
                dig_x = &dig_s;
            }
            else {
                dig_srch = dig_srch_b;
                dig_x = &dig_d;
            }

            for (i=0; i!=dig_type_dim; i++) {
#if 0
                if (*dig_x != -1 && *dig_x != dig_srch[i].dig_sync)
                    continue;
#endif
                bool nmatch = FALSE;
                do {
                    if (dig_srch[i].head == FALSE) {
                        if (lost.uint8 == FALSE && (nmatch == TRUE || TcpGrbDigMatchStart(&(dig_srch[i]), pkt) == 1)) {
                            nmatch = FALSE;
                            *dig_x = i;
                            dig_srch[i].head = TRUE;
                            dig_srch[i].dig_sync = i;
                            dig_srch[i].start_cap = pkt->cap_sec;
                            dig_srch[i].serial = pkt->serial;
                            j = 0;
                            k = dig_srch[i].ft->end_id[0];
                            while (k != -1) {
                                dig_srch[k].head = TRUE;
                                dig_srch[k].dig_sync = i;
                                j++;
                                k = dig_srch[i].ft->end_id[j];
                            }
                            /* save file */
                            sprintf(dig_srch[i].filename, "%s/%s/file_%lu%i.%s", ProtTmpDir(), TCP_GRB_TMP_DIR, time(NULL), incr_dig++, dig_srch[i].ft->ename);
                            LogPrintf(LV_DEBUG, "File %s found (%s)", dig_srch[i].ft->ename, dig_srch[i].filename);
                            dig_srch[i].fp = fopen(dig_srch[i].filename, "wb");
                            if (dig_srch[i].fp != NULL) {
                                if (pkt == dig_srch[i].pkt) {
                                    //ProtStackFrmDisp(pkt->stk, TRUE);
                                    dig_srch[i].fsize = pkt->len - dig_srch[i].pkt_offset;
                                    fwrite(pkt->data + dig_srch[i].pkt_offset, 1, dig_srch[i].fsize, dig_srch[i].fp);
                                }
                                else {
                                    if (opkt == dig_srch[i].pkt) {
                                        //ProtStackFrmDisp(pkt->stk, TRUE);
                                        dig_srch[i].fsize = opkt->len - dig_srch[i].pkt_offset;
                                        fwrite(opkt->data + dig_srch[i].pkt_offset, 1, dig_srch[i].fsize, dig_srch[i].fp);
                                    }
                                    else {
                                        LogPrintf(LV_ERROR, "Improve dig code");
                                    }
                                    fwrite(pkt->data, 1, pkt->len, dig_srch[i].fp);
                                    dig_srch[i].fsize = pkt->len;
                                }
                            }
                            dig_srch[i].pkt_offset = 0;
                            dig_srch[i].pkt = NULL;
                        }
                    }
                    else {
                        dig_end = FALSE;
                        if (lost.uint8 == FALSE) {
                            if (dig_srch[i].ft->elen != 0) {
                                if (TcpGrbDigMatchEnd(&(dig_srch[i]), pkt) == 1) {
                                    ProtStackFrmDisp(pkt->stk, TRUE);
                                    dig_end = TRUE;
                                    k = dig_srch[i].dig_sync;
                                    dig_srch[k].fsize += dig_srch[i].pkt_offset + 1;
                                    if (dig_srch[k].fp != NULL) {
                                        fwrite(pkt->data, 1, dig_srch[i].pkt_offset + 1, dig_srch[k].fp);
                                        fclose(dig_srch[k].fp);
                                    }
                                    dig_srch[i].pkt_offset = 0;
                                    dig_srch[i].pkt = NULL;
                                }
                                if (dig_srch[i].ft->stend == TRUE) {
                                    if (TcpGrbDigMatchStart(&(dig_srch[i]), pkt) == 1) {
                                        dig_end = TRUE;
                                        nmatch = TRUE;
                                        k = dig_srch[i].dig_sync;
                                        dig_srch[k].fsize += dig_srch[i].pkt_offset;
                                        if (dig_srch[k].fp != NULL) {
                                            fwrite(pkt->data, 1, dig_srch[i].pkt_offset, dig_srch[k].fp);
                                            fclose(dig_srch[k].fp);
                                        }
                                    }
                                }
                            }
                            if (dig_end == FALSE) {
                                if (dig_srch[i].fsize + pkt->len >= dig_srch[i].ft->msize) {
                                    dig_end = TRUE;
                                    k = dig_srch[i].dig_sync;
                                    if (dig_srch[k].fp != NULL) {
                                        if (lost.uint8 == FALSE)
                                            fwrite(pkt->data, 1, dig_srch[i].ft->msize - dig_srch[i].fsize, dig_srch[k].fp);
                                        fclose(dig_srch[k].fp);
                                        dig_srch[k].fsize = dig_srch[i].ft->msize;
                                    }
                                }
                            }
                            if (dig_end == TRUE) {
                                dig_srch[i].head = FALSE;
                                *dig_x = -1;
                                j = 0;
                                k = dig_srch[i].ft->end_id[0];
                                while (k != -1) {
                                    dig_srch[k].head = FALSE;
                                    if (k != i) {
                                        dig_srch[k].fs = 0;
                                        dig_srch[k].dig_sync = -1;
                                    }
                                    j++;
                                    k = dig_srch[i].ft->end_id[j];
                                }
                                k = dig_srch[i].dig_sync;
                                
                                dig_srch[i].fs = 0;
                                dig_srch[i].dig_sync = -1;
                                LogPrintf(LV_DEBUG, "End file %s (%s)", dig_srch[i].ft->ename, dig_srch[k].filename);
                                dig_srch[k].end_cap = pkt->cap_sec;

                                GrbDigPei(&dig_srch[k], tcp);
                                dig_srch[k].fsize = 0;
                                dig_srch[k].fp = NULL;
                                dig_srch[k].filename[0] = '\0';
                            }
                            else if (i == dig_srch[i].dig_sync) {
                                dig_srch[i].fsize += pkt->len;
                                if (dig_srch[i].fp != NULL) {
                                    if (lost.uint8 == FALSE)
                                        fwrite(pkt->data, 1, pkt->len, dig_srch[i].fp);
                                    else {
                                        char *zero;
                                        zero = xmalloc(pkt->len);
                                        if (zero != NULL) {
                                            memset(zero, 0, pkt->len);
                                            fwrite(zero, 1, pkt->len, dig_srch[i].fp);
                                            xfree(zero);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } while(nmatch == TRUE);
            }
        }
        
        if (opkt != NULL)
            PktFree(opkt);
        opkt = pkt;
        pkt = FlowGetPkt(flow_id);
    }
    if (opkt != NULL) {
        PktFree(opkt);
        opkt = NULL;
    }
    
    /* text flows */
    if (thrs != NULL) {
        if (txt_data == FALSE) {
            /* text flow */
            if (TcpGrbMajorityText(thrs, threshold) == TRUE) {
                sprintf(txt_file, "%s/%s/tcp_grb_%lu_%p_%i.txt", ProtTmpDir(), TCP_GRB_TMP_DIR, time(NULL), txt_file, incr++);
                txt_fp = fopen(txt_file, "w");
            }
        }
        if (txt_fp != NULL) {
            TcpGrbText(txt_fp, thrs, threshold);
        }
        xfree(thrs);
    }
    
    /* ndpi free */
    if (l7flow != NULL) {
        xfree(l7flow);
        xfree(l7src);
        xfree(l7dst);
    }
    if (l7prot_type == NULL)
        l7prot_type = "Unknown";

    /* dig flow */
    for (i=0; i!=dig_type_dim; i++) {
        if (dig_srch_a[i].head == TRUE) {
            if (i == dig_srch_a[i].dig_sync) {
                if (dig_srch_a[i].fp != NULL)
                    fclose(dig_srch_a[i].fp);
                LogPrintf(LV_DEBUG, "End stream of file %s", dig_srch_a[i].ft->ename);
                dig_srch_a[i].end_cap = end_cap;
                GrbDigPei(&dig_srch_a[i], tcp);
                dig_srch_a[i].fsize = 0;
                dig_srch_a[i].fp = NULL;
                dig_srch_a[i].filename[0] = '\0';
            }
        }
        if (dig_srch_b[i].head == TRUE) {
            if (i == dig_srch_b[i].dig_sync) {
                if (dig_srch_b[i].fp != NULL)
                    fclose(dig_srch_b[i].fp);
                LogPrintf(LV_DEBUG, "End stream of file %s", dig_srch_b[i].ft->ename);
                dig_srch_b[i].end_cap = end_cap;
                GrbDigPei(&dig_srch_b[i], tcp);
                dig_srch_b[i].fsize = 0;
                dig_srch_b[i].fp = NULL;
                dig_srch_b[i].filename[0] = '\0';
            }
        }
        
    }
    /* tcp reset */
    if (first_lost && (count < 5 || flow_size == 0)) {
        if (txt_fp != NULL) {
            fclose(txt_fp);
            remove(txt_file);
            txt_fp = NULL;
        }
    }
    else {
        if (txt_fp != NULL) {
            fclose(txt_fp);
            /* insert data */
            GrbPei(ppei, l7prot_type, flow_size, txt_file, &cap_sec, &end_cap);
            /* insert pei */
            PeiIns(ppei);
        }
        else  {
            /* insert data */
            GrbPei(ppei, l7prot_type, flow_size, NULL, &cap_sec, &end_cap);
            /* insert pei */
            PeiIns(ppei);
        }
    }
    /* end */
#if GRB_FILE
    if (fd_pcap != -1)
        close(fd_pcap);
#endif

    if (dig_srch_a != NULL) {
        xfree(dig_srch_a);
        xfree(dig_srch_b);
    }
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "TCP->%s garbage... bye bye  fid:%d count:%i", l7prot_type, flow_id, count);

    return NULL;
}

const int TcpGrbCfg(const char *cfg)
{
    FILE *fp;
    int i, j, ks, res;
    unsigned long size;
    char buffer[TCP_CFG_LINE_MAX_SIZE];
    char type[TCP_CFG_LINE_MAX_SIZE];
    char conc[TCP_CFG_LINE_MAX_SIZE];
    char stend[TCP_CFG_LINE_MAX_SIZE];
    char header[TCP_CFG_LINE_MAX_SIZE];
    char footer[TCP_CFG_LINE_MAX_SIZE];
    char *param;

    fp = fopen(cfg, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Opening file %s", cfg);
        return -1;
    }

    j = 0;
    dig_tbl = xmalloc(sizeof(dig_file));
    memset(dig_tbl, 0, sizeof(dig_file));
    while (fgets(buffer, TCP_CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParamIsComment(buffer)) {
            param = buffer;
            while (param[0] == ' ')
                param++;
            if (param[0] != '\0') {
                res = sscanf(param, "%s %s %s %lu %s %s", type, conc, stend, &size, header, footer);
                if (res > 4) {
                    strncpy(dig_tbl[j].ename, type, TCP_GRB_FILE_EXT_SIZE);
                    dig_tbl[j].msize = size;
                    if (header[0] == '/')
                        dig_tbl[j].sreg = TRUE;
                    else
                        dig_tbl[j].sreg = FALSE;
                    dig_tbl[j].starttxt = xmalloc(strlen(header) + 1);
                    strcpy(dig_tbl[j].starttxt, header);
                    if (res == 6) {
                        if (footer[0] == '/')
                            dig_tbl[j].ereg = TRUE;
                        else
                            dig_tbl[j].ereg = FALSE;
                        dig_tbl[j].endtxt = xmalloc(strlen(footer) + 1);
                        strcpy(dig_tbl[j].endtxt, footer);
                    }
                    else {
                        dig_tbl[j].ereg = FALSE;
                        dig_tbl[j].endtxt = NULL;
                    }
                    for (i=0; i!=TG_MULTI_END_NUM; i++) {
                        dig_tbl[j].end_id[i] = -1;
                    }

                    if (stend[0] == 'y')
                        dig_tbl[j].stend = TRUE;
                    else
                        dig_tbl[j].stend = FALSE;
                    
                    if (conc[0] == '.')
                        ks = j;
                    else {
                        for (i=0; i!=TG_MULTI_END_NUM; i++) {
                            if (dig_tbl[ks].end_id[i] == -1) {
                                if (i == 0) {
                                    dig_tbl[ks].end_id[0] = ks;
                                    dig_tbl[ks].end_id[1] = j;
                                }
                                else 
                                    dig_tbl[ks].end_id[i] = j;
                                break;
                            }
                        }
                        
                        for (i=ks+1; i<=j; i++) {
                            memcpy(dig_tbl[i].end_id, dig_tbl[ks].end_id, sizeof(dig_tbl[ks].end_id));
                        }
                    }
                    j++;
                    dig_type_dim++;
                    dig_tbl = xrealloc(dig_tbl, sizeof(dig_file)*(dig_type_dim + 1));
                    memset(&(dig_tbl[dig_type_dim]), 0, sizeof(dig_file));
                }
            }
        }
    }

    fclose(fp);

#if 0
    for (i=0; i!=dig_type_dim; i++) {
        printf("%s\n", dig_tbl[i].ename);
        for (j=0; j!=TG_MULTI_END_NUM; j++) {
            printf("-> %i ", dig_tbl[i].end_id[j]);
        }
        printf("\n");
    }
    exit(-1);
#endif

    return 0;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;
    char cfg[TCP_GRB_FILENAME_PATH_SIZE];

    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
 
    /* protocol name */
    ProtName("TCP garbage", "tcp-grb");

    /* dep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = TcpGrbCheck;
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

    peic.abbrev = "file";
    peic.desc = "File extracted";
    ProtPeiComponent(&peic);

    peic.abbrev = "ftype";
    peic.desc = "File type";
    ProtPeiComponent(&peic);
    
    dig_type_dim = 0;
    dig_tbl = NULL;
#if GRB_DIG_ENABLE
    enable_dig = TRUE;
#else
    enable_dig = FALSE;
#endif

    /* load config file data */
    if (CfgParamStr(file_cfg, TCP_GRB_CFG_FILE, cfg, TCP_GRB_FILENAME_PATH_SIZE) == 0)
        TcpGrbCfg(cfg);

    if (CfgParamInt(file_cfg, TCP_GRB_PKT_LIMIT_CFG, &limit_pkts) != 0)
        limit_pkts = TCP_GRB_PKT_LIMIT;
    if (enable_dig == FALSE)
        dig_type_dim = 0;
    
    /* dissectors subdissectors registration */
    ProtDissectors(NULL, TcpGrbDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tmp_dir[256];
    unsigned short i;
    NDPI_PROTOCOL_BITMASK all;

    /* part of file name */
    incr = 0;
    incr_dig = 0;

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
    }
    tcp_grb_id = ProtId("tcp-grb");
    
    /* pei id */
    pei_l7protocol_id = ProtPeiComptId(tcp_grb_id, "l7prot");
    pei_txt_id = ProtPeiComptId(tcp_grb_id, "txt");
    pei_size_id = ProtPeiComptId(tcp_grb_id, "size");
    pei_file_id = ProtPeiComptId(tcp_grb_id, "file");
    pei_file_type_id = ProtPeiComptId(tcp_grb_id, "ftype");

    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), TCP_GRB_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    /* init dig */
    if (enable_dig) {
        for (i=0; i!=dig_type_dim; i++) {
            if (!dig_tbl[i].sreg && dig_tbl[i].starttxt != NULL) {
                dig_tbl[i].start = strdup(dig_tbl[i].starttxt);
                if (dig_tbl[i].start == NULL) {
                    LogPrintf(LV_FATAL, "No memory!");
                    return -1;
                }
                dig_tbl[i].slen = TcpGrbDigConvert(dig_tbl[i].start);
            }
            if (!dig_tbl[i].ereg && dig_tbl[i].endtxt != NULL) {
                dig_tbl[i].end = strdup(dig_tbl[i].endtxt);
                if (dig_tbl[i].end == NULL) {
                    LogPrintf(LV_FATAL, "No memory!");
                    return -1;
                }
                dig_tbl[i].elen = TcpGrbDigConvert(dig_tbl[i].end);
            }
            //printf("File %s slen:%i elen: %i\n", dig_tbl[i].ename, dig_tbl[i].slen, dig_tbl[i].elen);
        }
    }

    /* ndpi */
    pthread_mutex_init(&ndpi_mux, NULL);
    ndpi = ndpi_init_detection_module(NDPI_TICK_RES, nDPImalloc, nDPIfree, nDPIPrintf);
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
