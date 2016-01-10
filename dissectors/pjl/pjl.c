/* pjl.c
 * PJL packet dissection
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "strutil.h"
#include "pei.h"
#include "pjl.h"

#define PJL_TMP_DIR    "pjl"

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int clnt_id;
static int pjl_id;

/* pei id */
static int pei_url_id;
static int pei_pdffile_id;
static int pei_pclfile_id;


static volatile unsigned int incr;
static char pcl6_path[] = "/opt/xplico/bin/pcl6";

static bool PjlClientPkt(pjl_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
        if (port.uint16 == priv->port)
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
        if (FTCmp(&priv->ip, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }

    /* first time, the verify function verify that first pkt is a client pkt */
    if (priv->dir == PJL_CLT_DIR_NONE) {
        if (ret == TRUE)
            priv->dir = PJL_CLT_DIR_OK;
        else {
            priv->dir = PJL_CLT_DIR_REVERS;
            ret = TRUE;
            LogPrintf(LV_WARNING, "Acqusition file have an error!");
            if (pkt != NULL)
                ProtStackFrmDisp(pkt->stk, TRUE);

        }
    }
    else {
        if (priv->dir == PJL_CLT_DIR_REVERS)
            ret = !ret;
    }
    
    return ret;
}


static int PjlConnec(int flow_id, pjl_priv *priv)
{
    pei *ppei;
    pei_component *cmpn;
    packet *pkt;
    ftval lost;
    bool err;
    int ind;
    ssize_t len;
    FILE *pcl;
    char cmd[PJL_FILENAME_PATH_SIZE*2];
    char *pcl_file, *pdf_file;
    unsigned long time_end;
    struct stat fst;

    pkt = FlowGetPkt(flow_id);
    if (pkt == NULL)
        return -1;

    /* compose pei */
    ppei = DMemMalloc(sizeof(pei));
    PeiInit(ppei);
    ppei->prot_id = pjl_id;
    ppei->serial = pkt->serial;
    ppei->time_cap = pkt->cap_sec;
    ppei->stack = ProtCopyFrame(pkt->stk, TRUE);

    /* compose pcl file */
    pcl_file = DMemMalloc(PJL_FILENAME_PATH_SIZE);
    pdf_file = DMemMalloc(PJL_FILENAME_PATH_SIZE);
    sprintf(pcl_file, "%s/%s/pjl_%lld_%p_%i.pcl", ProtTmpDir(), PJL_TMP_DIR, (long long)time(NULL), ppei, incr);
    sprintf(pdf_file, "%s/%s/pjl_%lld_%p_%i.pdf", ProtTmpDir(), PJL_TMP_DIR, (long long)time(NULL), ppei, incr);
    incr++;
    pcl = fopen(pcl_file, "w+");
    len = 0;
    err = FALSE;
    while (pkt != NULL) {
        time_end = pkt->cap_sec;
        if (pkt->len != 0) {
            if (PjlClientPkt(priv, pkt) == TRUE) {
                /* check if lost... */
                ProtGetAttr(pkt->stk, lost_id, &lost);
                if (lost.uint8 != TRUE) {
                    fwrite(pkt->data, 1, pkt->len, pcl);
                    len += pkt->len;
                }
                else
                    err = TRUE;
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    fclose(pcl);

    /* pdf conversion */
    sprintf(cmd, "%s -dNOPAUSE -sDEVICE=pdfwrite -sOutputFile=%s %s", pcl6_path, pdf_file, pcl_file);
    system(cmd);
    fst.st_size = 0;
    stat(pdf_file, &fst);

    /*   url */
    ind = 0;
    cmpn = DMemMalloc(sizeof(pei_component));
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_url_id;
    cmpn->id = ind;
    cmpn->time_cap = ppei->time_cap;
    cmpn->time_cap_end = time_end;
    cmpn->strbuf = NULL;
    ppei->components = cmpn;
    /*   pdf */
    ind++;
    cmpn->next = DMemMalloc(sizeof(pei_component));
    cmpn = cmpn->next;
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_pdffile_id;
    cmpn->id = ind;
    cmpn->time_cap = ppei->time_cap;
    cmpn->time_cap_end = time_end;
    cmpn->file_path = pdf_file;
    cmpn->file_size = fst.st_size;
    if (err == TRUE)
        cmpn->err = ELMT_ER_PARTIAL;
    /*   pcl */
    ind++;
    cmpn->next = DMemMalloc(sizeof(pei_component));
    cmpn = cmpn->next;
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_pclfile_id;
    cmpn->id = ind;
    cmpn->time_cap = ppei->time_cap;
    cmpn->time_cap_end = time_end;
    cmpn->file_path = pcl_file;
    cmpn->file_size = len;
    if (err == TRUE)
        cmpn->err = ELMT_ER_PARTIAL;
    
    /* insert pei */
    PeiIns(ppei);


    return 0;
}


static packet* PjlDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    pjl_priv *priv;
    packet *pkt;

    LogPrintf(LV_DEBUG, "PJL id: %d", flow_id);
    priv = DMemMalloc(sizeof(pjl_priv));
    memset(priv, 0, sizeof(pjl_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port = port_src.uint16;
    priv->dir = PJL_CLT_DIR_NONE;
    if (priv->port != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    if (ProtFrameProtocol(ip) == ip_id)
        priv->ipv6 = FALSE;
    
    if (priv->ipv6 == FALSE) {
        ProtGetAttr(ip, ip_src_id, &priv->ip);
        ProtGetAttr(ip, ip_dst_id, &ip_dst);
        ip_addr.s_addr = priv->ip.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = ip_dst.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip);
        ProtGetAttr(ip, ipv6_dst_id, &ip_dst);
        memcpy(ipv6_addr.s6_addr, priv->ip.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, ip_dst.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);

    if (PjlConnec(flow_id, priv) != 0) {
        /* raw pjl file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "PJL... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool PjlVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    bool ipv4, client;
    ftval lost, ips, ip_s;
    bool ret, fr_data;
    char *data, *new;
    short verify_step; /* 0: none; 1: server presentation ok; 2: command client ok */
    int cmp;
    unsigned long len;
    const char *eol, *lineend, *line;

    ipv4 = FALSE;
    client = TRUE; /* first packet without lost packet is a client packet */
    ret = FALSE;
    fr_data = FALSE;
    verify_step = 0;
    pkt = FlowGetPktCp(flow_id);

    if (pkt != NULL) {
        ip = ProtGetNxtFrame(pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id)
            ipv4 = TRUE;
        if (ipv4 == TRUE)
            ProtGetAttr(ip, ip_src_id, &ips);
        else
            ProtGetAttr(ip, ipv6_src_id, &ips);

        ProtGetAttr(pkt->stk, lost_id, &lost);
        while (lost.uint8 == FALSE && pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
            ProtGetAttr(pkt->stk, lost_id, &lost);
        }
    }

    if (pkt != NULL  && lost.uint8 == FALSE) {
        ip = ProtGetNxtFrame(pkt->stk);
        if (ipv4 == TRUE) {
            ProtGetAttr(ip, ip_src_id, &ip_s);
            cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
        }
        else {
            ProtGetAttr(ip, ipv6_src_id, &ip_s);
            cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
        }
        if (cmp != 0) {
            /* first packet (with data) is server packet */
            client = FALSE;
        }

        data = (char *)pkt->data;
        len = pkt->len;
        do {
            lineend = find_line_end(data, data+len, &eol);
            if (*eol == '\r' || *eol == '\n') {
                if (client == TRUE) {
                    /* first step is verify the client command */
                    if (len > 12 && memcmp(data+3, "12345X@PJL", 10) == 0) {
                        if (check == FALSE) {
                            ret = TRUE;
                            break;
                        }
                        line = lineend;
                        lineend = find_line_end(line, data+len, &eol);
                        if (*eol == '\r' || *eol == '\n') {
                            line = lineend;
                            lineend = find_line_end(line, data+len, &eol);
                            if (*eol == '\r' || *eol == '\n') {
                                if (memcmp(line, "@PJL", 4) == 0) {
                                    ret = TRUE;
                                    break;
                                }
                                else if ((lineend-line) > 12 && memcmp(line+3, "12345X@PJL", 10) == 0) {
                                    ret = TRUE;
                                    break;
                                }
                            }
                        }
                    }
                    else {
                        break;
                    }
                }
                else {
                    break;
                }
            }
            if (fr_data == FALSE) {
                data = xmalloc(len+1);
                if (data == NULL) {
                    LogPrintf(LV_WARNING, "Memmory unavailable");
                    break;
                }
                fr_data = TRUE;
                memcpy(data, pkt->data, len);
                data[len] = '\0';
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt != NULL) {
                ip = ProtGetNxtFrame(pkt->stk);
                if (ipv4 == TRUE) {
                    ProtGetAttr(ip, ip_src_id, &ip_s);
                    cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
                }
                else {
                    ProtGetAttr(ip, ipv6_src_id, &ip_s);
                    cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
                }
                if (cmp == 0) {
                    /* client to server */
                    if (client == FALSE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == FALSE) {
                        new = xrealloc(data, len+pkt->len+1);
                        if (new == NULL) {
                            LogPrintf(LV_WARNING, "Memmory unavailable");
                            break;
                        }
                        data = new;
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                        data[len] = '\0';
                    }
                    else {
                        PktFree(pkt);
                        pkt = NULL;
                    }
                    client = TRUE;
                }
                else {
#if 0
                    /* server to client */
                    if (client == TRUE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == FALSE) {
                        new = xrealloc(data, len+pkt->len+1);
                        if (new == NULL) {
                            LogPrintf(LV_WARNING, "Memmory unavailable");
                            break;
                        }
                        data = new;
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                        data[len] = '\0';
                    }
                    else {
                        PktFree(pkt);
                        pkt = NULL;
                    }
                    client = FALSE;
#endif
                }
            }
        } while (pkt != NULL && len < 1024); /* 1k: max pjl client job comunication */

        /* free memory */
        if (data != NULL && fr_data == TRUE) {
            xfree(data);
        }
    }
    
    if (pkt != NULL)
        PktFree(pkt);

    return ret;
}


static bool PjlCheck(int flow_id)
{
    return PjlVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&hdep, 0, sizeof(proto_heury_dep));

    /* protocol name */
    ProtName("Printer Job Language", "pjl");

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = PjlCheck;
    hdep.pktlim = PJL_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "pdf";
    peic.desc = "pdf file";
    ProtPeiComponent(&peic);

    peic.abbrev = "pcl";
    peic.desc = "pcl file";
    ProtPeiComponent(&peic);
    
    /* dissectors registration */
    ProtDissectors(NULL, PjlDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char pjl_dir[256];
    struct stat st;

    /* part of file name */
    incr = 0;

    /* check local pcl6 */
    if (stat("./pcl6", &st) == 0) {
        /* there is a local pcl6 application */
        strcpy(pcl6_path, "./pcl6");
    }
    
    /* protocols and attributes */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    tcp_id = ProtId("tcp");
    port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    lost_id = ProtAttrId(tcp_id, "tcp.lost");
    clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    pjl_id = ProtId("pjl");

    /* pei id */
    pei_url_id = ProtPeiComptId(pjl_id, "url");
    pei_pdffile_id = ProtPeiComptId(pjl_id, "pdf");
    pei_pclfile_id = ProtPeiComptId(pjl_id, "pcl");

    /* pjl tmp directory */
    sprintf(pjl_dir, "%s/%s", ProtTmpDir(), PJL_TMP_DIR);
    mkdir(pjl_dir, 0x01FF);

    return 0;
}
