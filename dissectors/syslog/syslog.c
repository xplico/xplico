/* syslog.c
 * syslog dissector
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "pei.h"
#include "dnsdb.h"
#include "syslog.h"

#define SYSLOG_TMP_DIR    "syslog"

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int udp_id;
static int port_src_id;
static int port_dst_id;
static int prot_id;

/* pei id */
static int pei_host_id;
static int pei_cmd_id;
static volatile unsigned long incr;

static const char *severity[] = {
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug"
};


static const char *facility[] = {
    "kernel",
    "user-level",
    "mail",
    "system",
    "authorization",
    "internally",
    "printer",
    "news",
    "UUCP",
    "clock",
    "authorization",
    "FTP",
    "NTP",
    "log audit",
    "log alert",
    "clock",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
    "---",
    "---",
    "---",
    "---",
    "---",
    "---",
    "---",
    "---",
    "---"
};


static short SyslogPri(const char *data, int len)
{
    int i;
    short pri;
    
    if (len > 2 && data[0] == '<') { /* the pri is => <digit> */
        /* find '>' */
        i = 1;
        while (i != len && data[i] != '>' && isdigit(data[i]))
            i++;
        if (data[i] != '>')
            return -1;
        pri = atoi(data+1);

        return pri;
    }

    return -1;
}


static inline const char *SyslogMsg(const char *data, int len)
{
    int i;
    
    i = 2;
    while (i != len && data[i] != '>')
        i++;
    if (i != len)
        return data + i + 1;
    return NULL;
}


static packet *SyslogDissector(int flow_id)
{
    packet *pkt;
    const pstack_f *udp, *ip;
    const char *msg;
    ftval val;
    char file_log[SYSLOG_FILENAME_PATH_SIZE];
    char host[SYSLOG_FILENAME_PATH_SIZE];
    pei *ppei;
    pei_component *cmpn;
    time_t cap_sec, end_cap;
    int cntpkt, len;
    short pri, fac, sev;
    FILE *fp;
    
    ppei = NULL;
    LogPrintf(LV_DEBUG, "Syslog id: %d", flow_id);
    cntpkt = 0;

    /* ip version and number */
    udp = FlowStack(flow_id); /* udp frame */
    ip = ProtGetNxtFrame(udp); /* ip/ipv6 frame */

    ProtStackFrmDisp(udp, TRUE);

    /* host */
    len = 0;
    if (ProtFrameProtocol(ip) == ip_id) {
        ProtGetAttr(ip, ip_src_id, &val);
        if (DnsDbSearch(&val, FT_IPv4, host+len, SYSLOG_FILENAME_PATH_SIZE - len) != 0) {
            FTString(&val, FT_IPv4, host+len);
        }
        len = strlen(host);
        host[len++] = ' ';
        host[len++] = '-';
        host[len++] = ' ';
        ProtGetAttr(ip, ip_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv4, host+len, SYSLOG_FILENAME_PATH_SIZE - len) != 0) {
            FTString(&val, FT_IPv4, host+len);
        }
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &val);
        if (DnsDbSearch(&val, FT_IPv6, host+len, SYSLOG_FILENAME_PATH_SIZE - len) != 0) {
            FTString(&val, FT_IPv6, host+len);
        }
        host[len++] = ' ';
        host[len++] = '-';
        host[len++] = ' ';
        ProtGetAttr(ip, ipv6_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv6, host+len, SYSLOG_FILENAME_PATH_SIZE - len) != 0) {
            FTString(&val, FT_IPv6, host+len);
        }
    }
    len = strlen(host);

    /* syslog file */
    sprintf(file_log, "%s/%s/syslog_%p_%lu.log", ProtTmpDir(), SYSLOG_TMP_DIR, file_log,incr++);
    fp = fopen(file_log, "w");
    
    /* first packet */
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
        /* pei definition */
        PeiNew(&ppei, prot_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, udp);
        cap_sec = pkt->cap_sec;
    }
    if (fp != NULL) {
        while (pkt != NULL) {
            cntpkt++;
            end_cap = pkt->cap_sec;
            pri = SyslogPri(pkt->data, pkt->len);
            if (pri != -1) {
                msg = SyslogMsg(pkt->data, pkt->len);
                if (msg != NULL) {
                    sev = pri & 0x07;
                    fac = pri >> 3;
                    fprintf(fp, "{%s.%s} %s", facility[fac], severity[sev], msg);
                }
            }
            
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
        fclose(fp);
        
        if (ppei != NULL) {
            /* pei completiton and insertion */
            /*  host */
            PeiNewComponent(&cmpn, pei_host_id);
            PeiCompCapTime(cmpn, cap_sec);
            PeiCompCapEndTime(cmpn, end_cap);
            PeiCompAddStingBuff(cmpn, host);
            PeiAddComponent(ppei, cmpn);
            /*  file */
            PeiNewComponent(&cmpn, pei_cmd_id);
            PeiCompCapTime(cmpn, cap_sec);
            PeiCompCapEndTime(cmpn, end_cap);
            PeiCompAddFile(cmpn, "syslog.log", file_log, 0);
            PeiAddComponent(ppei, cmpn);
            
            PeiIns(ppei);
        }
    }
    else {
        LogPrintf(LV_ERROR, "Unable to open file: %s", file_log);
        while (pkt != NULL) {
            cntpkt++;
            end_cap = pkt->cap_sec;

            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
        
        /* pei completiton and insertion */
        /*  host */
        PeiNewComponent(&cmpn, pei_host_id);
        PeiCompCapTime(cmpn, cap_sec);
        PeiCompCapEndTime(cmpn, end_cap);
        PeiCompAddStingBuff(cmpn, host);
        PeiAddComponent(ppei, cmpn);

        PeiIns(ppei);
    }

    LogPrintf(LV_DEBUG, "Syslog... bye bye. (count:%i)", cntpkt);

    return NULL;
}


static bool SyslogVerifyCheck(int flow_id, bool check)
{
    packet *pkt;
    short cnt, cnt_lim;
    short pri;
    unsigned long num;

    cnt = 0;
    pkt = FlowGetPktCp(flow_id);
    if (!check) {
        /* numer of packet to verify */
        cnt_lim = SYSLOG_PKT_VER;
    }
    else {
        /* numer of packet to verify */
        cnt_lim = SYSLOG_PKT_CHECK;
    }

    if (FlowIsClose(flow_id) == TRUE) {
        num = FlowPktNum(flow_id);
        if (num < cnt_lim)
            cnt_lim = num;
    }

    do {
        while (pkt != NULL && pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
        }
        if (pkt != NULL && pkt->data != NULL && pkt->len > SYSLOG_PKT_MIN_LEN) {
            pri = SyslogPri(pkt->data, pkt->len);
            if (pri != -1) {
                if (isascii(pkt->data[pkt->len - 3]))
                    cnt++;
                else if (check) {
                    break;
                }
            }
            else if (check)
                break;
        }
        PktFree(pkt);
        pkt = FlowGetPktCp(flow_id);
    } while (pkt != NULL);
    
    if (pkt != NULL)
        PktFree(pkt);
    
    if (cnt >= cnt_lim) {
        return TRUE;
    }

    return FALSE;
}


static bool SyslogVerify(int flow_id)
{
    return SyslogVerifyCheck(flow_id, FALSE);
}


static bool SyslogCheck(int flow_id)
{
    return SyslogVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
    memset(&hdep, 0, sizeof(proto_heury_dep));

    /* protocol name */
    ProtName("Syslog message", "syslog");

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_UDP_SYSLOG;
    dep.ProtCheck = SyslogVerify;
    dep.pktlim = SYSLOG_PKT_VER_LIMIT;
    ProtDep(&dep);
    dep.attr = "udp.srcport";
    ProtDep(&dep);

    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = SyslogCheck;
    hdep.pktlim = SYSLOG_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "hosts";
    peic.desc = "Syslog hosts";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "log";
    peic.desc = "Log file";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, SyslogDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tdir[256];
    
    incr = 0;

    /* info id */
    prot_id = ProtId("syslog");
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    udp_id = ProtId("udp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    port_dst_id = ProtAttrId(udp_id, "udp.dstport");
    port_src_id = ProtAttrId(udp_id, "udp.srcport");

    /* pei id */
    pei_host_id = ProtPeiComptId(prot_id, "hosts");
    pei_cmd_id = ProtPeiComptId(prot_id, "log");

    /* tmp directory */
    sprintf(tdir, "%s/%s", ProtTmpDir(), SYSLOG_TMP_DIR);
    mkdir(tdir, 0x01FF);

    return 0;
}
