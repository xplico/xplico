/* telnet.c
 * Dissector of telnet protocol
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: ettercap -- dissector telnet --
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "dnsdb.h"
#include "telnet.h"
#include "pei.h"

#define TELNET_TMP_DIR    "telnet"

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
static int telnet_id;

/* pei id */
static int pei_host_id;
static int pei_user_id;
static int pei_password_id;
static int pei_cmd_id;

static volatile unsigned int incr;

extern char *strcasestr(const char *haystack, const char *needle);

static int TelnetSkipCommand(unsigned char *ptr, unsigned char *end)
{
    int len;
    
    len = 0;
    while (ptr < end && *ptr == 0xff) {
        /* sub option 0xff 0xfa ... ... 0xff 0xf0 */
        if (*(ptr + 1) == 0xfa) {
            ptr += 1;
            len++;
            /* search the sub-option end (0xff 0xf0) */
            do {
                ptr += 1;
                len++;
            } while(*ptr != 0xff && ptr < end);
            /* skip the sub-option end */
            ptr += 2;
            len += 2;
        }
        else {
            /* normal option 0xff 0xXX 0xXX */
            ptr += 3;
            len += 3;
        }
    }

    return len;
}


/* 
 * convert 0x00 char into spaces (0x20) so we can
 * use str*() functions on the buffer...
 */
static void TelnetConvertZeros(unsigned char *ptr, unsigned char *end)
{
    bool i;

    /* 
     * walk the entire buffer, but skip the last
     * char, if it is 0x00 it is actually the string
     * terminator
     */
    i = FALSE;
    while (ptr < end) {
        if (*ptr == 0x00) {
            /* convert the char to a space */
            if (i && *(ptr - 1) == '\r') {
                *ptr = '\n';
            }
            else {
                *ptr = ' ';
            }
        }
        ptr++;
        i = TRUE;
    }
}


static int TelnetLogin(char *buf, char *user, char *pswd, int bsize)
{
    char *tmp, *lgn;
    long size, i;

    lgn = strcasestr(buf, "login:");
    if (lgn != NULL && strchr(lgn, '\r') != NULL) {
        /* last login */
        tmp = lgn;
        while (tmp != NULL) {
            tmp = strcasestr(tmp + 1, "login:");
            if (tmp != NULL && tmp[-1] != ' ' && tmp[-1] != '\n') {
                if (strcasestr(tmp, "Password:") != NULL)
                    lgn = tmp;
                else
                    tmp = NULL; 
            }
        }
        lgn += 6;
        tmp = strchr(lgn, '\r');
        size = tmp - lgn;
        if (bsize < size) {
            LogPrintf(LV_WARNING, "user name error: %s", lgn);
            size = bsize - 1;
        }
        memcpy(user, lgn, size);
        user[size] = '\0';

        /* password */
        lgn = strcasestr(lgn, "Password:");
        if (lgn != NULL) {
            lgn += 9;
            tmp = strchr(lgn, '\r');
            size = tmp - lgn;
            if (bsize < size) {
                LogPrintf(LV_WARNING, "password error: %s", lgn);
                size = bsize - 1;
            }
            memcpy(pswd, lgn, size);
            pswd[size] = '\0';
        }

        /* echo remove */
        size = strlen(user);
        if ((size%2 == 0 && user[0] == ' ') || size%2) {
            tmp = user;
            if (user[0] == ' ') {
                tmp++;
                size--;
            }
            while (size) {
                if (tmp[0] != tmp[1])
                    break;
                tmp += 2;
                size -=2;
            }
            
            if (size == 0) {
                /* echo remove */
                size = strlen(user)/2;
                tmp = user;
                i = 0;
                while (i != size) {
                    tmp[i] = user[i*2+1];
                    i++;
                }
                tmp[i] = '\0';
            }
        }
    }

    return 0;
}


static int TelnetPei(pei *ppei, const char *host, const char *user, const char *password, const char *cmd_file, time_t *cap_sec, time_t *end_cap)
{
    pei_component *cmpn;

    /* compose pei */
    /* host */
    PeiNewComponent(&cmpn, pei_host_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompAddStingBuff(cmpn, host);
    PeiAddComponent(ppei, cmpn);

    /* user */
    if (user[0] != '\0') {
        PeiNewComponent(&cmpn, pei_user_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompAddStingBuff(cmpn, user);
        PeiAddComponent(ppei, cmpn);
    }

    /* password */
    if (password[0] != '\0') {
        PeiNewComponent(&cmpn, pei_password_id);
        PeiCompCapTime(cmpn, *cap_sec);
        PeiCompAddStingBuff(cmpn, password);
        PeiAddComponent(ppei, cmpn);
    }

    /* cmd */
    PeiNewComponent(&cmpn, pei_cmd_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddFile(cmpn, "Telnet commands", cmd_file, 0);
    PeiAddComponent(ppei, cmpn);

    return 0;
}


static packet *TelnetDissector(int flow_id)
{
    packet *pkt;
    const pstack_f *tcp, *ip;
    ftval lost, ip_host, port;
    unsigned short port_host;
    bool ipv6;
    long offset, len, size;
    char host[TELNET_FILENAME_PATH_SIZE];
    char user[TELNET_BUF_SIZE];
    char password[TELNET_BUF_SIZE];
    char cmd_file[TELNET_FILENAME_PATH_SIZE];
    FILE *fp;
    char *buf;
    pei *ppei;
    time_t cap_sec, end_cap;
    int cntpkt;

    LogPrintf(LV_DEBUG, "Telnet id: %d", flow_id);
    
    cntpkt = 0;
    /* init (this for each telnet stream) */
    user[0] = '\0';
    password[0] = '\0';
    sprintf(cmd_file, "%s/%s/telnet_%lld_%p_%i.txt", ProtTmpDir(), TELNET_TMP_DIR, (long long)time(NULL), cmd_file, incr);
    incr++;
    fp = fopen(cmd_file, "w");
    ipv6 = FALSE;
    buf = DMemMalloc(TELNET_LOGIN_SIZE);
    buf[0] = '\0';
    len = 0;
    
    /* ip version and number */
    tcp = FlowStack(flow_id); /* tcp frame */
    ip = ProtGetNxtFrame(tcp); /* ip/ipv6 frame */
    ProtGetAttr(tcp, port_dst_id, &port);
    port_host = port.uint16;
    if (ProtFrameProtocol(ip) == ipv6_id) {
        ipv6 = TRUE;
    }
    if (ipv6 == FALSE) {
        ProtGetAttr(ip, ip_dst_id, &ip_host);
        if (DnsDbSearch(&(ip_host), FT_IPv4, host, TELNET_FILENAME_PATH_SIZE) != 0) {
            FTString(&(ip_host), FT_IPv4, host);
        }
    }
    else {
        ProtGetAttr(ip, ipv6_dst_id, &ip_host);
        if (DnsDbSearch(&(ip_host), FT_IPv6, host, TELNET_FILENAME_PATH_SIZE) != 0) {
            FTString(&(ip_host), FT_IPv6, host);
        }
    }
    sprintf(host+strlen(host), ":%i", port_host);
    
    /* first packet */
    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) {
        /* pei definition */
        PeiNew(&ppei, telnet_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, tcp);
        cap_sec = pkt->cap_sec;
    }
    while (pkt != NULL) {
        cntpkt++;
        end_cap = pkt->cap_sec;
        offset = 0;
        /* check if there are packet lost */
        ProtGetAttr(pkt->stk, lost_id, &lost);
        //ProtStackFrmDisp(pkt->stk, TRUE); /* this function display the structure of packet stack of this packet */
        if (lost.uint8 == FALSE && pkt->len != 0) {
            /* no packet lost and packet with data */
            /* skip the telnet commands, we are interested only in readable data */
#warning "to do: reassemble telnet message from many tcp packets"
            offset = TelnetSkipCommand((unsigned char *)(pkt->data), (unsigned char *)(pkt->data + pkt->len));
            if (offset < pkt->len) {
                TelnetConvertZeros((unsigned char *)(pkt->data + offset), (unsigned char *)(pkt->data + pkt->len));
                size = pkt->len - offset;
                fwrite(pkt->data + offset, 1, size, fp);
                if (len + size < TELNET_LOGIN_SIZE) {
                    memcpy(buf+len, pkt->data + offset, size);
                    len += size;
                    buf[len] = '\0';
                }
            }
        }
        else if (lost.uint8) {
            fprintf(fp, "-----> xplico: packets lost (size: %lub) <-----", pkt->len);
        }

        /* new/next packet */
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    /* search login */
    buf[TELNET_LOGIN_SIZE - 1] = '\0';
    TelnetLogin(buf, user, password, TELNET_BUF_SIZE);

    /* free memory and close file */
    DMemFree(buf);
    if (fp != NULL) {
        fclose(fp);
    }

    if (len != 0) {
        /* compose pei */
        TelnetPei(ppei, host, user, password, cmd_file, &cap_sec, &end_cap);
        /* insert pei */
        PeiIns(ppei);
    }
    
    LogPrintf(LV_DEBUG, "Telnet... bye bye. (count:%i)", cntpkt);

    return NULL;
}


static bool TelnetVerifyCheck(int flow_id, bool check)
{
    packet *pkt;
    short cnt, cnt_lim;
    long offset;
    ftval lost;
    
    cnt = 0;
    pkt = FlowGetPktCp(flow_id);
    /* numer of packet to verify */
    cnt_lim = TELNET_PKT_CHECK;
    if (!check) {
        cnt_lim = 1;
        do {
            while (pkt != NULL && pkt->len == 0) {
                PktFree(pkt);
                pkt = FlowGetPktCp(flow_id);
            }
            if (pkt != NULL && pkt->data != NULL && pkt->len != 0) {
                offset = TelnetSkipCommand((unsigned char *)(pkt->data), 
                                           (unsigned char *)(pkt->data + pkt->len));
                if (offset == pkt->len)
                    cnt++;
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
        } while (pkt != NULL);
    }
    else if (pkt != NULL) {
        do {
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == FALSE && pkt->data != NULL && pkt->len != 0) {
                offset = TelnetSkipCommand((unsigned char *)(pkt->data), 
                                           (unsigned char *)(pkt->data + pkt->len));
                if (offset == pkt->len) {
                    cnt++;
                }
                else {
                    break;
                }
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
        } while (pkt != NULL);
    }
    
    if (pkt != NULL)
        PktFree(pkt);
    if (cnt >= cnt_lim) {
        return TRUE;
    }

    return FALSE;
}


static bool TelnetVerify(int flow_id)
{
    return TelnetVerifyCheck(flow_id, FALSE);
}


static bool TelnetCheck(int flow_id)
{
    return TelnetVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    proto_dep dep;
    pei_cmpt peic;

    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Telnet", "telnet");

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = TelnetCheck;
    hdep.pktlim = TELNET_PKT_LIMIT;
    ProtHeuDep(&hdep);

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_TELNET;
    dep.ProtCheck = TelnetVerify;
    dep.pktlim = TELNET_PKT_LIMIT;
    ProtDep(&dep);

    /* PEI components */
    peic.abbrev = "host";
    peic.desc = "Host name or IP";
    ProtPeiComponent(&peic);

    peic.abbrev = "user";
    peic.desc = "User name";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "password";
    peic.desc = "Password";
    ProtPeiComponent(&peic);

    peic.abbrev = "cmd";
    peic.desc = "Commands";
    ProtPeiComponent(&peic);

    /* dissectors subdissectors registration */
    ProtDissectors(NULL, TelnetDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char telnet_dir[256];

    /* part of file name */
    incr = 0;

    /* info id */
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    tcp_id = ProtId("tcp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    lost_id = ProtAttrId(tcp_id, "tcp.lost");
    telnet_id = ProtId("telnet");

    /* pei id */
    pei_host_id = ProtPeiComptId(telnet_id, "host");
    pei_user_id = ProtPeiComptId(telnet_id, "user");
    pei_password_id= ProtPeiComptId(telnet_id, "password");
    pei_cmd_id = ProtPeiComptId(telnet_id, "cmd");

    /* telnet tmp directory */
    sprintf(telnet_dir, "%s/%s", ProtTmpDir(), TELNET_TMP_DIR);
    mkdir(telnet_dir, 0x01FF);

    return 0;
}
