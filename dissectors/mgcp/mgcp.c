/* mgcp.c
 * Dissector of MGCP protocol
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <stdlib.h>
#include <sys/wait.h>
#include <ctype.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "flow.h"
#include "log.h"
#include "mgcp.h"
#include "pei.h"
#include "sdp.h"
#include "grp_rule.h"
#include "grp_flows.h"
#include "pcap_gfile.h"

#define NO_DEBUG_RM     1  /* if 1 then all files are removed from tmp dir */

#define MGCP_VERB_LEN   4

#define MGCP_TMP_DIR    "mgcp"

/* info id */
static int ppp_id;
static int eth_id;
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ip_offset_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int tcp_id;
static int tport_src_id;
static int tport_dst_id;
static int udp_id;
static int uport_src_id;
static int uport_dst_id;
static int lost_id;
static int clnt_id;
static int sdp_id;
static int mgcp_id;

/* pei id */
static int pei_to_id;
static int pei_from_id;
static int pei_cmd_id;
static int pei_audio_from_id;
static int pei_audio_to_id;
static int pei_audio_mix_id;
static int pei_duration_id;

static volatile unsigned int incr;


static const char *mgcp_methods[] = {
        "AUEP",
        "AUCX",
        "CRCX",
        "DLCX",
        "EPCF",
        "MDCX",
        "NTFY",
        "RQNT",
        "RSIP"
};


static mgcp_ver MgcpReqVersion(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return MGCP_VER_NONE;
    }
    line = next_token;

    /* The next token is the identification of the transaction */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return MGCP_VER_NONE;
    line = next_token;

    /* The next token is the name of the endpoint */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return MGCP_VER_NONE;
    line = next_token;

    /* Everything to the end of the line is the version. */
    tokenlen = lineend - line;
    if (tokenlen == 0)
        return MGCP_VER_NONE;
    
    if (strncmp(line, "MGCP 1.0", 8) == 0)
        return MGCP_VER_1_0;
    else if (strncmp(line, "MGCP ", 5) == 0) {
        LogPrintf(LV_WARNING, "MGCP Version not supported");
    }
    
    return MGCP_VER_NONE;
}


static mgcp_ver MgcpTo(mgcp_call *call, const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return -1;
    }
    line = next_token;

    /* The next token is the identification of the transaction */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return -1;
    line = next_token;

    /* The next token is the name of the endpoint */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return -1;

    if (tokenlen > MGCP_HEADER_LINE)
        tokenlen = MGCP_HEADER_LINE - 1;
    memcpy(call->to, line, tokenlen);
    call->to[tokenlen] = '\0';

    return 0;
}


static mgcp_status MgcpResValid(const char *line, int len)
{
    if (len > 3) {
        if (isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2]) )
            return MGCP_ST_VALID;
    }
    
    return MGCP_ST_NONE;
}


static mgcp_mthd MgcpReqMethod(const char *data, int linelen)
{
    const char *ptr;
    int	index = 0;
    char frt;

    ptr = (const char *)data;
    
    /* Look for the space following the Method */
    while (index < linelen) {
        if (*ptr == ' ')
            break;
        else {
            ptr++;
            index++;
        }
    }
    
    if (index != MGCP_VERB_LEN) {
        LogPrintf(LV_WARNING, "Mgcp method (dim:%i) \"%s\" don't managed.", index, data);
        
        return MGCP_MT_NONE;
    }
    
    /* Check the methods */
    frt = data[0];

    if (frt == 'A' || frt == 'a') {
        if (strncasecmp(data, "AUEP", MGCP_VERB_LEN) == 0)
            return MGCP_MT_AUEP;
        else if (strncasecmp(data, "AUCX", MGCP_VERB_LEN) == 0)
            return MGCP_MT_AUCX;
    }
    else if (frt == 'C' || frt == 'c') {
        if (strncasecmp(data, "CRCX", MGCP_VERB_LEN) == 0)
            return MGCP_MT_CRCX;
    }
    else if (frt == 'D' || frt == 'd') {
        if (strncasecmp(data, "DLCX", MGCP_VERB_LEN) == 0)
            return MGCP_MT_DLCX;
    }
    else if (frt == 'E' || frt == 'e') {
        if (strncasecmp(data, "EPCF", MGCP_VERB_LEN) == 0)
            return MGCP_MT_EPCF;
    }
    else if (frt == 'M' || frt == 'm') {
        if (strncasecmp(data, "MDCX", MGCP_VERB_LEN) == 0)
            return MGCP_MT_MDCX;
    }
    else if (frt == 'N' || frt == 'n') {
        if (strncasecmp(data, "NTFY", MGCP_VERB_LEN) == 0)
            return MGCP_MT_NTFY;
    }
    else if (frt == 'R' || frt == 'r') {
        if (strncasecmp(data, "RQNT", MGCP_VERB_LEN) == 0)
            return MGCP_MT_RQNT;
        else if (strncasecmp(data, "RSIP", MGCP_VERB_LEN) == 0)
            return MGCP_MT_RSIP;
    }
    
    return MGCP_MT_NONE;
}


static int MgcpTranId(const char *data, int linelen, mgcp_msg *msg)
{
    const char *start;
    const char *next_token;
    const char *lineend;
    int tokenlen, i;

    lineend = data + linelen;

    /* The first token is the method. */
    tokenlen = get_token_len(data, lineend, &start);
    if (tokenlen == 0 || data[tokenlen] != ' ') {
        return -1;
    }

    /* The next token is the identification of the transaction */
    tokenlen = get_token_len(start, lineend, &next_token);
    if (tokenlen == 0 || start[tokenlen] != ' ')
        return MGCP_VER_NONE;
    i = 0;
    for (; start != next_token; start++)
        msg->tran_id[i++] = *start;
    msg->tran_id[i] = '\0';
    
    return 0;
}


static mgcp_status MgcpRespStatus(const char *line, int len)
{
    const char *lineend;
    int val;

    lineend = line + len;

    /* The first token is the response code */
    if (sscanf(line, "%i", &val) != 1) {
        LogPrintf(LV_ERROR, "MGCP return status\n");

        return MGCP_ST_NONE;
    }
    
    /* search enum */
    if (val == 200)
        return MGCP_ST_200;
    else if (val >= MGCP_ST_RESP_FIRST && val <= MGCP_ST_RESP_LAST)
        return MGCP_ST_VALID;
        
    LogPrintf(LV_WARNING, "MGCP return status unknown!!!\n");

    return MGCP_ST_NONE;
}


static bool MgcpMediaPkt(rtx_media *media, const packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (media->ipv6 == TRUE) {
        ProtGetAttr(ProtGetNxtFrame(pkt->stk), ipv6_dst_id, &ip);
        type = FT_IPv6;
    }
    else {
        ProtGetAttr(ProtGetNxtFrame(pkt->stk), ip_dst_id, &ip);
        type = FT_IPv4;
    }
    if (FTCmp(&media->ip_dst, &ip, type, FT_OP_EQ, NULL) == 0) {
        ProtGetAttr(pkt->stk, uport_dst_id, &port);
        if (port.uint16 == media->dst_port.uint16)
            ret = TRUE;
    }

    return ret;
}


static char* MgcpHeaderEnd(const char *header, unsigned long len)
{
    const char *lf, *nxtlf, *end;
    const char *buf_end;
   
    end = NULL;
    buf_end = header + len;
    lf =  memchr(header, '\n', len);
    if (lf == NULL)
        return NULL;
    lf++; /* next charater */
    nxtlf = memchr(lf, '\n', buf_end - lf);
    while (nxtlf != NULL) {
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        nxtlf++;
        lf = nxtlf;
        nxtlf = memchr(nxtlf, '\n', buf_end - nxtlf);
    }

    return (char *)end;
}


mgcp_msg *MgcpMessage(int flow_id, mgcp_msg **partial)
{
    packet* pkt;
    mgcp_msg *msg;

    /* extract a single message */
    do {
        pkt = FlowGetPkt(flow_id);
        if (pkt == NULL) {
            return NULL;
        }
        /* new msg */
        if (*partial != NULL) {
            msg = *partial;
            *partial = NULL;
        }
        else {

        }
    } while (1);
}


static void MgcpCallInit(mgcp_call *call, const packet *pkt, int flow_id, mgcp_msg *msg)
{
    memset(call, 0, sizeof(mgcp_call));
    call->sdp_cr = NULL;
    call->sdp_cd = NULL;
    call->rule_cr_id = -1;
    call->rule_cd_id = -1;
    call->audio_rtp_cr = -1;
    call->audio_rtp_cd = -1;
    call->audio_rtcp_cr = -1;
    call->audio_rtcp_cd = -1;
    sprintf(call->from, "Not present");
    sprintf(call->to, "Not present");
    //call->audio_cr = NULL;
    //call->audio_cd = NULL;
    strcpy(call->id, msg->conn_id);
    strcpy(call->tran_id, msg->tran_id);
    call->closed = FALSE;
    /* pei */
    PeiNew(&(call->ppei), mgcp_id);
    PeiCapTime(call->ppei, pkt->cap_sec);
    PeiMarker(call->ppei, pkt->serial);
    PeiStackFlow(call->ppei, FlowStack(flow_id));
    /* commands component */
    incr++;
    sprintf(call->cmd_file, "%s/%s/mgcp_cmd_%lu_%d.txt", ProtTmpDir(), MGCP_TMP_DIR, time(NULL), incr);
    call->cmd_fp = fopen(call->cmd_file, "w");
}


static void MgcpCallFree(mgcp_call *call)
{
    xfree(call);
}


static int MgcpMsgDec(mgcp_msg *msg, packet *pkt)
{
    char *conn_id, *end, c;
    mgcp_ver ver;

    memset(msg, 0, sizeof(mgcp_msg));
    msg->conn_id[0] = msg->tran_id[0] = '\0';
    msg->status = MGCP_ST_NONE;
    ver = MgcpReqVersion(pkt->data, pkt->len);
    if (ver != MGCP_VER_NONE) {
        msg->mtd = MgcpReqMethod(pkt->data, pkt->len);
    }
    else {
        msg->mtd = MGCP_MT_NONE;
        /* respose ? */
        msg->status = MgcpRespStatus(pkt->data, pkt->len);
    }
    /* transaction ID */
    MgcpTranId(pkt->data, pkt->len, msg);
    
    /* connection id */
    conn_id = strstr(pkt->data, "\nI:");
    if (conn_id == NULL) {
        conn_id = strstr(pkt->data, "\ni:");
        if (conn_id != NULL)
            conn_id += 3;
    }
    else {
        conn_id += 3;
    }
    
    if (conn_id != NULL) {
        end = strchr(conn_id, '\r');
        c = '\r';
        if (end == NULL) {
            end = strchr(conn_id, '\n');
            c = '\n';
        }
        if (end != NULL) {
            while (*conn_id == ' ' || *conn_id == '\t')
                conn_id += 1;
            *end = '\0';
            strncpy(msg->conn_id, conn_id, MGCP_HEADER_LINE);
            *end = c;
        }
    }

    return 0;
}


static int MgcpStorageInit(mgcp_call *call, int flow_id)
{
    struct pcap_file_header fh;
    
    sprintf(call->cr.file_name, "%s/%s/mgcp_cr_%lu_%d.pcap", ProtTmpDir(), MGCP_TMP_DIR, time(NULL), incr);
    sprintf(call->cd.file_name, "%s/%s/mgcp_cd_%lu_%d.pcap", ProtTmpDir(), MGCP_TMP_DIR, time(NULL), incr);
    call->cr.fp = fopen(call->cr.file_name, "w");
    call->cd.fp = fopen(call->cd.file_name, "w");
    memset(&fh, 0, sizeof(struct pcap_file_header));
    fh.magic = 0xA1B2C3D4;
    fh.version_major = PCAP_VERSION_MAJOR;
    fh.version_minor = PCAP_VERSION_MINOR;
    fh.snaplen = 65535;
    fh.linktype = DLT_RAW;
    if (call->cr.fp != NULL) {
        fwrite((char *)&fh, 1, sizeof(struct pcap_file_header), call->cr.fp);
    }
    if (call->cd.fp != NULL) {
        fwrite((char *)&fh, 1, sizeof(struct pcap_file_header), call->cd.fp);
    }
    
    return 0;
}


static int MgcpMediaFlow(mgcp_call *call, int media_id)
{
    const pstack_f *media_stk;
    ftval port, ip;
    enum ftype type;

    media_stk = FlowStack(media_id);
    
    if (call->audio_cr.ipv6 == TRUE) {
        ProtGetAttr(ProtGetNxtFrame(media_stk), ipv6_dst_id, &ip);
        type = FT_IPv6;
    }
    else {
        ProtGetAttr(ProtGetNxtFrame(media_stk), ip_dst_id, &ip);
        type = FT_IPv4;
    }
    if (FTCmp(&call->audio_cr.ip_dst, &ip, type, FT_OP_EQ, NULL) == 0) {
        ProtGetAttr(media_stk, uport_dst_id, &port);
        if (port.uint16 == call->audio_cr.dst_port.uint16) {
            call->rule_cr_id = -1;
            call->audio_rtp_cr = media_id;
            PeiAddStkGrp(call->ppei, FlowStack(media_id));
            FlowSetTimeOut(media_id, 0);
            return 0;
        }
    }
    if (FTCmp(&call->audio_cd.ip_dst, &ip, type, FT_OP_EQ, NULL) == 0) {
        ProtGetAttr(media_stk, uport_dst_id, &port);
        if (port.uint16 == call->audio_cd.dst_port.uint16) {
            call->rule_cd_id = -1;
            call->audio_rtp_cd = media_id;
            PeiAddStkGrp(call->ppei, FlowStack(media_id));
            FlowSetTimeOut(media_id, 0);
            return 0;
        }
    }
    
    if (call->audio_cr.ipv6 == TRUE) {
        ProtGetAttr(ProtGetNxtFrame(media_stk), ipv6_src_id, &ip);
        type = FT_IPv6;
    }
    else {
        ProtGetAttr(ProtGetNxtFrame(media_stk), ip_src_id, &ip);
        type = FT_IPv4;
    }
    if (FTCmp(&call->audio_cr.ip_dst, &ip, type, FT_OP_EQ, NULL) == 0) {
        ProtGetAttr(media_stk, uport_src_id, &port);
        if (port.uint16 == call->audio_cr.dst_port.uint16) {
            call->rule_cr_id = -1;
            call->audio_rtp_cr = media_id;
            PeiAddStkGrp(call->ppei, FlowStack(media_id));
            FlowSetTimeOut(media_id, 0);
            return 0;
        }
    }
    if (FTCmp(&call->audio_cd.ip_dst, &ip, type, FT_OP_EQ, NULL) == 0) {
        ProtGetAttr(media_stk, uport_src_id, &port);
        if (port.uint16 == call->audio_cd.dst_port.uint16) {
            call->rule_cd_id = -1;
            call->audio_rtp_cd = media_id;
            PeiAddStkGrp(call->ppei, FlowStack(media_id));
            FlowSetTimeOut(media_id, 0);
            return 0;
        }
    }
    
    return -1;
}


static int MgcpPktStorageCr(mgcp_call *call, const packet *pkt)
{
    const pstack_f *ip;
    struct pcappkt_hdr pckt_header;
    size_t nwrt, wcnt;
    ftval offset;

    if (MgcpMediaPkt(&(call->audio_cr), pkt)) {
        if (call->audio_cr.start_time_sec == 0) {
            call->audio_cr.start_time_sec = pkt->cap_sec;
            call->audio_cr.start_time_usec = pkt->cap_usec;
        }
        call->audio_cr.end_time_sec = pkt->cap_sec;
        /* save in the pcap file */
        if (call->audio_cr.ipv6) {
            ip = ProtStackSearchProt(pkt->stk, ipv6_id);
            ProtGetAttr(ip, ipv6_offset_id, &offset);
            wcnt = offset.uint32;
        }
        else {
            ip = ProtStackSearchProt(pkt->stk, ip_id);
            ProtGetAttr(ip, ip_offset_id, &offset);
            wcnt = offset.uint32;
        }
        pckt_header.caplen = pkt->raw_len - wcnt;
        pckt_header.len = pkt->raw_len - wcnt;
        pckt_header.tv_sec = pkt->cap_sec;
        pckt_header.tv_usec = pkt->cap_usec;
        if (call->cr.fp != NULL) {
            wcnt = 0;
            do {
                nwrt = fwrite(((char *)&pckt_header)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, call->cr.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != sizeof(struct pcappkt_hdr));
            
            wcnt = offset.uint32;
            do {
                nwrt = fwrite(((char *)pkt->raw)+wcnt, 1, pkt->raw_len-wcnt, call->cr.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != pkt->raw_len);
        }
    }
    else {
        if (call->audio_cd.start_time_sec == 0) {
            call->audio_cd.start_time_sec = pkt->cap_sec;
            call->audio_cd.start_time_usec = pkt->cap_usec;
        }
        call->audio_cd.end_time_sec = pkt->cap_sec;
        /* save in the pcap file */
        if (call->audio_cr.ipv6) {
            ip = ProtStackSearchProt(pkt->stk, ipv6_id);
            ProtGetAttr(ip, ipv6_offset_id, &offset);
            wcnt = offset.uint32;
        }
        else {
            ip = ProtStackSearchProt(pkt->stk, ip_id);
            ProtGetAttr(ip, ip_offset_id, &offset);
            wcnt = offset.uint32;
        }
        pckt_header.caplen = pkt->raw_len - wcnt;
        pckt_header.len = pkt->raw_len - wcnt;
        pckt_header.tv_sec = pkt->cap_sec;
        pckt_header.tv_usec = pkt->cap_usec;
        if (call->cd.fp != NULL) {
            wcnt = 0;
            do {
                nwrt = fwrite(((char *)&pckt_header)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, call->cd.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != sizeof(struct pcappkt_hdr));
            
            wcnt = offset.uint32;
            do {
                nwrt = fwrite(((char *)pkt->raw)+wcnt, 1, pkt->raw_len-wcnt, call->cd.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != pkt->raw_len);
        }
    }

    return 0;
}


static int MgcpPktStorageCd(mgcp_call *call, const packet *pkt)
{
    const pstack_f *ip;
    struct pcappkt_hdr pckt_header;
    size_t nwrt, wcnt;
    ftval offset;
    
    if (MgcpMediaPkt(&(call->audio_cd), pkt)) {
        if (call->audio_cd.start_time_sec == 0) {
            call->audio_cd.start_time_sec = pkt->cap_sec;
            call->audio_cd.start_time_usec = pkt->cap_usec;
        }
        call->audio_cd.end_time_sec = pkt->cap_sec;
        /* save in the pcap file */
        if (call->audio_cd.ipv6) {
            ip = ProtStackSearchProt(pkt->stk, ipv6_id);
            ProtGetAttr(ip, ipv6_offset_id, &offset);
            wcnt = offset.uint32;
        }
        else {
            ip = ProtStackSearchProt(pkt->stk, ip_id);
            ProtGetAttr(ip, ip_offset_id, &offset);
            wcnt = offset.uint32;
        }
        pckt_header.caplen = pkt->raw_len - wcnt;
        pckt_header.len = pkt->raw_len - wcnt;
        pckt_header.tv_sec = pkt->cap_sec;
        pckt_header.tv_usec = pkt->cap_usec;
        if (call->cd.fp != NULL) {
            wcnt = 0;
            do {
                nwrt = fwrite(((char *)&pckt_header)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, call->cd.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != sizeof(struct pcappkt_hdr));
        
            wcnt = offset.uint32;
            do {
                nwrt = fwrite(((char *)pkt->raw)+wcnt, 1, pkt->raw_len-wcnt, call->cd.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != pkt->raw_len);
        }
    }
    else {
        if (call->audio_cr.start_time_sec == 0) {
            call->audio_cr.start_time_sec = pkt->cap_sec;
            call->audio_cr.start_time_usec = pkt->cap_usec;
        }
        call->audio_cr.end_time_sec = pkt->cap_sec;
        /* save in the pcap file */
        if (call->audio_cd.ipv6) {
            ip = ProtStackSearchProt(pkt->stk, ipv6_id);
            ProtGetAttr(ip, ipv6_offset_id, &offset);
            wcnt = offset.uint32;
        }
        else {
            ip = ProtStackSearchProt(pkt->stk, ip_id);
            ProtGetAttr(ip, ip_offset_id, &offset);
            wcnt = offset.uint32;
        }
        pckt_header.caplen = pkt->raw_len - wcnt;
        pckt_header.len = pkt->raw_len - wcnt;
        pckt_header.tv_sec = pkt->cap_sec;
        pckt_header.tv_usec = pkt->cap_usec;
        if (call->cr.fp != NULL) {
            wcnt = 0;
            do {
                nwrt = fwrite(((char *)&pckt_header)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, call->cr.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != sizeof(struct pcappkt_hdr));
        
            wcnt = offset.uint32;
            do {
                nwrt = fwrite(((char *)pkt->raw)+wcnt, 1, pkt->raw_len-wcnt, call->cr.fp);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != pkt->raw_len);
        }
    }

    return 0;
}


static int MgcpCallPei(mgcp_call *call)
{
    int ret;
    char media_file_1[MGCP_FILENAME_PATH_SIZE];
    char media_file_2[MGCP_FILENAME_PATH_SIZE];
    char tmp_file_1[MGCP_FILENAME_PATH_SIZE];
    char tmp_file_2[MGCP_FILENAME_PATH_SIZE];
    char media_conv[MGCP_FILENAME_PATH_SIZE];
    char cmd[MGCP_FILENAME_PATH_SIZE*3];
    bool aud1, aud2;
    struct stat fsbuf;
    pei_component *cmpn;

    /* close all files */
    if (call->cr.fp != NULL)
        fclose(call->cr.fp);
    if (call->cd.fp != NULL)
        fclose(call->cd.fp);
    if (call->cmd_fp)
        fclose(call->cmd_fp);

    /* audio decoding */
    sprintf(cmd, "videosnarf -i %s -o %s 2>/dev/null 1>/dev/null", call->cr.file_name, call->cr.file_name);
    ret = system(cmd);
    if (ret == -1) {
        LogPrintf(LV_WARNING, "videosnarf failed");
    }
    else if (WEXITSTATUS(ret) != 0) {
        switch (WEXITSTATUS(ret)) {
        case 127:
            LogPrintf(LV_WARNING, "'videosnarf' command not found by shell");
            break;
            
        default:
            LogPrintf(LV_WARNING, "videosnarf crashed");
        }
    }
    sprintf(cmd, "videosnarf -i %s -o %s 2>/dev/null 1>/dev/null", call->cd.file_name, call->cd.file_name);
    ret = system(cmd);
    if (ret == -1) {
        LogPrintf(LV_WARNING, "videosnarf failed");
    }
    else if (WEXITSTATUS(ret) != 0) {
        switch (WEXITSTATUS(ret)) {
        case 127:
            LogPrintf(LV_WARNING, "'videosnarf' command not found by shell");
            break;
            
        default:
            LogPrintf(LV_WARNING, "videosnarf crashed");
        }
    }
    /* delete pcap files */
#if NO_DEBUG_RM
    remove(call->cr.file_name);
    remove(call->cd.file_name);
#endif
    sprintf(media_file_2, "%s-media-1.wav", call->cr.file_name);
    sprintf(media_file_1, "%s-media-1.wav", call->cd.file_name);
    sprintf(media_conv, "%s/%s/mgcp_media_%p_%lu", ProtTmpDir(), MGCP_TMP_DIR, call, time(NULL));

    /* complete pei */
    /*  from */
    PeiNewComponent(&cmpn, pei_from_id);
    PeiCompCapTime(cmpn, call->start_time_sec);
    PeiCompAddStingBuff(cmpn, call->from);
    PeiAddComponent(call->ppei, cmpn);
    /*  to */
    PeiNewComponent(&cmpn, pei_to_id);
    PeiCompCapTime(cmpn, call->start_time_sec);
    PeiCompAddStingBuff(cmpn, call->to);
    PeiAddComponent(call->ppei, cmpn);
    /*  duration */
    sprintf(cmd, "%lu", call->audio_cr.end_time_sec - call->audio_cr.start_time_sec);
    PeiNewComponent(&cmpn, pei_duration_id);
    PeiCompCapTime(cmpn, call->start_time_sec);
    PeiCompAddStingBuff(cmpn, cmd);
    PeiAddComponent(call->ppei, cmpn);
    /* commands */
    PeiNewComponent(&cmpn, pei_cmd_id);
    PeiCompCapTime(cmpn, call->start_time_sec);
    PeiCompCapEndTime(cmpn, call->end_time_sec);
    PeiCompAddFile(cmpn, "mgcp_commands.txt", call->cmd_file, 0);
    PeiAddComponent(call->ppei, cmpn);
    
    /*  audio from */
    aud2 = FALSE;
    if (stat(media_file_2, &fsbuf) == 0) {
        aud2 = TRUE;
        /* convert to be used with lame */
        sprintf(tmp_file_2, "%s_2.wav", media_conv);
        sprintf(cmd, "sox %s -e signed-integer %s 2>/dev/null 1>/dev/null", media_file_2, tmp_file_2);
        ret = system(cmd);
#if NO_DEBUG_RM
        remove(media_file_2);
#endif
        /* mp3 conversion */
        sprintf(media_file_2, "%s_2.mp3", media_conv);
        sprintf(cmd, "lame --quiet -h %s %s 2>/dev/null 1>/dev/null", tmp_file_2, media_file_2);
        ret = system(cmd);
        if (ret == -1) {
            LogPrintf(LV_WARNING, "lame failed");
        }
        else if (WEXITSTATUS(ret) != 0) {
            switch (WEXITSTATUS(ret)) {
            case 127:
                LogPrintf(LV_WARNING, "'lame' command not found by shell");
                break;
                
            default:
                LogPrintf(LV_WARNING, "lame crashed: %s", cmd);
            }
        }
        if (stat(media_file_2, &fsbuf) == 0) {
            PeiNewComponent(&cmpn, pei_audio_from_id);
            PeiCompCapTime(cmpn, call->audio_cr.start_time_sec);
            PeiCompCapEndTime(cmpn, call->audio_cr.end_time_sec);
            PeiCompAddFile(cmpn, "audio_caller.mp3", media_file_2, fsbuf.st_size);
            PeiAddComponent(call->ppei, cmpn);
        }
        sprintf(media_file_2, "%s_stereo_2.wav", media_conv);
        sprintf(cmd, "sox %s -c 2 %s delay 0 remix 1v0 1 2>/dev/null 1>/dev/null", tmp_file_2, media_file_2);
        ret = system(cmd);
#if NO_DEBUG_RM
        remove(tmp_file_2);
#endif
    }
    /*  audio to */
    aud1 = FALSE;
    if (stat(media_file_1, &fsbuf) == 0) {
        aud1 = TRUE;
        /* convert to be used with lame */
        sprintf(tmp_file_1, "%s_1.wav", media_conv);
        sprintf(cmd, "sox %s -e signed-integer %s 2>/dev/null 1>/dev/null", media_file_1, tmp_file_1);
        ret = system(cmd);
#if NO_DEBUG_RM
        remove(media_file_1);
#endif
        /* mp3 conversion */
        sprintf(media_file_1, "%s_1.mp3", media_conv);
        sprintf(cmd, "lame --quiet -h %s %s 2>/dev/null 1>/dev/null", tmp_file_1, media_file_1);
        ret = system(cmd);
        if (ret == -1) {
            LogPrintf(LV_WARNING, "lame failed");
        }
        else if (WEXITSTATUS(ret) != 0) {
            switch (WEXITSTATUS(ret)) {
            case 127:
                LogPrintf(LV_WARNING, "'lame' command not found by shell");
                break;
                
            default:
                LogPrintf(LV_WARNING, "lame crashed %s", cmd);
            }
        }
        if (stat(media_file_1, &fsbuf) == 0) {
            PeiNewComponent(&cmpn, pei_audio_to_id);
            PeiCompCapTime(cmpn, call->audio_cd.start_time_sec);
            PeiCompCapEndTime(cmpn, call->audio_cd.end_time_sec);
            PeiCompAddFile(cmpn, "audio_called.mp3", media_file_1, fsbuf.st_size);
            PeiAddComponent(call->ppei, cmpn);
        }
        sprintf(media_file_1, "%s_stereo_1.wav", media_conv);
        sprintf(cmd, "sox %s -c 2 %s delay 0 remix 1 1v0 2>/dev/null 1>/dev/null", tmp_file_1, media_file_1);
        ret = system(cmd);
#if NO_DEBUG_RM
        remove(tmp_file_1);
#endif
    }
    /*  mix audio */
    if (aud2 || aud1) {
        /* mix two audio files */
        sprintf(tmp_file_1, "%s_mix.wav", media_conv);
        sprintf(tmp_file_2, "%s_mix.mp3", media_conv);
        if (aud1 == FALSE) {
            sprintf(cmd, "sox %s %s 2>/dev/null 1>/dev/null", media_file_2, tmp_file_1);
        }
        else if (aud2 == FALSE) {
            sprintf(cmd, "sox %s %s 2>/dev/null 1>/dev/null", media_file_1, tmp_file_1);
        }
        else {
            sprintf(cmd, "sox -m %s %s -e signed-integer %s 2>/dev/null 1>/dev/null", media_file_2, media_file_1, tmp_file_1);
        }
        ret = system(cmd);
        if (ret == -1) {
            LogPrintf(LV_WARNING, "sox failed");
        }
        else if (WEXITSTATUS(ret) != 0) {
            switch (WEXITSTATUS(ret)) {
            case 127:
                LogPrintf(LV_WARNING, "'sox' command not found by shell");
                break;
                
            default:
                LogPrintf(LV_WARNING, "sox mix crash: %s", cmd);
            }
        }       
        /* mp3 conversion */
        sprintf(cmd, "lame --quiet -h %s %s 2>/dev/null 1>/dev/null", tmp_file_1, tmp_file_2);
        ret = system(cmd);
        /* delete temporary files */
#if NO_DEBUG_RM
        remove(media_file_1);
        remove(media_file_2);
        remove(tmp_file_1);
#endif
        if (stat(tmp_file_2, &fsbuf) == 0) {
            PeiNewComponent(&cmpn, pei_audio_mix_id);
            PeiCompCapTime(cmpn, call->audio_cr.start_time_sec);
            PeiCompCapEndTime(cmpn, call->audio_cr.end_time_sec);
            PeiCompAddFile(cmpn, "audio_mix.mp3", tmp_file_2, fsbuf.st_size);
            PeiAddComponent(call->ppei, cmpn);
        }
    }

    /* insert pei */
    PeiIns(call->ppei);
    call->ppei = NULL;

    MgcpCallFree(call);

    return 0;
}


static packet *MgcpDissector(int flow_id)
{
    mgcp_msg msg;
    packet *pkt;
    mgcp_call *list, *call, *ctmp;
    char  *sdp;
    int len;
    int rid, gid;
    cmp_val rip, rport;
    sdp_msg *sdpm;
    bool wto, cend, flowsend;
    int media_id;

    LogPrintf(LV_DEBUG, "MGCP id: %d", flow_id);

    list = NULL;
    gid = FlowGrpId(flow_id);
    flowsend = FALSE;
    do {
        call = NULL;
        wto = TRUE;
        /* main UDP stream */
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            wto = FALSE;
            MgcpMsgDec(&msg, pkt);
            len = strlen(msg.conn_id);
            if (msg.mtd != MGCP_MT_NONE) {
                if (msg.mtd == MGCP_MT_MDCX || msg.mtd == MGCP_MT_CRCX) {
                    if (msg.conn_id[0] != '\0') {
                        call = list;
                        while (call != NULL) {
                            if (strncmp(call->id, msg.conn_id, len) == 0)
                                break;
                            call = call->nxt;
                        }
                    }
                    else {
                        /* new call */
                        call = NULL;
                    }
                    
                    if (call == NULL) {
                        LogPrintf(LV_DEBUG, "New call");
                        /* new MDCX/CRCX  -> new call */
                        
                        call = xmalloc(sizeof(mgcp_call));
                        MgcpCallInit(call, pkt, flow_id, &msg);
                        MgcpTo(call, pkt->data, pkt->len);
                        call->nxt = list;
                        if (list == NULL) {
                            FlowSetTimeOut(flow_id, MGCP_PKT_TIMEOUT);
                        }
                        list = call;
                        call->start_time_sec = pkt->cap_sec;
                    }
                    if (call->cmd_fp != NULL)
                        fwrite(pkt->data, 1, pkt->len, call->cmd_fp);
                    call->end_time_sec = pkt->cap_sec;
                }
                else {
                    /* other methods */
                    /* search conn_id */
                    call = list;
                    while (call != NULL) {
                        if (strncmp(call->id, msg.conn_id, len) == 0)
                            break;
                        call = call->nxt;
                    }
                    if (call != NULL) {
                        call->end_time_sec = pkt->cap_sec;
                        if (call->cmd_fp != NULL)
                            fwrite(pkt->data, 1, pkt->len, call->cmd_fp);
                        if (msg.mtd == MGCP_MT_DLCX) {
                            if (call->rule_cr_id != -1) {
                                GrpRuleRm(call->rule_cr_id);
                                call->rule_cr_id = -1;
                            }
                            if (call->rule_cd_id != -1) {
                                GrpRuleRm(call->rule_cd_id);
                                call->rule_cd_id = -1;
                            }
                            call->closed = TRUE;
                        }
                    }
                    else {
                        /* all in the last call */
                        if (list != NULL) {
                            list->end_time_sec = pkt->cap_sec;
                            fwrite(pkt->data, 1, pkt->len, list->cmd_fp);
                            
                            if (msg.mtd == MGCP_MT_NTFY) {
                                /* phone number */
#warning "to complete"
                            }
                        }
                    }
                }
            }
            else {
                /* MGCP response */
                if (msg.status != MGCP_ST_NONE)
                    LogPrintf(LV_DEBUG, "MGCP response");
                    
                /* search call */
                call = list;
                if (call != NULL && call->id[0] != '\0') {
                    while (call != NULL) {
                        if (strncmp(call->id, msg.conn_id, len) == 0)
                            break;
                        call = call->nxt;
                    }
                }
                else {
                    if (call != NULL)
                        len = strlen(msg.tran_id);
                    while (call != NULL) {
                        if (strncmp(call->tran_id, msg.tran_id, len) == 0) {
                            strcpy(call->id, msg.conn_id);
                            break;
                        }
                        call = call->nxt;
                    }
                }
                if (call != NULL) {
                    call->end_time_sec = pkt->cap_sec;
                    if (call->cmd_fp != NULL)
                        fwrite(pkt->data, 1, pkt->len, call->cmd_fp);
                }
            }
            if (call != NULL) {
                /* sdp */
                sdp = MgcpHeaderEnd(pkt->data, pkt->len);
                if (sdp != NULL && (pkt->len - (sdp - pkt->data)) > 3) {
                    //ProtStackFrmDisp(pkt->stk, TRUE);
                    sdp +=  1;
                    /* pdu */
                    pkt->len = pkt->len - (sdp - pkt->data);
                    pkt->data = sdp;
                    if (sdp_id != -1) {
                        pkt = ProtDissecPkt(sdp_id, pkt);
                        if (pkt != NULL) {
                            sdpm = (sdp_msg *)pkt->data;
                            SdpMsgPrint(sdpm);
                            if (call->rule_cr_id == -1 && msg.mtd != MGCP_MT_NONE) { /* this is a big limitation */
                                if (sdpm->cntn_info.nettype != SDP_NETTP_NONE) {
                                    rid = GrpRuleNew(flow_id);
                                    LogPrintf(LV_DEBUG, "Rule 1 %i, ip:%s port:%i", rid, sdpm->cntn_info.address, sdpm->transp.port[0]);
                                    rip.prot = ip_id;
                                    rip.att = ip_dst_id;
                                    inet_pton(AF_INET, sdpm->cntn_info.address, &rip.val.uint32);
                                    rport.prot = udp_id;
                                    rport.att = uport_dst_id;
                                    rport.val.int16 = sdpm->transp.port[0];
                                    GrpRule(rid, 2, &rip, &rport);
                                    rip.att = ip_src_id;
                                    rport.att = uport_src_id;
                                    GrpRule(rid, 2, &rip, &rport);
                                    GrpRuleCmplt(rid);
                                    call->rule_cr_id = rid;
                                    // data 
                                    call->audio_cr.ipv6 = FALSE;
                                    call->audio_cr.ip_dst.uint32 = rip.val.uint32;
                                    call->audio_cr.dst_port.int16 = rport.val.int16;
                                    MgcpStorageInit(call, flow_id);
                                }
                            }
                            else if (call->rule_cd_id == -1 && msg.mtd == MGCP_MT_NONE) { /* this is a big limitation */
                                if (sdpm->cntn_info.nettype != SDP_NETTP_NONE) {
                                    rid = GrpRuleNew(flow_id);
                                    LogPrintf(LV_DEBUG, "Rule 2 %i, ip:%s port:%i", rid, sdpm->cntn_info.address, sdpm->transp.port[0]);
                                    rip.prot = ip_id;
                                    rip.att = ip_dst_id;
                                    inet_pton(AF_INET, sdpm->cntn_info.address, &rip.val.uint32);
                                    rport.prot = udp_id;
                                    rport.att = uport_dst_id;
                                    rport.val.int16 = sdpm->transp.port[0];
                                    GrpRule(rid, 2, &rip, &rport);
                                    rip.att = ip_src_id;
                                    rport.att = uport_src_id;
                                    GrpRule(rid, 2, &rip, &rport);
                                    GrpRuleCmplt(rid);
                                    call->rule_cd_id = rid;
                                    // data 
                                    call->audio_cd.ipv6 = FALSE;
                                    call->audio_cd.ip_dst.uint32 = rip.val.uint32;
                                    call->audio_cd.dst_port.int16 = rport.val.int16;
                                    MgcpStorageInit(call, flow_id);
                                }
                            }
                            SdpMsgFree(sdpm);
                        }
                    }
                }
            }
        }
        /* free packet */
        if (pkt != NULL) {
            wto = FALSE;
            PktFree(pkt);
        }
        else if (FlowIsEmpty(flow_id)) {
            /* close all call */
            call = list;
            while (call != NULL) {
                if (call->rule_cr_id != -1) {
                    GrpRuleRm(call->rule_cr_id);
                    call->rule_cr_id = -1;
                }
                if (call->rule_cd_id != -1) {
                    GrpRuleRm(call->rule_cd_id);
                    call->rule_cd_id = -1;
                }
                call->closed = TRUE;
                call = call->nxt;
            }
        }

        /* wait media flow */
        media_id = GrpLink(gid);
        if (media_id != -1) {
            call = list;
            while (call != NULL) {
                if (MgcpMediaFlow(call, media_id) == 0) {
                    FlowSetTimeOut(flow_id, 0);
                    break;
                }
                call = call->nxt;
            }
            if (call == NULL) {
                LogPrintf(LV_ERROR, "Media without a call");
            }
        }

        /* read pkt from media */
        call = list;
        while (call != NULL) {
            if (call->audio_rtp_cr != -1) {
                pkt = FlowGetPkt(call->audio_rtp_cr);
                if (pkt != NULL) {
                    MgcpPktStorageCr(call, pkt);
                    wto = FALSE;
                    PktFree(pkt);
                }
                else if (FlowIsEmpty(call->audio_rtp_cr)) {
                    call->audio_rtp_cr = -1;
                }
            }
            if (call->audio_rtp_cd != -1) {
                pkt = FlowGetPkt(call->audio_rtp_cd);
                if (pkt != NULL) {
                    MgcpPktStorageCd(call, pkt);
                    wto = FALSE;
                    PktFree(pkt);
                }
                else if (FlowIsEmpty(call->audio_rtp_cd)) {
                    call->audio_rtp_cd = -1;
                }
            }
            call = call->nxt;
        }
        
        /* if no data... wait */
        if (list != NULL) {
            if (wto)
                FlowSetTimeOut(flow_id, MGCP_PKT_TIMEOUT);
            else
                FlowSetTimeOut(flow_id, 0);
        }
        
        /* check call status */
        ctmp = NULL;
        call = list;
        flowsend = FlowIsEmpty(flow_id);
        while (call != NULL) {
            cend = FALSE;
            if ((call->id != '\0' || flowsend == TRUE) &&
                call->rule_cr_id == -1 && call->rule_cd_id == -1) {
                cend = TRUE;
                if (call->audio_rtp_cr != -1) {                        
                    cend = FALSE;
                }
                if (call->audio_rtp_cd != -1) {
                    cend = FALSE;
                }
                if (cend) {
                    call->closed = TRUE;
                }
            }
            if (call->closed && cend) {
                /* call teminated */
                if (ctmp != NULL) {
                    ctmp->nxt = call->nxt;
                }
                else 
                    list = call->nxt;

                /* convert file and complete pei */
                MgcpCallPei(call);

                if (list == NULL)
                    FlowSetTimeOut(flow_id, -1);
                if (ctmp != NULL)
                    call = ctmp->nxt;
                else
                    call = list;
            }
            else {
                ctmp = call;
                call = call->nxt;
            }
        }
    } while (list != NULL || flowsend == FALSE);

    LogPrintf(LV_DEBUG, "MGCP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool MgcpVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    char *data, *new;
    const char *eol, *lineend;
    unsigned long len;
    int cmp;
    mgcp_ver ver;
    bool ret, fr_data;
    ftval lost, ips, ip_s;
    bool ipv4, udp;
    short preaded;

    ipv4 = FALSE;
    udp = FALSE;
    ret = FALSE;
    fr_data = FALSE;
    lost.uint8 = FALSE; /* by default -for udp- */

    pkt = FlowGetPktCp(flow_id);
    preaded = 1;
    if (pkt != NULL) {
        //ProtStackFrmDisp(pkt->stk, TRUE);
        /* check if udp or tcp */
        if (ProtFrameProtocol(pkt->stk) == udp_id)
            udp = TRUE;
        /* check ip */
        ip = ProtGetNxtFrame(pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id)
            ipv4 = TRUE;
        if (ipv4 == TRUE)
            ProtGetAttr(ip, ip_src_id, &ips);
        else
            ProtGetAttr(ip, ipv6_src_id, &ips);
        if (!udp)
            ProtGetAttr(pkt->stk, lost_id, &lost);
        while (lost.uint8 == FALSE && pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
            if (!udp)
                ProtGetAttr(pkt->stk, lost_id, &lost);
        }
    }
    if (pkt != NULL) {
        if (lost.uint8 == FALSE) {
            data = (char *)pkt->data;
            len = pkt->len;
            do {
                lineend = find_line_end(data, data+len, &eol);
                if (lineend != data+len && (*eol == '\r' || *eol == '\n')) {
                    /* check if msg request */
                    ver = MgcpReqVersion(data, lineend-data);
                    if (ver != MGCP_VER_NONE) {
                        if (check == FALSE) {
                            ret = TRUE;
                            break;
                        }
                        else if (MgcpReqMethod(data, lineend-data) != MGCP_MT_NONE) {
                            if (MgcpHeaderEnd(data, len) != NULL) {
                                ret = TRUE;
                                break;
                            }
                        }
                    }
                    else {
                        /* check if msg response */
                        ver = MgcpResValid(data, lineend-data);
                        if (ver == MGCP_ST_NONE)
                            break;
                        /* do noting, we wait a msg request */
                        preaded = 1;
                    }
                }
                if (udp == FALSE) {
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
                        ip = ProtStackSearchProt(pkt->stk, ip_id);
                        if (ipv4 == TRUE) {
                            ProtGetAttr(ip, ip_src_id, &ip_s);
                            cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
                        }
                        else {
                            ProtGetAttr(ip, ipv6_src_id, &ip_s);
                            cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
                        }
                        if (cmp == 0) {
                            if (!udp)
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
                        }
                    }
                }
                else {
                    PktFree(pkt);
                    pkt = NULL;
                    if (preaded != MGCP_PKT_NULL_LIMIT) {
                        pkt = FlowGetPktCp(flow_id);
                        if (pkt != NULL) {
                            preaded++;
                            data = (char *)pkt->data;
                            len = pkt->len;
                        }
                    }
                }
            } while (pkt != NULL && len < 4096); /* 4k: max mgcp request length */

            /* free memory */
            if (data != NULL && fr_data == TRUE) {
                xfree(data);
            }
        }
        
        if (pkt != NULL)
            PktFree(pkt);
    }
    
    return ret;
}


static bool MgcpVerify(int flow_id)
{
    return MgcpVerifyCheck(flow_id, FALSE);
}


static bool MgcpCheck(int flow_id)
{
    return MgcpVerifyCheck(flow_id, TRUE);
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
    ProtName("Media Gateway Control Protocol", "mgcp");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_MGCP;
    dep.ProtCheck = MgcpVerify;
    dep.pktlim = MGCP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = UDP_PORT_MGCP;
    dep.ProtCheck = MgcpVerify;
    dep.pktlim = MGCP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = UDP_PORT_MGCP_CA;
    dep.ProtCheck = MgcpVerify;
    dep.pktlim = MGCP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = MgcpCheck;
    hdep.pktlim = MGCP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "to";
    peic.desc = "Called";
    ProtPeiComponent(&peic);

    peic.abbrev = "from";
    peic.desc = "Caller";
    ProtPeiComponent(&peic);

    peic.abbrev = "cmd";
    peic.desc = "MGCP commands";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "audio_from";
    peic.desc = "Caller audio file";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "audio_to";
    peic.desc = "Called audio file";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "audio_mix";
    peic.desc = "Caller and Called";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "duration";
    peic.desc = "Call duration";
    ProtPeiComponent(&peic);

    /* group protocol (master flow) */
    ProtGrpEnable();
    
    /* dissectors registration */
    ProtDissectors(NULL, MgcpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char mgcp_dir[256];
    
    /* info id */
    ppp_id = ProtId("ppp");
    eth_id = ProtId("eth");
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ip_offset_id = ProtAttrId(ip_id, "ip.offset");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    tcp_id = ProtId("tcp");
    tport_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    tport_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    udp_id = ProtId("udp");
    uport_dst_id = ProtAttrId(udp_id, "udp.dstport");
    uport_src_id = ProtAttrId(udp_id, "udp.srcport");
    lost_id = ProtAttrId(tcp_id, "tcp.lost");
    clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    sdp_id = ProtId("sdp");
    mgcp_id = ProtId("mgcp");

    /* pei id */
    pei_from_id = ProtPeiComptId(mgcp_id, "from");
    pei_to_id = ProtPeiComptId(mgcp_id, "to");
    pei_cmd_id = ProtPeiComptId(mgcp_id, "cmd");
    pei_audio_from_id = ProtPeiComptId(mgcp_id, "audio_from");
    pei_audio_to_id = ProtPeiComptId(mgcp_id, "audio_to");
    pei_audio_mix_id = ProtPeiComptId(mgcp_id, "audio_mix");
    pei_duration_id = ProtPeiComptId(mgcp_id, "duration");

    /* mgcp tmp directory */
    sprintf(mgcp_dir, "%s/%s", ProtTmpDir(), MGCP_TMP_DIR);
    mkdir(mgcp_dir, 0x01FF);
    incr = 0;

    return 0;
}
