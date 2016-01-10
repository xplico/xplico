/* sip.c
 * Dissector of SIP protocol
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * based on: packet-sip.c of Wireshark
 *   Copyright 1998 Gerald Combs
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

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "flow.h"
#include "log.h"
#include "sip.h"
#include "pei.h"
#include "sdp.h"
#include "pcap_gfile.h"
#include "grp_rule.h"
#include "grp_flows.h"

#define NO_DEBUG_RM    1  /* if 1 then all files are removed from tmp dir */

#define SIP_TMP_DIR    "sip"

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
static int sip_id;

/* pei id */
static int pei_to_id;
static int pei_from_id;
static int pei_cmd_id;
static int pei_audio_from_id;
static int pei_audio_to_id;
static int pei_audio_mix_id;
static int pei_duration_id;

static volatile unsigned int incr;

#if 0
/* PUBLISH method added as per http://www.ietf.org/internet-drafts/draft-ietf-sip-publish-01.txt */
static const char *sip_methods[] = {
        "ACK",
        "BYE",
        "CANCEL",
        "DO",
        "INFO",
        "INVITE",
        "MESSAGE",
        "NOTIFY",
        "OPTIONS",
        "PRACK",
        "QAUTH",
        "REFER",
        "REGISTER",
        "SPRACK",
        "SUBSCRIBE",
        "UPDATE",
        "PUBLISH"
};
#endif

static sip_ver SipReqVersion(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return SIP_VER_NONE;
    }
    line = next_token;

    /* The next token is the URI. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return SIP_VER_NONE;
    line = next_token;

    /* Everything to the end of the line is the version. */
    tokenlen = lineend - line;
    if (tokenlen == 0)
        return SIP_VER_NONE;
    
    if (strncmp(line, "SIP/2.0", 7) == 0)
        return SIP_VER_2_0;

    return SIP_VER_NONE;
}


static sip_ver SipResVersion(const char *line, int len)
{
    if (strncmp(line, "SIP/2.0", 7) == 0)
        return SIP_VER_2_0;

    return SIP_VER_NONE;
}


static sip_mthd SipReqMethod(const char *data, int linelen)
{
    const char *ptr;
    int	index = 0;

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

    /* Check the methods that have same length */
    switch (index) {
    case 2:
        if (strncmp(data, "DO", index) == 0) {
            return SIP_MT_DO;
        }
        break;

    case 3:
        if (strncmp(data, "ACK", index) == 0) {
            return SIP_MT_ACK;
        }
        else if (strncmp(data, "BYE", index) == 0) {
            return SIP_MT_BYE;
        }
        break;

    case 4:
        if (strncmp(data, "INFO", index) == 0) {
            return SIP_MT_INFO;
        }
        break;

    case 5:
        if (strncmp(data, "PRACK", index) == 0) {
            return SIP_MT_PRACK;
        }
        else if (strncmp(data, "QAUTH", index) == 0) {
            return SIP_MT_QAUTH;
        }
        else if (strncmp(data, "REFER", index) == 0) {
            return SIP_MT_REFER;
        }
        break;

    case 6:
        if (strncmp(data, "CANCEL", index) == 0) {
            return SIP_MT_CANCEL;
        }
        else if (strncmp(data, "INVITE", index) == 0) {
            return SIP_MT_INVITE;
        }
        else if (strncmp(data, "NOTIFY", index) == 0) {
            return SIP_MT_NOTIFY;
        }
        else if (strncmp(data, "SPRACK", index) == 0) {
            return SIP_MT_SPRACK;
        }
        else if (strncmp(data, "UPDATE", index) == 0) {
            return SIP_MT_UPDATE;
        }
        break;

    case 7:
        if (strncmp(data, "MESSAGE", index) == 0) {
            return SIP_MT_MESSAGE;
        }
        else if (strncmp(data, "OPTIONS", index) == 0) {
            return SIP_MT_OPTIONS;
        }
        else if (strncmp(data, "PUBLISH", index) == 0) {
            return SIP_MT_PUBLISH;
        }
        break;

    case 8:
        if (strncmp(data, "REGISTER", index) == 0) {
            return SIP_MT_REGISTER;
        }
        break;

    case 9:
        if (strncmp(data, "SUBSCRIBE", index) == 0) {
            return SIP_MT_SUBSCRIBE;
        }
        break;

    default:
        break;
    }

    if (index > 0)
        LogPrintf(LV_WARNING, "Sip method (dim:%i) \"%s\" don't managed.", index, data);

    return SIP_MT_NONE;
}


static sip_status SipRespStatus(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    sip_status status;
    int tokenlen, val;

    lineend = line + len;
    status = SIP_ST_NONE;

    /* The first token is the protocol and version */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return status;
    }

    line = next_token;
    /* The next token is status value. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || (line[tokenlen] != ' ' && line[tokenlen] != '\r' && line[tokenlen] != '\n')) {
        return status;
    }
    if (sscanf(line, "%i", &val) != 1) {
        LogPrintf(LV_ERROR, "SIP return status\n");

        return status;
    }
    
    /* search enum */
    if (val < 200)
         return SIP_ST_1XX;
    else if (val < 300)
        return SIP_ST_2XX;
    else if (val < 400)
        return SIP_ST_3XX;
    else if (val < 500)
        return SIP_ST_4XX;
    else if (val < 600)
        return SIP_ST_5XX;
    else if (val < 700)
        return SIP_ST_6XX;
        
    LogPrintf(LV_WARNING, "SIP return status unknown!!!\n");

    return status;
}


static bool SipMediaPkt(rtx_media *media, const packet *pkt)
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


static char* SipHeaderEnd(const char *header, unsigned long len)
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


sip_msg *SipMessage(int flow_id, sip_msg **partial)
{
    packet* pkt;
    sip_msg *msg;

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


static void SipCallInit(sip_call *call, const packet *pkt, int flow_id, const char *call_id)
{
    memset(call, 0, sizeof(sip_call));
    call->sdp_cr = NULL;
    call->sdp_cd = NULL;
    call->rule_cr_id = -1;
    call->rule_cd_id = -1;
    call->sdp = FALSE;
    call->audio_rtp_cr = -1;
    call->audio_rtp_cd = -1;
    call->audio_rtcp_cr = -1;
    call->audio_rtcp_cd = -1;
    //call->audio_cr = NULL;
    //call->audio_cd = NULL;
    strcpy(call->id, call_id);
    call->closed = FALSE;
    /* pei */
    PeiNew(&(call->ppei), sip_id);
    PeiCapTime(call->ppei, pkt->cap_sec);
    PeiMarker(call->ppei, pkt->serial);
    PeiStackFlow(call->ppei, FlowStack(flow_id));
    /* commands component */
    incr++;
    sprintf(call->cmd_file, "%s/%s/sip_cmd_%lu_%d.txt", ProtTmpDir(), SIP_TMP_DIR, time(NULL), incr);
    call->cmd_fp = fopen(call->cmd_file, "w");
}


static void SipCallFree(sip_call *call)
{
    xfree(call);
}


static int SipMsgDec(sip_msg *msg, packet *pkt)
{
    char *call_id, *end, c;
    sip_ver ver;

    memset(msg, 0, sizeof(sip_msg));
    msg->status = SIP_ST_NONE;
    ver = SipReqVersion(pkt->data, pkt->len);
    if (ver != SIP_VER_NONE) {
        msg->mtd = SipReqMethod(pkt->data, pkt->len);
    }
    else {
        msg->mtd = SIP_MT_NONE;
        /* respose ? */
        msg->status = SipRespStatus(pkt->data, pkt->len);
    }
    /* find call id */
    call_id = strstr(pkt->data, "Call-ID: ");
    if (call_id == NULL) {
        call_id = strstr(pkt->data, "i: ");
        if (call_id != NULL)
            call_id += 3;
    }
    else {
        call_id += 9;
    }

    if (call_id != NULL) {
        end = strchr(call_id, '\r');
        c = '\r';
        if (end == NULL) {
            end = strchr(call_id, '\n');
            c = '\n';
        }
        if (end != NULL) {
            *end = '\0';
            strncpy(msg->call_id, call_id, SIP_HEADER_LINE);
            *end = c;
        }
    }

    return 0;
}


static void SipFromTo(sip_call *call, const char *data, unsigned long len)
{
    const char *from, *to, *end, *par, *tok;
    
    from = strstr(data, "From: ");
    if (from == NULL) {
        from = strstr(data, "f: ");
        if (from != NULL)
            from += 3;
    }
    else {
        from = from + 6;
    }
    to = strstr(data, "To: ");
    if (to == NULL) {
        to = strstr(data, "t: ");
        if (to != NULL)
            to += 3;
    }
    else {
        to = to + 4;
    }
    
    /* from */
    if (from != NULL) {
        tok = strchr(from, ';');
        par = strchr(from, '>');
        end = strchr(from, '\r');
        if (tok != NULL) {
            if (tok < end) {
                strncpy(call->from, from, tok-from);
                call->from[tok-from] = '\0';
            }
            else {
                strncpy(call->from, from, end-from);
                call->from[end-from] = '\0';
            }
        }
        else {
            strncpy(call->from, from, end-from);
            call->from[end-from] = '\0';
        }
        LogPrintf(LV_DEBUG, "From: %s", call->from);
    }
    /* to */
    if( to != NULL) {
        tok = strchr(to, ';');
        par = strchr(to, '>');
        end = strchr(to, '\r');
        if (tok != NULL) {
            if (tok < end) {
                strncpy(call->to, to, tok-to);
                call->to[tok-to] = '\0';
            }
            else {
                strncpy(call->to, to, end-to);
                call->to[end-to] = '\0';
            }
        }
        else {
            strncpy(call->to, to, end-to);
            call->to[end-to] = '\0';
        }
        LogPrintf(LV_DEBUG, "To: %s", call->to);
    }
}


static int SipStorageInit(sip_call *call, int flow_id)
{
    struct pcap_file_header fh;

    sprintf(call->cr.file_name, "%s/%s/sip_cr_%lu_%d.pcap", ProtTmpDir(), SIP_TMP_DIR, time(NULL), incr);
    sprintf(call->cd.file_name, "%s/%s/sip_cd_%lu_%d.pcap", ProtTmpDir(), SIP_TMP_DIR, time(NULL), incr);
    call->cr.fp = fopen(call->cr.file_name, "wb");
    call->cd.fp = fopen(call->cd.file_name, "wb");
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


static int SipMediaFlow(sip_call *call, int media_id)
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


static int SipPktStorageCr(sip_call *call, const packet *pkt)
{
    const pstack_f *ip;
    struct pcappkt_hdr pckt_header;
    size_t nwrt, wcnt;
    ftval offset;

    if (SipMediaPkt(&(call->audio_cr), pkt)) {
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


static int SipPktStorageCd(sip_call *call, const packet *pkt)
{
    const pstack_f *ip;
    struct pcappkt_hdr pckt_header;
    size_t nwrt, wcnt;
    ftval offset;
    
    if (SipMediaPkt(&(call->audio_cd), pkt)) {
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


static int SipCallPei(sip_call *call)
{
    int ret;
    char media_file_1[SIP_FILENAME_PATH_SIZE];
    char media_file_2[SIP_FILENAME_PATH_SIZE];
    char tmp_file_1[SIP_FILENAME_PATH_SIZE];
    char tmp_file_2[SIP_FILENAME_PATH_SIZE];
    char media_conv[SIP_FILENAME_PATH_SIZE];
    char cmd[SIP_FILENAME_PATH_SIZE*3];
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
    if (call->cr.file_name[0] != '\0') {
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
    }
    if (call->cd.file_name[0] != '\0') {
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
                LogPrintf(LV_WARNING, "videosnarf crash");
            }
        }
    }
    /* delete pcap files */
#if NO_DEBUG_RM
    remove(call->cr.file_name);
    remove(call->cd.file_name);
#endif
    sprintf(media_file_2, "%s-media-1.wav", call->cr.file_name);
    sprintf(media_file_1, "%s-media-1.wav", call->cd.file_name);
    sprintf(media_conv, "%s/%s/sip_media_%p_%lu", ProtTmpDir(), SIP_TMP_DIR, call, time(NULL));

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
    PeiCompAddFile(cmpn, "sip_commands.txt", call->cmd_file, 0);
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
                LogPrintf(LV_WARNING, "lame crashes: %s", cmd);
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
        if (ret == -1) {
            LogPrintf(LV_WARNING, "sox failed");
        }
        else if (WEXITSTATUS(ret) != 0) {
            switch (WEXITSTATUS(ret)) {
            case 127:
                LogPrintf(LV_WARNING, "'sox' command not found by shell");
                break;
                
            default:
                LogPrintf(LV_WARNING, "sox crashed: %s", cmd);
            }
        }
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
                LogPrintf(LV_WARNING, "lame crashed: %s", cmd);
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
        if (ret == -1) {
            LogPrintf(LV_WARNING, "sox failed");
        }
        else if (WEXITSTATUS(ret) != 0) {
            switch (WEXITSTATUS(ret)) {
            case 127:
                LogPrintf(LV_WARNING, "'sox' command not found by shell");
                break;
                
            default:
                LogPrintf(LV_WARNING, "sox crashed: %s", cmd);
            }
        }
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
                LogPrintf(LV_WARNING, "sox mix crashed: %s", cmd);
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

    SipCallFree(call);

    return 0;
}


static packet *SipDissector(int flow_id)
{
    sip_msg msg;
    packet *pkt;
    sip_call *list, *call, *ctmp;
    char  *sdp;
    int len;
    int rid, gid;
    cmp_val rip, rport;
    sdp_msg *sdpm;
    bool wto, cend;
    int media_id;
    time_t cap_sec;

    LogPrintf(LV_DEBUG, "SIP id: %d", flow_id);

    list = NULL;
    gid = FlowGrpId(flow_id);
    do {
        call = NULL;
        wto = TRUE;
        /* main UDP stream */
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            cap_sec = pkt->cap_sec;
            wto = FALSE;
            SipMsgDec(&msg, pkt);
            len = strlen(msg.call_id);
            if (msg.mtd != SIP_MT_NONE) {
                if (msg.mtd == SIP_MT_INVITE) {
                    call = list;
                    while (call != NULL) {
                        if (strncmp(call->id, msg.call_id, len) == 0)
                            break;
                        call = call->nxt;
                    }
                    if (call == NULL) {
                        LogPrintf(LV_DEBUG, "New call: %s", msg.call_id);
                        /* new invite -> new call */
                        call = xmalloc(sizeof(sip_call));
                        SipCallInit(call, pkt, flow_id, msg.call_id);
                        call->nxt = list;
                        if (list == NULL) {
                            FlowSetTimeOut(flow_id, SIP_PKT_TIMEOUT);
                        }
                        list = call;
                        /* search from a to sip address */
                        SipFromTo(call, pkt->data, pkt->len);
                        call->start_time_sec = pkt->cap_sec;
                    }
                    if (call->cmd_fp != NULL)
                        fwrite(pkt->data, 1, pkt->len, call->cmd_fp);
                    call->end_time_sec = pkt->cap_sec;
                }
                else {
                    /* other methods */
                    /* search call_id */
                    call = list;
                    while (call != NULL) {
                        if (strncmp(call->id, msg.call_id, len) == 0)
                            break;
                        call = call->nxt;
                    }
                    if (call != NULL) {
                        call->end_time_sec = pkt->cap_sec;
                        if (call->cmd_fp != NULL)
                            fwrite(pkt->data, 1, pkt->len, call->cmd_fp);
                        if (msg.mtd == SIP_MT_BYE || msg.mtd == SIP_MT_CANCEL) {
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
                }
            }
            else {
                /* SIP response */
                if (msg.status != SIP_ST_NONE)
                    LogPrintf(LV_DEBUG, "SIP response");
                /* search call_id */
                call = list;
                while (call != NULL) {
                    if (strncmp(call->id, msg.call_id, len) == 0)
                        break;
                    call = call->nxt;
                }
                if (call == NULL && msg.call_id[0] != '\0') {
                    LogPrintf(LV_DEBUG, "New call (rep): %s", msg.call_id);
                    /* new call id -> new call */
                    call = xmalloc(sizeof(sip_call));
                    SipCallInit(call, pkt, flow_id, msg.call_id);
                    call->nxt = list;
                    if (list == NULL) {
                        FlowSetTimeOut(flow_id, SIP_PKT_TIMEOUT);
                    }
                    list = call;
                    /* search from a to sip address */
                    SipFromTo(call, pkt->data, pkt->len);
                    call->start_time_sec = pkt->cap_sec;
                }
                if (call != NULL) {
                    call->end_time_sec = pkt->cap_sec;
                    if (call->cmd_fp != NULL)
                        fwrite(pkt->data, 1, pkt->len, call->cmd_fp);
                }
            }
            if (call != NULL) {
                /* sdp */
                sdp = strstr(pkt->data, "Content-Type: application/sdp");
                if (sdp == NULL) {
                    sdp = strstr(pkt->data, "Content-Type:application/sdp");
                    if (sdp == NULL) {
                        sdp = strstr(pkt->data, "Content-Type: application/SDP");
                        if (sdp == NULL) {
                            sdp = strstr(pkt->data, "Content-Type:application/SDP");
                            if (sdp == NULL) {
                                sdp = strstr(pkt->data, "\nc: application/SDP");
                                if (sdp == NULL) {
                                    sdp = strstr(pkt->data, "\nc: application/sdp");
                                }
                            }
                        }
                    }
                }
                if (sdp != NULL) {
                    if (strstr(pkt->data, "Content-Length") != NULL || strstr(pkt->data, "\nl:")) {
                        sdp = SipHeaderEnd(pkt->data, pkt->len) + 1;
                        /* pdu */
                        pkt->len = pkt->len - (sdp - pkt->data);
                        pkt->data = sdp;
                        if (sdp_id != -1) {
                            pkt = ProtDissecPkt(sdp_id, pkt);
                            if (pkt != NULL) {
                                call->sdp = TRUE;
                                sdpm = (sdp_msg *)pkt->data;
                                if (call->rule_cr_id == -1 && msg.mtd == SIP_MT_INVITE) { /* this is a big limitation */
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
                                        SipStorageInit(call, flow_id);
                                    }
                                }
                                else if (call->rule_cd_id == -1 && msg.mtd == SIP_MT_NONE) { /* this is a big limitation */
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
                                        SipStorageInit(call, flow_id);
                                    }
                                }
                                SdpMsgFree(sdpm);
                            }
                        }
                    }
                    else {
                        LogPrintf(LV_WARNING, "sdp without information!");
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
                call->sdp = TRUE;
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
                if (SipMediaFlow(call, media_id) == 0) {
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
                    SipPktStorageCr(call, pkt);
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
                    SipPktStorageCd(call, pkt);
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
                FlowSetTimeOut(flow_id, SIP_PKT_TIMEOUT);
            else
                FlowSetTimeOut(flow_id, 0);
        }
        
        /* check call status */
        ctmp = NULL;
        call = list;
        while (call != NULL) {
            cend = FALSE;
            if ((call->sdp == TRUE || (call->start_time_sec + SIP_SDP_TO) < cap_sec) && call->rule_cr_id == -1 && call->rule_cd_id == -1) {
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
                else {
                    list = call->nxt;
                }

                /* convert file and complete pei */
                SipCallPei(call);

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
    } while (list != NULL || FlowIsEmpty(flow_id) == FALSE);

    LogPrintf(LV_DEBUG, "SIP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool SipVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    char *data, *new;
    const char *eol, *lineend;
    unsigned long len;
    int cmp;
    sip_ver ver;
    bool ret, fr_data;
    ftval lost, ips, ip_s;
    bool ipv4, udp;
    short preaded, resp_only, resp_only_lim;

    ipv4 = FALSE;
    udp = FALSE;
    ret = FALSE;
    fr_data = FALSE;
    lost.uint8 = FALSE; /* by default -for udp- */

    if (FlowIsClose(flow_id) == FALSE) {
        resp_only_lim = FlowPktNum(flow_id);
    }
    else {
        resp_only_lim = SIP_PKT_RESP_ONLY;
    }
    
    pkt = FlowGetPktCp(flow_id);
    preaded = 1;
    resp_only = 0;
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
                if (lineend != data+len && (lineend - data) > 2 && (*eol == '\r' || *eol == '\n')) {
                    /* check if msg request */
                    ver = SipReqVersion(data, lineend-data);
                    if (ver != SIP_VER_NONE) {
                        resp_only = 0;
                        if (check == FALSE) {
                            ret = TRUE;
                            break;
                        }
                        else if (SipReqMethod(data, lineend-data) != SIP_MT_NONE) {
                            if (SipHeaderEnd(data, len) != NULL) {
                                ret = TRUE;
                                break;
                            }
                        }
                    }
                    else {
                        /* check if msg response */
                        ver = SipResVersion(data, lineend-data);
                        if (ver == SIP_VER_NONE)
                            break;
                        resp_only++;
                        if (resp_only == resp_only_lim) {
                            ret = TRUE;
                            break;
                        }
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
                    if (preaded != SIP_PKT_NULL_LIMIT) {
                        pkt = FlowGetPktCp(flow_id);
                        if (pkt != NULL) {
                            preaded++;
                            data = (char *)pkt->data;
                            len = pkt->len;
                        }
                    }
                }
            } while (pkt != NULL && len < 4096); /* 4k: max sip request length */

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


static bool SipVerify(int flow_id)
{
    return SipVerifyCheck(flow_id, FALSE);
}


static bool SipCheck(int flow_id)
{
    return SipVerifyCheck(flow_id, TRUE);
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
    ProtName("Session Initiation Protocol", "sip");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_SIP;
    dep.ProtCheck = SipVerify;
    dep.pktlim = SIP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = UDP_PORT_SIP;
    dep.ProtCheck = SipVerify;
    dep.pktlim = SIP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* dep: udp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TLS_PORT_SIP;
    dep.ProtCheck = SipVerify;
    dep.pktlim = SIP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = SipCheck;
    hdep.pktlim = SIP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = SipCheck;
    hdep.pktlim = SIP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "to";
    peic.desc = "SIP address";
    ProtPeiComponent(&peic);

    peic.abbrev = "from";
    peic.desc = "SIP address";
    ProtPeiComponent(&peic);

    peic.abbrev = "cmd";
    peic.desc = "SIP commands";
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
    ProtDissectors(NULL, SipDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char sip_dir[256];
    
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
    sip_id = ProtId("sip");

    /* pei id */
    pei_from_id = ProtPeiComptId(sip_id, "from");
    pei_to_id = ProtPeiComptId(sip_id, "to");
    pei_cmd_id = ProtPeiComptId(sip_id, "cmd");
    pei_audio_from_id = ProtPeiComptId(sip_id, "audio_from");
    pei_audio_to_id = ProtPeiComptId(sip_id, "audio_to");
    pei_audio_mix_id = ProtPeiComptId(sip_id, "audio_mix");
    pei_duration_id = ProtPeiComptId(sip_id, "duration");

    /* sip tmp directory */
    sprintf(sip_dir, "%s/%s", ProtTmpDir(), SIP_TMP_DIR);
    mkdir(sip_dir, 0x01FF);
    incr = 0;

    return 0;
}
