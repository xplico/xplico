/* sdp.c
 * Dissector of SDP (RFC 2327)
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * Gianluca Costa
 * Liberally copied from packet-sdp.c, by Jason Lango <jal@netapp.com>
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
#include "strutil.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "sdp.h"
#include "sdp_com.h"
#include "strutil.h"


static int sdp_id;


static void SdpMsgInit(sdp_msg *msg)
{
    memset(msg, 0, sizeof(sdp_msg));
}


static int SdpProtocolVersion(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpOwner(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpSessionName(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpMediaTitle(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpSessionInfo(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpUri(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpEmail(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpPhone(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpConnectionInfo(const char *data, int len, sdp_msg *msg)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;

    lineend = data + len;

    /* The first token is connection type */
    tokenlen = get_token_len(data, lineend, &next_token);
    if (tokenlen == 0 || data[tokenlen] != ' ') {
        return -1;
    }
    if (strncmp(data, "IN", tokenlen) == 0) {
        msg->cntn_info.nettype = SDP_NETTP_IN;
    }
    else {
        return -1;
    }
    data = next_token;
    
    /* next token is address type */
    tokenlen = get_token_len(data, lineend, &next_token);
    if (tokenlen == 0 || data[tokenlen] != ' ') {
        msg->cntn_info.nettype = SDP_NETTP_NONE;
        return -1;
    }
    if (strncmp(data, "IP4", tokenlen) == 0) {
        msg->cntn_info.nettype = SDP_ADDRTP_IP4;
    }
    else if (strncmp(data, "IP6", tokenlen) == 0) {
        msg->cntn_info.nettype = SDP_ADDRTP_IP6;
    }
    else {
        msg->cntn_info.nettype = SDP_NETTP_NONE;
        return -1;
    }
    data = next_token;
    /* next token is address */
    tokenlen = get_token_len(data, lineend, &next_token);
    if (tokenlen == 0 || (data[tokenlen] != '\r' && data[tokenlen] != '\n')) {
        msg->cntn_info.nettype = SDP_NETTP_NONE;
        msg->cntn_info.nettype = SDP_ADDRTP_NONE;
        return -1;
    }
    msg->cntn_info.address = DMemMalloc(tokenlen + 1);
    memcpy(msg->cntn_info.address, data, tokenlen);
    msg->cntn_info.address[tokenlen] = '\0';

    return 0;
}


static int SdpBandwidth(const char *data, int len, sdp_msg *msg)
{
    msg->version = atoi(data);

    return 0;
}


static int SdpTime(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpRepeatTime(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpMedia(const char *data, int len, sdp_msg *msg)
{
    const char *next_token;
    const char *lineend;
    char number[256];
    int tokenlen, token;
    short mcnt;

    mcnt = msg->transp.count;
    if (mcnt == SDP_MAX_RTP_CHANNELS)
        return -1;

    lineend = data + len;
    
    /* The first token media type */
    tokenlen = get_token_len(data, lineend, &next_token);
    if (tokenlen == 0 || data[tokenlen] != ' ') {
        return -1;
    }
    msg->transp.type[mcnt] = SDP_MEDIA_UNKNOW;
    if (strncmp(data, "audio", tokenlen) == 0) {
        msg->transp.type[mcnt] = SDP_MEDIA_AUDIO;
    }
    else if (strncmp(data, "video", tokenlen) == 0) {
        msg->transp.type[mcnt] = SDP_MEDIA_VIDEO;
    }
    else {
        LogPrintf(LV_WARNING, "New media type");
    }
    data = next_token;
    
    /* port */
    tokenlen = get_token_len(data, lineend, &next_token);
    if (tokenlen == 0 || data[tokenlen] != ' ') {
        return -1;
    }
    token = find_chr(data, tokenlen, '/');

    if (token != -1) {
        memcpy(number, data, token);
        number[token] = '\0';
        msg->transp.port[mcnt] = atoi(number);
        LogPrintf(LV_WARNING, "Port count to be complete");
    }
    else {
        msg->transp.port[mcnt] = atoi(data);
    }
    data = next_token;

    /* media protocol */
    tokenlen = get_token_len(data, lineend, &next_token);
    if (tokenlen == 0 || data[tokenlen] != ' ') {
        return -1;
    }
    msg->transp.proto[mcnt] = DMemMalloc(tokenlen+1);
    memcpy(msg->transp.proto[mcnt], data, tokenlen);
    msg->transp.proto[mcnt][tokenlen] = '\0';
    data = next_token;

    /* pt */
    tokenlen = get_token_len(data, lineend, &next_token);
    
    if (strcmp(msg->transp.proto[mcnt], "RTP/AVP") == 0) {
        while (tokenlen != 0) {
#if 0
            memcpy(number, data, tokenlen);
            number[tokenlen] = '\0';
            msg->transp.media[mcnt].pt[msg->transp.media[mcnt].pt_count] = atoi(number);
#else
            msg->transp.media[mcnt].pt[msg->transp.media[mcnt].pt_count] = atoi(data);
#endif
            msg->transp.media[mcnt].pt_count++;
            data = next_token;
            tokenlen = get_token_len(data, lineend, &next_token);
        }
    }

    msg->transp.count++;

    return 0;
}


static int SdpEncryptionKey(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpMediaAttribute(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpSessionAttribute(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpTimezone(const char *data, int len, sdp_msg *msg)
{
    return 0;
}


static int SdpParse(packet *pkt, int len, sdp_msg *msg)
{
    bool in_media;
    int offset;
    int linelen;
    int next_offset;
    unsigned char type;
    unsigned char delim;
    char *tmp;
    int (*SdpAttr)(const char *, int, sdp_msg *);
    char *data;

    data = pkt->data;
    in_media = FALSE;
    offset = 0;
    while (offset < len) {
        /*
         * Find the end of the line.
         */
        linelen = find_line_end_unquoted(data+offset, len - offset, &next_offset);

        /*
         * Line must contain at least e.g. "v=".
         */
        if (linelen < 2)
            break;
        
        type = data[offset];
        delim = data[offset + 1];
        if (delim != '=') {
            LogPrintf(LV_WARNING, "Invalid SDP line (no '=' delimiter)");
            LogPrintf(LV_DEBUG, "Type %c, %i, %s", type, offset, data+offset);
            offset += next_offset;
            continue;
        }

        /*
         * Attributes.
         */
        SdpAttr = NULL;
        switch (type) {
        case 'v':
            SdpAttr = SdpProtocolVersion;
            break;

        case 'o':
            SdpAttr = SdpOwner;
            break;

        case 's':
            SdpAttr = SdpSessionName;
            break;

        case 'i':
            if (in_media) {
                SdpAttr = SdpMediaTitle;
            }
            else{
                SdpAttr = SdpSessionInfo;
            }
            break;

        case 'u':
            SdpAttr = SdpUri;
            break;

        case 'e':
            SdpAttr = SdpEmail;
            break;

        case 'p':
            SdpAttr = SdpPhone;
            break;

        case 'c':
            SdpAttr = SdpConnectionInfo;
            break;

        case 'b':
            SdpAttr = SdpBandwidth;
            break;

        case 't':
            SdpAttr = SdpTime;
            break;

        case 'r':
            SdpAttr = SdpRepeatTime;
            break;

        case 'm':
            SdpAttr = SdpMedia;
            in_media = TRUE;
            break;

        case 'k':
            SdpAttr = SdpEncryptionKey;
            break;

        case 'a':
            if (in_media) {
                SdpAttr = SdpMediaAttribute;
            }
            else{
                SdpAttr = SdpSessionAttribute;
            }
            break;

        case 'z':
            SdpAttr = SdpTimezone;
            break;

        default:
            break;
        }
        if (SdpAttr) {
            SdpAttr(data+offset + 2, linelen - 2, msg);
        }
        else {
            tmp = DMemMalloc(linelen + 1);
            memcpy(tmp, data + offset, linelen);
            tmp[linelen] = '\0';
            LogPrintf(LV_WARNING, "Invalid SDP Attribute: %s", tmp);
            DMemFree(tmp);
        }

        offset += next_offset;
    }
    
    return 0;
}


static packet* SdpDissector(packet *pkt)
{
    packet *sdp_pkt;
    sdp_msg *msg;
    pstack_f *frame;

    sdp_pkt = NULL;

    /* create new SDP message */
    msg = DMemMalloc(sizeof(sdp_msg));
    SdpMsgInit(msg);
    if (SdpParse(pkt, pkt->len, msg) == 0) {
        /* new sdp packet */
        sdp_pkt = PktNew();
        sdp_pkt->stk = ProtCopyFrame(pkt->stk, TRUE);

        /* new frame */
        frame = ProtCreateFrame(sdp_id);
        ProtSetNxtFrame(frame, sdp_pkt->stk);
        sdp_pkt->stk = frame;

        /* set frame attribute */
        sdp_pkt->cap_sec = pkt->cap_sec;
        sdp_pkt->cap_usec = pkt->cap_usec;
        sdp_pkt->serial = pkt->serial;
        
        sdp_pkt->data = (char *)msg;
    }
    PktFree(pkt);

    return sdp_pkt;
}


int DissecRegist(const char *file_cfg)
{
    /* protocol name */
    ProtName("Session Description Protocol", "sdp");

    /* dissectors registration */
    ProtDissectors(SdpDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    sdp_id = ProtId("sdp");

    return 0;
}
