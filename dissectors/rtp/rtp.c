/* rtp.c
 * Dissector of RTP protocol
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
#include <stdlib.h>
#include <sys/wait.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "rtp.h"
#include "pei.h"
#include "pcap_gfile.h"
#include "grp_rule.h"
#include "grp_flows.h"
#include "stun.h"

#define DEBUG_RM         1  /* if 1 then all files are removed from tmp dir */
#define RTP_WAV          1  /* wav or mp3 */

#define RTP_TMP_DIR      "rtp"

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
static int udp_id;
static int uport_src_id;
static int uport_dst_id;
static int rtp_id;
static int ver_id;
static int pt_id;
static int seq_id;
static int ts_id;
static int sync_id;
static int rtcp_id;
static int rtcp_phone_id;

/* pei id */
static int pei_from;
static int pei_to;
static int pei_audio_from;
static int pei_audio_to;
static int pei_audio_mix;
static int pei_duration;

static volatile unsigned int incr;

static packet *RtpPktDissector(packet *pkt)
{
    return NULL;
}


static bool RtpClientPkt(rtp_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, uport_src_id, &port);
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


static bool RtcpClientPkt(rtp_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    const pstack_f *udp;

    ret = FALSE;
    udp = ProtStackSearchProt(pkt->stk, udp_id);
    if (priv->port_diff == TRUE) {
        ProtGetAttr(udp, uport_src_id, &port);
        if (port.uint16 == priv->port_s)
            ret = TRUE;
    }
    else {
        if (priv->ipv6 == TRUE) {
            ProtGetAttr(ProtGetNxtFrame(udp), ipv6_src_id, &ip);
            type = FT_IPv6;
        }
        else {
            ProtGetAttr(ProtGetNxtFrame(udp), ip_src_id, &ip);
            type = FT_IPv4;
        }
        if (FTCmp(&priv->ip_s, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }
    
    return ret;
}


static packet *RtpDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *udp, *ip;
    ftval port_src, port_dst, offset, phone;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    rtp_priv *priv;
    packet *pkt;
    int rid, ret, gid, rtcp_fid;
    cmp_val rip, rport;
    char tmp_file_1[256];
    char tmp_file_2[256];
    char media_file_1[256];
    char media_file_2[256];
    char media_conv[256];
    FILE *fp_pcap_1, *fp_pcap_2, *fp_pcap;
    struct pcap_file_header fh;
    struct pcappkt_hdr pckt_header;
    struct stat fsbuf;
    char cmd[1024];
    size_t nwrt, wcnt;
    time_t tstart, tend;
    pei *ppei, *ppein;
    pei_component *cmpn;
    bool aud1, aud2, good;
    unsigned short pkt_cnt;
    rtp_hdr *rtp;
    short cod_cng, i;
    unsigned char pt1, pt2;
    unsigned int ssrc1, ssrc2;
    
    LogPrintf(LV_DEBUG, "RTP id: %d", flow_id);
    
    ppein = ppei = NULL;
    cod_cng = 0;
    pt1 = pt2 = 0;
    ssrc1 = ssrc2 = 0;

    gid = FlowGrpId(flow_id);
    priv = DMemMalloc(sizeof(rtp_priv));
    memset(priv, 0, sizeof(rtp_priv));
    udp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(udp);
    ProtGetAttr(udp, uport_src_id, &port_src);
    ProtGetAttr(udp, uport_dst_id, &port_dst);
    priv->port_s = port_src.uint16;
    priv->port_d = port_dst.uint16;
    priv->stack = udp;
    if (priv->port_s != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    if (ProtFrameProtocol(ip) == ip_id)
        priv->ipv6 = FALSE;
    
    if (priv->ipv6 == FALSE) {
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
    
    /* RTCP flow search */
    rid = -1;
    rtcp_fid = -1;
    if (rtcp_id != -1) {
        rid = GrpRuleNew(flow_id);
        if (priv->ipv6 == TRUE) {
            rip.prot = ipv6_id;
            rip.att = ipv6_dst_id;
            FTCopy(&rip.val, &priv->ip_d, FT_IPv6);
        }
        else {
            rip.prot = ip_id;
            rip.att = ip_dst_id;
            rip.val.uint32 = priv->ip_d.uint32;
        }
        rport.prot = udp_id;
        rport.att = uport_dst_id;
        port_dst.uint16++;
        rport.val.int16 = port_dst.uint16;
        GrpRule(rid, 2, &rip, &rport);
        if (priv->ipv6 == TRUE) {
            rip.att = ipv6_src_id;
        }
        else {
            rip.att = ip_src_id;
        }
        rport.att = uport_src_id;
        GrpRule(rid, 2, &rip, &rport);
        GrpRuleCmplt(rid);
        LogPrintf(LV_DEBUG, "Rule rtcp %i, port:%i", rid, port_dst.uint16);
    }
    
    /* put packets in the pcap files */
    sprintf(tmp_file_1, "%s/%s/rtp_%d_1_%lld_%d.pcap", ProtTmpDir(), RTP_TMP_DIR, incr, (long long)time(NULL), port_src.uint16);
    sprintf(tmp_file_2, "%s/%s/rtp_%d_2_%lld_%d.pcap", ProtTmpDir(), RTP_TMP_DIR, incr, (long long)time(NULL), port_src.uint16);
    sprintf(media_conv, "%s/%s/rtp_%d_%lld_%d", ProtTmpDir(), RTP_TMP_DIR, incr, (long long)time(NULL), port_src.uint16);
    incr++;

    fp_pcap_1 = fopen(tmp_file_1, "wb");
    fp_pcap_2 = fopen(tmp_file_2, "wb");
    memset(&fh, 0, sizeof(struct pcap_file_header));
    fh.magic = 0xA1B2C3D4;
    fh.version_major = PCAP_VERSION_MAJOR;
    fh.version_minor = PCAP_VERSION_MINOR;
    fh.snaplen = 65535;
    fh.linktype = DLT_RAW;
    if (fp_pcap_1 != NULL) {
        fwrite((char *)&fh, 1, sizeof(struct pcap_file_header), fp_pcap_1);
    }
    if (fp_pcap_2 != NULL) {
        fwrite((char *)&fh, 1, sizeof(struct pcap_file_header), fp_pcap_2);
    }

    /* first packet */
    pkt_cnt = 0;
    pkt = FlowGetPkt(flow_id);
    /* start time */
    if (pkt != NULL) {
        /* pei definition */
        PeiNew(&ppei, rtp_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, udp);
        tstart = pkt->cap_sec;
    }
    while (pkt != NULL) {
        pkt_cnt++;
        /* check if exit rtcp "stream" */
        if (rid != -1) {
            rtcp_fid = GrpLink(gid);
            if (rtcp_fid != -1) {
                FlowSyncr(flow_id, FALSE);
                FlowSyncr(rtcp_fid, FALSE);
                PeiAddStkGrp(ppei, FlowStack(rtcp_fid));
                rid = -1;
            }
        }

        tend = pkt->cap_sec;
        if (priv->ipv6) {
            ip = ProtStackSearchProt(pkt->stk, ipv6_id);
            ProtGetAttr(ip, ipv6_offset_id, &offset);
            wcnt = offset.uint32;
        }
        else {
            ip = ProtStackSearchProt(pkt->stk, ip_id);
            ProtGetAttr(ip, ip_offset_id, &offset);
            wcnt = offset.uint32;
        }
        good = FALSE;
        /* check the RTP */
        if (pkt->len > sizeof(rtp_hdr)) {
            rtp = (rtp_hdr *)pkt->data;
            if (rtp->version == 2) {
                good = TRUE;
            }
        }
        if (good) {
            pckt_header.caplen = pkt->raw_len - wcnt;
            pckt_header.len = pkt->raw_len - wcnt;
            pckt_header.tv_sec = pkt->cap_sec;
            pckt_header.tv_usec = pkt->cap_usec;
            if (RtpClientPkt(priv, pkt)) {
                fp_pcap = fp_pcap_1;
                if (pt1 != rtp->pt) {
                    cod_cng++;
                    pt1 = rtp->pt;
                }
                else if (ssrc1 != rtp->ssrc) {
                    cod_cng++;
                    ssrc1= rtp->ssrc;
                }
            }
            else {
                fp_pcap = fp_pcap_2;
                if (pt2 != rtp->pt) {
                    cod_cng++;
                    pt2 = rtp->pt;
                }
                else if (ssrc2 != rtp->ssrc) {
                    cod_cng++;
                    ssrc2= rtp->ssrc;
                }
            }
            if (fp_pcap != NULL) {
                wcnt = 0;
                do {
                    nwrt = fwrite(((char *)&pckt_header)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, fp_pcap);
                    if (nwrt != -1)
                        wcnt += nwrt;
                    else
                        break;
                } while (wcnt != sizeof(struct pcappkt_hdr));
                
                wcnt = offset.uint32;
                do {
                    nwrt = fwrite(((char *)pkt->raw)+wcnt, 1, pkt->raw_len-wcnt, fp_pcap);
                    if (nwrt != -1)
                        wcnt += nwrt;
                    else
                        break;
                } while (wcnt != pkt->raw_len);
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    /* close file */
    if (fp_pcap_1 != NULL)
        fclose(fp_pcap_1);
    if (fp_pcap_1 != NULL)
        fclose(fp_pcap_2);
    /* remove rtcp rule */
    if (rid != -1) {
        rtcp_fid = GrpLink(gid);
        if (rtcp_fid != -1) {
            FlowSyncr(flow_id, FALSE);
            FlowSyncr(rtcp_fid, FALSE);
            PeiAddStkGrp(ppei, FlowStack(rtcp_fid));
            rid = -1;
        }
        else {
            GrpRuleRm(rid);
        }
    }
    
    /* decode rtcp packet */
    if (rtcp_fid != -1) {
        /* new priv data */
        priv->port_s++;
        priv->port_d++;
        pkt = FlowGetPkt(rtcp_fid);
        while (pkt != NULL) {
            pkt = ProtDissecPkt(rtcp_id, pkt);
            if (pkt != NULL) {
                ProtGetAttr(pkt->stk, rtcp_phone_id, &phone);
                if (RtcpClientPkt(priv, pkt)) {
                    strcpy(ipd_str, phone.str);
                }
                else {
                    strcpy(ips_str, phone.str);
                }
                PktFree(pkt);
            }
            pkt = FlowGetPkt(rtcp_fid); 
        }
    }

    /* audio decoding */
    sprintf(cmd, "videosnarf -i %s -o %s 2>/dev/null 1>/dev/null", tmp_file_1, tmp_file_1);
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
    sprintf(cmd, "videosnarf -i %s -o %s 2>/dev/null 1>/dev/null", tmp_file_2, tmp_file_2);
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
    /* delete temporary files */
#if DEBUG_RM
    remove(tmp_file_1);
    remove(tmp_file_2);
#endif

    good = TRUE;
    for (i=0; i!=cod_cng; i++) {
        if (ppei == NULL) {
            ppei = ppein;
            ppein = NULL;
        }
        /* pei definition */
        PeiNew(&ppein, rtp_id);
        PeiCapTime(ppein, tstart);
        PeiMarker(ppein, ppei->serial);
        PeiStackFlow(ppein, ppei->stack);

        /* media file check */
        sprintf(media_file_1, "%s-media-%i.wav", tmp_file_1, i+1);
        sprintf(media_file_2, "%s-media-%i.wav", tmp_file_2, i+1);
        
        /* complete pei */
        /*  from */
        PeiNewComponent(&cmpn, pei_from);
        PeiCompCapTime(cmpn, tstart);
        PeiCompAddStingBuff(cmpn, ipd_str);
        PeiAddComponent(ppei, cmpn);
        /*  to */
        PeiNewComponent(&cmpn, pei_to);
        PeiCompCapTime(cmpn, tstart);
        PeiCompAddStingBuff(cmpn, ips_str);
        PeiAddComponent(ppei, cmpn);
        /*  duration */
        sprintf(cmd, "%lld", (long long)tend-tstart);
        PeiNewComponent(&cmpn, pei_duration);
        PeiCompCapTime(cmpn, tstart);
        PeiCompAddStingBuff(cmpn, cmd);
        PeiAddComponent(ppei, cmpn);
        /*  audio from */
        aud2 = FALSE;
        if (stat(media_file_2, &fsbuf) == 0) {
#if RTP_WAV
            PeiNewComponent(&cmpn, pei_audio_from);
            PeiCompCapTime(cmpn, tstart);
            PeiCompCapEndTime(cmpn, tend);
            PeiCompAddFile(cmpn, "audio_caller.wav", media_file_2, fsbuf.st_size);
            PeiAddComponent(ppei, cmpn);
#endif
            aud2 = TRUE;
            /* convert to be used with lame */
            sprintf(tmp_file_2, "%s_2.wav", media_conv);
            sprintf(cmd, "sox %s -e signed-integer %s 2>/dev/null 1>/dev/null", media_file_2, tmp_file_2);
            ret = system(cmd);
#if RTP_WAV == 0
# if DEBUG_RM
            remove(media_file_2);
# endif
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
                    LogPrintf(LV_WARNING, "lame crash (%i): %s", WEXITSTATUS(ret), cmd);
                }
            }
            if (stat(media_file_2, &fsbuf) == 0) {
                PeiNewComponent(&cmpn, pei_audio_from);
                PeiCompCapTime(cmpn, tstart);
                PeiCompCapEndTime(cmpn, tend);
                PeiCompAddFile(cmpn, "audio_caller.mp3", media_file_2, fsbuf.st_size);
                PeiAddComponent(ppei, cmpn);
            }
            sprintf(media_file_2, "%s_stereo_2.wav", media_conv);
            sprintf(cmd, "sox %s -c 2 %s delay 0 remix 1v0 1 2>/dev/null 1>/dev/null", tmp_file_2, media_file_2);
            ret = system(cmd);
            
#if DEBUG_RM
            remove(tmp_file_2);
#endif
        }
        /*  audio to */
        aud1 = FALSE;
        if (stat(media_file_1, &fsbuf) == 0) {
#if RTP_WAV
            PeiNewComponent(&cmpn, pei_audio_to);
            PeiCompCapTime(cmpn, tstart);
            PeiCompCapEndTime(cmpn, tend);
            PeiCompAddFile(cmpn, "audio_called.wav", media_file_1, fsbuf.st_size);
            PeiAddComponent(ppei, cmpn);
#endif
            aud1 = TRUE;
            /* convert to be used with lame */
            sprintf(tmp_file_1, "%s_1.wav", media_conv);
            sprintf(cmd, "sox %s -e signed-integer %s 2>/dev/null 1>/dev/null", media_file_1, tmp_file_1);
            ret = system(cmd);
#if RTP_WAV == 0
# if DEBUG_RM
            remove(media_file_1);
# endif
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
                    LogPrintf(LV_WARNING, "lame crashed (%i): %s", WEXITSTATUS(ret), cmd);
                }
            }
            if (stat(media_file_1, &fsbuf) == 0) {
                PeiNewComponent(&cmpn, pei_audio_to);
                PeiCompCapTime(cmpn, tstart);
                PeiCompCapEndTime(cmpn, tend);
                PeiCompAddFile(cmpn, "audio_called.mp3", media_file_1, fsbuf.st_size);
                PeiAddComponent(ppei, cmpn);
            }
            sprintf(media_file_1, "%s_stereo_1.wav", media_conv);
            sprintf(cmd, "sox %s -c 2 %s delay 0 remix 1 1v0 2>/dev/null 1>/dev/null", tmp_file_1, media_file_1);
            ret = system(cmd);
#if DEBUG_RM
            remove(tmp_file_1);
#endif
        }
        /*  mix audio */
        if (aud2 || aud1) {
            good = TRUE;
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
#if DEBUG_RM
            remove(media_file_1);
            remove(media_file_2);
            remove(tmp_file_1);
#endif
            if (stat(tmp_file_2, &fsbuf) == 0) {
                PeiNewComponent(&cmpn, pei_audio_mix);
                PeiCompCapTime(cmpn, tstart);
                PeiCompCapEndTime(cmpn, tend);
                PeiCompAddFile(cmpn, "audio_mix.mp3", tmp_file_2, fsbuf.st_size);
                PeiAddComponent(ppei, cmpn);
            }
        }
        
        /* insert pei */
        if (good) {
            PeiIns(ppei);
        }
        else {
            PeiFree(ppei);
        }
        ppei = NULL;
        good = FALSE;
    }

    /* free */
    DMemFree(priv);
    
    LogPrintf(LV_DEBUG, "RTP... bye bye  fid:%d (pkt:%i)", flow_id, pkt_cnt);

    return NULL;
}


static bool RtpCheck(int flow_id)
{
    const pstack_f *ip;
    packet *pkt;
    bool ret;
    ftval ips, ipx, port;
    bool ipv4, cmp, pok;
    int pt_1, pt_2;
    unsigned int ssrc_1, ssrc_2;
    int cnt, ecnt;
    rtp_hdr *rtp;
    unsigned short min_size;
    stun_hdr *stun;

    if (FlowPktNum(flow_id) < RTP_PKT_LIMIT && FlowIsClose(flow_id) == FALSE) {
        return FALSE;
    }

    ipv4 = FALSE;
    ret = FALSE;
    cnt = ecnt = 0;

    pkt = FlowGetPktCp(flow_id);
    if (pkt != NULL) {
        /* check port */
        ProtGetAttr(pkt->stk, uport_dst_id, &port);
        if (port.uint16 < 1024) {
            PktFree(pkt);
            return FALSE;
        }
        ProtGetAttr(pkt->stk, uport_src_id, &port);
        if (port.uint16 < 1024) {
            PktFree(pkt);
            return FALSE;
        }
        /* check ip */
        ip = ProtGetNxtFrame(pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id)
            ipv4 = TRUE;
        if (ipv4 == TRUE)
            ProtGetAttr(ip, ip_src_id, &ips);
        else
            ProtGetAttr(ip, ipv6_src_id, &ips);
        while (pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
        }
    }
    if (pkt != NULL) {
        pt_1 = pt_2 = -1;
        do {
            if (pkt->len > sizeof(rtp_hdr)) {
                rtp = (rtp_hdr *)pkt->data;
                if (rtp->version != 2) {
                    if (pkt->len > sizeof(stun_hdr)) {
                        stun = (stun_hdr *)pkt->data;
                        if (ntohs(stun->len) + sizeof(stun_hdr) != pkt->len){
                            cnt = 0;
                            ecnt++;
                        }
                    }
                    else {
                        cnt = 0;
                        ecnt++;
                    }
                }
                else {
                    pok = TRUE;
                    ip = ProtGetNxtFrame(pkt->stk);
                    if (ipv4 == TRUE) {
                        ProtGetAttr(ip, ip_src_id, &ipx);
                        cmp = FTCmp(&ips, &ipx, FT_IPv4, FT_OP_EQ, NULL);
                        if (cmp) {
                            if (pt_1 == -1) {
                                pt_1 = rtp->pt;
                                ssrc_1 = rtp->ssrc;
                            }
                            else if (pt_1 != rtp->pt || ssrc_1 != rtp->ssrc) {
                                pok = FALSE;
                                pt_1 = rtp->pt;
                                ssrc_1 = rtp->ssrc;
                            }
                        }
                        else {
                            if (pt_2 == -1) {
                                pt_2 = rtp->pt;
                                ssrc_2 = rtp->ssrc;
                            }
                            else if (pt_2 != rtp->pt || ssrc_2 != rtp->ssrc) {
                                pok = FALSE;
                                pt_2 = rtp->pt;
                                ssrc_2 = rtp->ssrc;
                            }
                        }
                        /* check size */
                        if (rtp->cc != 0) {
                            min_size = rtp->cc * 4; /* every CSRC has 4 byte */
                            min_size += sizeof(rtp_hdr);
                            if (pkt->len < min_size)
                                pok = FALSE;
                        }
                    }
                    else {
                        ProtGetAttr(ip, ipv6_src_id, &ipx);
                        cmp = FTCmp(&ips, &ipx, FT_IPv6, FT_OP_EQ, NULL);
                        if (cmp) {
                            if (pt_1 == -1) {
                                pt_1 = rtp->pt;
                                ssrc_1 = rtp->ssrc;
                            }
                            else if (pt_1 != rtp->pt || ssrc_1 != rtp->ssrc) {
                                pok = FALSE;
                                pt_1 = rtp->pt;
                                ssrc_1 = rtp->ssrc;
                            }
                        }
                        else {
                            if (pt_2 == -1) {
                                pt_2 = rtp->pt;
                                ssrc_2 = rtp->ssrc;
                            }
                            else if (pt_2 != rtp->pt || ssrc_2 != rtp->ssrc) {
                                pok = FALSE;
                                pt_2 = rtp->pt;
                                ssrc_2 = rtp->ssrc;
                            }
                        }
                        /* check size */
                        if (rtp->cc != 0) {
                            min_size = rtp->cc * 4; /* every CSRC has 4 byte */
                            min_size += sizeof(rtp_hdr);
                            if (pkt->len < min_size)
                                pok = FALSE;
                        }
                    }
                    if (pok == TRUE)
                        cnt++;
                }
            }
            else {
                if (pkt->len > sizeof(stun_hdr)) {
                    stun = (stun_hdr *)pkt->data;
                    if (ntohs(stun->len) + sizeof(stun_hdr) != pkt->len){
                        cnt = 0;
                        ecnt++;
                    }
                }
                else {
                    cnt = 0;
                    ecnt++;
                }
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
        } while (ecnt != RTP_PKT_ERR_CHECK && cnt != RTP_PKT_CHECK && pkt != NULL);
    }
    
    if (pkt != NULL) {
        PktFree(pkt);
        pkt = NULL;
    }
    
    if (cnt == RTP_PKT_CHECK) {
        ret = TRUE;
    }

    return ret;
}


int DissecRegist(const char *file_cfg)
{
    proto_heury_dep hdep;
    pei_cmpt peic;
    proto_info info;

    memset(&info, 0, sizeof(proto_info));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Real time Transport Protocol", "rtp");

    /* info: version */
    info.name = "Version";
    info.abbrev = "rtp.ver";
    info.type = FT_UINT8;
    ver_id = ProtInfo(&info);

    /* info: payload type */
    info.name = "Payload type";
    info.abbrev = "rtp.pt";
    info.type = FT_UINT8;
    pt_id = ProtInfo(&info);

    /* info: sequence number */
    info.name = "Sequence number";
    info.abbrev = "rtp.seq";
    info.type = FT_UINT16;
    seq_id = ProtInfo(&info);

    /* info: timestamp */
    info.name = "Timestamp";
    info.abbrev = "rtp.ts";
    info.type = FT_UINT32;
    ts_id = ProtInfo(&info);

    /* info: synchronization source */
    info.name = "Synchronization source";
    info.abbrev = "rtp.sync";
    info.type = FT_UINT32;
    sync_id = ProtInfo(&info);

    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = RtpCheck;
    hdep.pktlim = RTP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);
    
    /* PEI components */
    peic.abbrev = "from";
    peic.desc = "Caller";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "to";
    peic.desc = "Called";
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
    ProtDissectors(RtpPktDissector, RtpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char rtp_dir[256];
    
    /* part of file name */
    incr = 0;

    /* info id */
    ppp_id = ProtId("ppp");
    eth_id = ProtId("eth");
    ip_id = ProtId("ip");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
        ip_offset_id = ProtAttrId(ip_id, "ip.offset");
    }
    ipv6_id = ProtId("ipv6");
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
        ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    }
    udp_id = ProtId("udp");
    if (uport_dst_id != -1) {
        uport_dst_id = ProtAttrId(udp_id, "udp.dstport");
        uport_src_id = ProtAttrId(udp_id, "udp.srcport");
    }
    rtp_id = ProtId("rtp");
    rtcp_id = ProtId("rtcp");
    if (rtcp_id != -1)
        rtcp_phone_id = ProtAttrId(rtcp_id, "rtcp.phone");
 
    /* pei id */
    pei_from = ProtPeiComptId(rtp_id, "from");
    pei_to = ProtPeiComptId(rtp_id, "to");
    pei_audio_from = ProtPeiComptId(rtp_id, "audio_from");
    pei_audio_to = ProtPeiComptId(rtp_id, "audio_to");
    pei_audio_mix = ProtPeiComptId(rtp_id, "audio_mix");
    pei_duration = ProtPeiComptId(rtp_id, "duration");

    /* rtp tmp directory */
    sprintf(rtp_dir, "%s/%s", ProtTmpDir(), RTP_TMP_DIR);
    mkdir(rtp_dir, 0x01FF);

    return 0;
}
