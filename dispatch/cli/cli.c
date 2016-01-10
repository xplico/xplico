/* cli.c
 * Xplico System dispatcher for cli usage
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2014 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>

#include "proto.h"
#include "log.h"
#include "pei.h"
#include "dmemory.h"
#include "cli.h"
#include "dnsdb.h"
#include "gearth.h"
#include "fileformat.h"
#include "config_param.h"

#ifndef DISP_CLI_FILE_LIST
#  define DISP_CLI_FILE_LIST    0
#  define DispFilePaths(x)      
#endif

#define HTTP_REVERSE_ENG        0   /* log http pei and don't remove header files from tmp */
#define HTTP_ALL_DATA           0   /* save all data (header,body) of any http message */

/* ip v4 id */
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
/* ip v6 id */
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;
/* pop id */
static int pop_id;
static int pei_pop_user_id;
static int pei_pop_pswd_id;
static int pei_pop_eml_id;
/* smtp id */
static int smtp_id;
static int pei_smtp_to_id;
static int pei_smtp_from_id;
static int pei_smtp_eml_id;
/* imap id */
static int imap_id;
static int pei_imap_user_id;
static int pei_imap_pswd_id;
static int pei_imap_params_id;
static int pei_imap_eml_id;
/* http id */
static int http_id;
static int http_encoding_id;
static int pei_http_url_id;
static int pei_http_client_id;
static int pei_http_host_id;
static int pei_http_content_type_id;
static int pei_http_method_id;
static int pei_http_status_id;
static int pei_http_req_header_id;
static int pei_http_req_body_id;
static int pei_http_res_header_id;
static int pei_http_res_body_id;
static int pei_http_file_id;
/* ftp */
static int ftp_id;
static int pei_ftp_url_id;
static int pei_ftp_user_id;
static int pei_ftp_pswd_id;
static int pei_ftp_cmd_id;
static int pei_ftp_file_in_id;
static int pei_ftp_file_out_id;
static int pei_ftp_file_offset_id;
static int pei_ftp_down_n_id;
static int pei_ftp_up_n_id;
/* ipp */
static int ipp_id;
static int pei_ipp_url_id;
static int pei_ipp_pdf_id;
static int pei_ipp_pcl_id;
/* pjl */
static int pjl_id;
static int pei_pjl_url_id;
static int pei_pjl_pdf_id;
static int pei_pjl_pcl_id;
/* mms */
static int mms_id;
static int pei_mms_url_id;
static int pei_mms_from_id;
static int pei_mms_to_id;
static int pei_mms_cc_id;
static int pei_mms_bcc_id;
static int pei_mms_part_id;
static int pei_mms_raw_id;
/* tftp */
static int tftp_id;
static int pei_tftp_url_id;
static int pei_tftp_cmd_id;
static int pei_tftp_file_in_id;
static int pei_tftp_file_out_id;
static int pei_tftp_down_n_id;
static int pei_tftp_up_n_id;
/* dns */
static int dns_id;
static int pei_dns_host_id;
static int pei_dns_ip_id;
static int pei_dns_cname_id;
static int pei_dns_pkt_id;
/* nntp */
static int nntp_id;
static int pei_nntp_url_id;
static int pei_nntp_grp_id;
static int pei_nntp_article_id;
static int pei_nntp_header_id;
static int pei_nntp_body_id;
static int pei_nntp_post_id;
/* facebook web chat */
static int fbwc_id;
static int pei_fbwc_user_id;
static int pei_fbwc_friend_id;
static int pei_fbwc_chat_id;
static int pei_fbwc_duration_id;
/* telnet */
static int telnet_id;
static int pei_telnet_host_id;
static int pei_telnet_user_id;
static int pei_telnet_password_id;
static int pei_telnet_cmd_id;
/* webmail */
static int webmail_id;
static int pei_webmail_serv_id;
static int pei_webmail_dir_id;
static int pei_webmail_to_id;
static int pei_webmail_from_id;
static int pei_webmail_cc_id;
static int pei_webmail_sent_id;
static int pei_webmail_rec_id;
static int pei_webmail_messageid_id;
static int pei_webmail_subj_id;
static int pei_webmail_eml_id;
static int pei_webmail_html_id;
static int pei_webmail_txt_id;
/* http file */
static int httpfile_id;
static int pei_httpfile_url_id;
static int pei_httpfile_file_id;
static int pei_httpfile_content_type;
static int pei_httpfile_parts_id;
static int pei_httpfile_complete_id;
/* garbage tcp */
static int grb_tcp_id;
static int pei_grb_tcp_l7prot_id;
static int pei_grb_tcp_txt_id;
static int pei_grb_tcp_size_id;
static int pei_grb_tcp_file_id;
static int pei_grb_tcp_file_type_id;
/* garbage udp */
static int grb_udp_id;
static int pei_grb_udp_connect_id;
static int pei_grb_udp_txt_id;
/* rtp voip */
static int rtp_id;
static int pei_rtp_from;
static int pei_rtp_to;
static int pei_rtp_audio_from;
static int pei_rtp_audio_to;
static int pei_rtp_audio_mix;
static int pei_rtp_duration;
/* sip voip */
static int sip_id;
static int pei_sip_from;
static int pei_sip_to;
static int pei_sip_cmd;
static int pei_sip_audio_from;
static int pei_sip_audio_to;
static int pei_sip_audio_mix;
static int pei_sip_duration;
/* arp/rarp */
static int arp_id;
static int pei_arp_mac_id;
static int pei_arp_ip_id;
/* irc */
static int irc_id;
static int pei_irc_server_id;
static int pei_irc_channel_id;
static int pei_irc_channel_users_id;
static int pei_irc_channel_nick_id;
/* paltalk express */
static int paltalk_exp_id;
static int pei_pltk_e_user_id;
static int pei_pltk_e_chat_id;
static int pei_pltk_e_duration_id;
/* paltalk */
static int paltalk_id;
static int pei_pltk_room_id;
static int pei_pltk_room_duration_id;
static int pei_pltk_room_users_id;
static int pei_pltk_room_nick_id;
/* msn */
static int msn_id;
static int pei_msn_from_id;
static int pei_msn_to_id;
static int pei_msn_chat_id;
static int pei_msn_duration_id;
/* mgcp voip */
static int mgcp_id;
static int pei_mgcp_from;
static int pei_mgcp_to;;
static int pei_mgcp_cmd;
static int pei_mgcp_audio_from;
static int pei_mgcp_audio_to;
static int pei_mgcp_audio_mix;
static int pei_mgcp_duration;
/* yahoo web chat */
static int webymsg_id;
static int pei_webymsg_user_id;
static int pei_webymsg_friend_id;
static int pei_webymsg_chat_id;
static int pei_webymsg_duration_id;
/* syslog */
static int syslog_id;
static int pei_syslog_host_id;
static int pei_syslog_log_id;
/* yahoo web chat */
static int yahoo_id;
static int pei_yahoo_user_id;
static int pei_yahoo_friend_id;
static int pei_yahoo_chat_id;
static int pei_yahoo_duration_id;
/* ymsg */
static int ymsg_id;
static int pei_ymsg_session_id;
static int pei_ymsg_sender_id;
static int pei_ymsg_receiver_id;
static int pei_ymsg_msg_id;
/* whatsapp */
static int wa_id;
static int pei_wa_device_id;
static int pei_wa_phone_id;

/* geomap */
static volatile unsigned long geo_id; /* geo session number, in this case we have only one session */
static time_t tstart;
static unsigned long npop, nsmtp, nimap, nhttp, nftp, nipp,
    npjl, nmms, ntftp, ndns, nnntp, nfbwc, ntelnet, nwebmail,
    nhttpfile, ngrptcp, ngrpudp, nrtp, nsip, narp, nirc, npltk_exp,
    npltk, msn, nbo, mgcp, webymsg, syslog, ymsg, nyahoo, nwa;

/* decode dir */
char xdecode[CFG_LINE_MAX_SIZE];

/* lock to access of file */
#if DISP_CLI_FILE_LIST
static pthread_mutex_t file_mux;  /* mutex to access the file */
#endif
#if HTTP_ALL_DATA
static pthread_mutex_t http_data_mux;  /* mutex to access the file */
#endif

#if DISP_CLI_FILE_LIST
static inline void DispFilePaths(char *path)
{
    FILE *fp;
    
    pthread_mutex_lock(&file_mux);

    fp = fopen(XCLI_FILE_PATHS, "a");
    if (fp != NULL) {
        fwrite(path, 1, strlen(path), fp);
        fwrite("\n", 1, 1, fp);
        fclose(fp);
    }

    pthread_mutex_unlock(&file_mux);
}
#endif


inline static int DispUncompress(const char *encoding, const char *file_in,  const char *file_out)
{
    return FFormatUncompress(encoding, file_in, file_out);
}


static inline int DispDirMail(char *name)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/email", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/email/in", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/email/out", xdecode, name);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirHttp(char *src, char *dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/http/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/http/%s", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/http/%s/post", xdecode, src, dest);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirFtp(char *src, char *dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/ftp/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/ftp/%s", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/ftp/%s/upload", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/ftp/%s/download", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirIrc(char *src, char *channel)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/irc/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/irc/%s", xdecode, src, channel);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirPaltalkExp(char *src, char *nick)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/paltalk_exp/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/paltalk_exp/%s", xdecode, src, nick);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirPaltalk(char *src, char *channel)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/paltalk/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/paltalk/%s", xdecode, src, channel);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirMsn(char *src, char *channel)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/msn/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/msn/%s", xdecode, src, channel);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirWebYmsg(char *src, char *channel)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/webymsg/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/webymsg/%s", xdecode, src, channel);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirWhatsApp(char *src, char *phone)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/whatsapp/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/whatsapp/%s", xdecode, src, phone);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirSyslog(char *src)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/syslog", xdecode, src);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirPrinter(char *name)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/printer", xdecode, name);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirMms(char *name)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/mms", xdecode, name);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirTftp(char *src, char *dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/tftp/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/tftp/%s", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/tftp/%s/upload", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/tftp/%s/download", xdecode, src, dest);
    mkdir(dir, 0x01FF);
    
    return 0;
}


static inline int DispDirDns(char *name)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/dns", xdecode, name);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirArp(void)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/arp", xdecode);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirNntp(char *name)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/nntp", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/nntp/in", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/nntp/out", xdecode, name);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirFbwc(char *ip, char *user)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, ip);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/facebook_chat", xdecode, ip);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/facebook_chat/%s", xdecode, ip, user);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirTelnet(char *name, char *dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/telnet", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/telnet/%s", xdecode, name, dest);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirWebmail(char *name, const char *service)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/webmail", xdecode, name);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/webmail/%s", xdecode, name, service);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/webmail/%s/out", xdecode, name, service);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/webmail/%s/in", xdecode, name, service);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirHttpFile(char *ip_str, char *ip_dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, ip_str);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/httpfile", xdecode, ip_str);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/httpfile/%s", xdecode, ip_str, ip_dest);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirGrbTcp(char *ip_str, char *ip_dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, ip_str);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/grbtcp", xdecode, ip_str);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/grbtcp/%s", xdecode, ip_str, ip_dest);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirGrbTcpDig(char *ip_str, char *ip_dest, bool full)
{
    char dir[XCLI_STR_DIM];

    if (full) {
        sprintf(dir, "%s/%s", xdecode, ip_str);
        mkdir(dir, 0x01FF);
        sprintf(dir, "%s/%s/dig", xdecode, ip_str);
        mkdir(dir, 0x01FF);
        sprintf(dir, "%s/%s/dig/%s", xdecode, ip_str, ip_dest);
        mkdir(dir, 0x01FF);
    }
    else {
        sprintf(dir, "%s/dig", xdecode);
        mkdir(dir, 0x01FF);
    }

    return 0;
}


static inline int DispDirGrbUdp(char *ip_str, char *ip_dest)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, ip_str);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/grbudp", xdecode, ip_str);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/grbudp/%s", xdecode, ip_str, ip_dest);
    mkdir(dir, 0x01FF);

    return 0;
}


static inline int DispDirVoip(char *ips, char *from, char *to)
{
    char dir[XCLI_STR_DIM];

    sprintf(dir, "%s/%s", xdecode, ips);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/voip", xdecode, ips);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/voip/%s", xdecode, ips, from);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/voip/%s/%s", xdecode, ips, from, to);
    mkdir(dir, 0x01FF);

    return 0;
}


/*static inline int DispDirYmsg(char *src, char *msg)*/
static inline int DispDirYmsg(char *src, char *dir_name)
{
    char dir[XCLI_STR_DIM];
        //printf("helloworld - cli.c - DispDirHelloworld\n");
    LogPrintf(LV_DEBUG, "Ymsg - cli.c - dir_name:%s - DispDirYmsg", dir_name);

    sprintf(dir, "%s/%s", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/ymsg/", xdecode, src);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/ymsg/%s", xdecode, src, dir_name); /*msg);*/
    mkdir(dir, 0x01FF);

    return 0;
}

static inline int DispDirYahoo(char *ip, char *user)
{
    char dir[XCLI_STR_DIM];

	LogPrintf(LV_DEBUG, "Yahoo! - cli.c - user:%s - DispDirYahoo", user);

    sprintf(dir, "%s/%s", xdecode, ip);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/yahoo_chat", xdecode, ip);
    mkdir(dir, 0x01FF);
    sprintf(dir, "%s/%s/yahoo_chat/%s", xdecode, ip, user);
    mkdir(dir, 0x01FF);

    return 0;
}


static char* DispIp(const pstack_f *stack, char *buff)
{
    const pstack_f* frame;
    ftval val;
    char *ret;

    ret = buff;

    /* ipv4 */
    frame = ProtStackSearchProt(stack, ip_id);
    if (frame == NULL) {
        /* ipv6 */
        frame = ProtStackSearchProt(stack, ipv6_id);
        if (frame != NULL) {
            ProtGetAttr(frame, ipv6_src_id, &val);
            ret = FTString(&val, FT_IPv6, buff);
        }
        else {
            memcpy(buff, "ip_none", 8);
        }
    }
    else {
        ProtGetAttr(frame, ip_src_id, &val);
        ret = FTString(&val, FT_IPv4, buff);
    }
    
    return ret;
}


static char* DispDestHost(const pstack_f *stack, char *buff, int len)
{
    const pstack_f* frame;
    ftval val;
    char *ret;

    ret = buff;

    /* ipv4 */
    frame = ProtStackSearchProt(stack, ip_id);
    if (frame == NULL) {
        /* ipv6 */
        frame = ProtStackSearchProt(stack, ipv6_id);
        if (frame != NULL) {
            ProtGetAttr(frame, ipv6_dst_id, &val);
            if (DnsDbSearch(&val, FT_IPv6, buff, len) == -1)
                ret = FTString(&val, FT_IPv6, buff);
        }
        else {
            memcpy(buff, "ip_none", 8);
        }
    }
    else {
        ProtGetAttr(frame, ip_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv4, buff, len) == -1)
            ret = FTString(&val, FT_IPv4, buff);
    }
    
    return ret;
}


static int DispPop(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *path, *name;
    char ip_str[XCLI_STR_DIM];

    cmpn = ppei->components;
    while (cmpn != NULL) {
        path = NULL;
        if (cmpn->eid == pei_pop_eml_id) {
            path = cmpn->file_path;
        }

        /* move file */
        if (path) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_str) == NULL)
                return -1;
            DispDirMail(ip_str);
            
            /* new path */
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, "%s/%s/email/in/%s", xdecode, ip_str, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
        cmpn = cmpn->next;
    }

    return 0;
}


static int DispSmtp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *path, *name;
    char ip_str[XCLI_STR_DIM];

    path = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_smtp_eml_id) {
            path = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }

    /* move file */
    if (path) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirMail(ip_str);

        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(new_path, "%s/%s/email/out/%s", xdecode, ip_str, name);
        rename(path, new_path);
        DispFilePaths(new_path);
    }

    return 0;
}


static int DispImap(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *path, *name, *fetch;
    char ip_str[XCLI_STR_DIM];

    path = fetch = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_imap_eml_id) {
            path = cmpn->file_path;
        }
        else if (cmpn->eid == pei_imap_params_id) {
            fetch = cmpn->strbuf;
        }
        cmpn = cmpn->next;

        /* move file */
        if (path) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_str) == NULL)
                return -1;
            DispDirMail(ip_str);
    
            /* new path */
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, "%s/%s/email/in/%s", xdecode, ip_str, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
    }
    return 0;
}


static int DispHttp(pei *ppei)
{
    static unsigned long cnt_fl = 0;
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];
    const pstack_f *frame;
    ftval val;
    char *name;
    char *cont_type;
    char *path_rq_h, *path_rq_b, *path_rs_h, *path_rs_b;
    char *path_file, *file_name;
    bool create = TRUE;
#if HTTP_ALL_DATA
    static unsigned long mcont = 0;
#endif

    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }

    file_name = path_file = path_rq_h = path_rq_b = path_rs_h = path_rs_b = NULL; 
    cont_type = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_http_content_type_id) {
            cont_type = cmpn->strbuf;
        }
        if (cmpn->eid == pei_http_req_header_id) {
            path_rq_h = cmpn->file_path;
        }
        if (cmpn->eid == pei_http_req_body_id) {
            path_rq_b = cmpn->file_path;
        }
        if (cmpn->eid == pei_http_res_header_id) {
            path_rs_h = cmpn->file_path;
        }
        if (cmpn->eid == pei_http_res_body_id) {
            path_rs_b = cmpn->file_path;
        }
        if (cmpn->eid == pei_http_file_id) {
            path_file = cmpn->file_path;
            file_name = cmpn->name;
        }
        
        cmpn = cmpn->next;
    }

    /* compose httpfile query and insert record */
    if (path_file != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_src) == NULL)
            return -1;
        if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
            return -1;
        DispDirHttpFile(ip_src, ip_dest);

        /* new path */
        if (file_name == NULL) {
            name = strrchr(path_file, '/');
            name++;
            sprintf(new_path, "%s/%s/httpfile/%s/%s", xdecode, ip_src, ip_dest, file_name);
        }
        else {
            sprintf(new_path, "%s/%s/httpfile/%s/%lld_%lu_%s", xdecode, ip_src, ip_dest, (long long)time(NULL), cnt_fl, file_name);
            cnt_fl++;
        }
        rename(path_file, new_path);
        DispFilePaths(new_path);
    }
    else {
        /* compose http query and insert record */
#if HTTP_REVERSE_ENG
        PeiPrint(ppei);
#endif

#if HTTP_ALL_DATA
        pthread_mutex_lock(&http_data_mux);
        mcont++;
#endif
        if (path_rq_h != NULL) {
#if HTTP_ALL_DATA
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL) {
                pthread_mutex_unlock(&http_data_mux);
                return -1;
            }
            if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL) {
                pthread_mutex_unlock(&http_data_mux);
                return -1;
            }
            DispDirHttp(ip_src, ip_dest);
            create = FALSE;
            
            /* post */
            name = strrchr(path_rq_h, '/');
            name++;
            sprintf(new_path, "%s/%s/http/%s/%lu_%s", xdecode, ip_src, ip_dest, mcont, name);
            rename(path_rq_h, new_path);
            DispFilePaths(new_path);
#elif HTTP_REVERSE_ENG == 0
            remove(path_rq_h);
#endif
        }
        if (path_rq_b != NULL) {
            if (create == TRUE) {
                /* dir name and creation */
                if (DispIp(ppei->stack, ip_src) == NULL) {
                    return -1;
                }
                if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL) {
                    return -1;
                }
                DispDirHttp(ip_src, ip_dest);
                create = FALSE;
            }
            
            /* post */
            name = strrchr(path_rq_b, '/');
            name++;

#if HTTP_ALL_DATA
            sprintf(new_path, "%s/%s/http/%s/%lu_%s", xdecode, ip_src, ip_dest, mcont, name);
#else
            sprintf(new_path, "%s/%s/http/%s/post/%s", xdecode, ip_src, ip_dest, name);
#endif
            rename(path_rq_b, new_path);
            DispFilePaths(new_path);
        }
        if (path_rs_h != NULL) {
#if HTTP_ALL_DATA
            if (create == TRUE) {
                /* dir name and creation */
                if (DispIp(ppei->stack, ip_src) == NULL)
                    return -1;
                if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
                    return -1;
                DispDirHttp(ip_src, ip_dest);
                create = FALSE;
            }
            
            /* post */
            name = strrchr(path_rs_h, '/');
            name++;
            sprintf(new_path, "%s/%s/http/%s/%lu_%s", xdecode, ip_src, ip_dest, mcont, name);
            rename(path_rs_h, new_path);
            DispFilePaths(new_path);
#elif HTTP_REVERSE_ENG == 0
            remove(path_rs_h);
#endif
        }
        if (path_rs_b != NULL) {
            if (create == TRUE) {
                /* dir name and creation */
                if (DispIp(ppei->stack, ip_src) == NULL)
                    return -1;
                if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
                    return -1;
                DispDirHttp(ip_src, ip_dest);
            }
            
            /* all body */
            name = strrchr(path_rs_b, '/');
            name++;
#if HTTP_ALL_DATA
            sprintf(new_path, "%s/%s/http/%s/%lu_%s", xdecode, ip_src, ip_dest, mcont, name);
#else
            sprintf(new_path, "%s/%s/http/%s/%s", xdecode, ip_src, ip_dest, name);
#endif
            if (val.str[0] == '\0') {
                rename(path_rs_b, new_path);
            }
            else {
                DispUncompress(val.str, path_rs_b, new_path);
                remove(path_rs_b);
            }
            DispFilePaths(new_path);
        }
#if HTTP_ALL_DATA
        pthread_mutex_unlock(&http_data_mux);
#endif
    }
    FTFree(&val, FT_STRING);
    
    return 0;
}


static int DispFtp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];
    char *name;
    char *user, *passwd, *url, *filename, *path;
    bool downloaded, data;
    size_t sz;

    path = filename = passwd = user = NULL;
    cmpn = ppei->components;
    sz = 0;
    
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ftp_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_pswd_id) {
            passwd = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_cmd_id) {
            data = FALSE;
            filename = cmpn->name;
            path = cmpn->file_path;
            sz = cmpn->file_size;
        }
        else if (cmpn->eid == pei_ftp_file_in_id) {
            data = TRUE;
            downloaded = TRUE;
            filename = cmpn->name;
            path = cmpn->file_path;
            sz = cmpn->file_size; 
        }
        else if (cmpn->eid == pei_ftp_file_out_id) {
            data = TRUE;
            downloaded = FALSE;
            filename = cmpn->name;
            path = cmpn->file_path;
            sz = cmpn->file_size; 
        }
        else if (cmpn->eid == pei_ftp_file_offset_id) {
        }
        else if (cmpn->eid == pei_ftp_up_n_id) {
        }
        else if (cmpn->eid == pei_ftp_down_n_id) {
        }

        cmpn = cmpn->next;
    }
    
    if (ppei->ret == FALSE && path != NULL) {
        if (data == FALSE) {
            /* erase command file */
#define CHECK_FTP 0
#if CHECK_FTP
            rename(path, "ftp_cmd.txt");
#else
            remove(path);
#endif
        }
        else {
#if CHECK_FTP
            LogPrintf(LV_DEBUG, "FTP file: %s size: %lu", filename, sz);
#endif
            
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
                return -1;
            DispDirFtp(ip_src, ip_dest);
            
            name = strrchr(path, '/');
            name++;
            if (downloaded == FALSE)
                sprintf(new_path, "%s/%s/ftp/%s/upload/%s", xdecode, ip_src, ip_dest, name);
            else
                sprintf(new_path, "%s/%s/ftp/%s/download/%s", xdecode, ip_src, ip_dest, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
    }
    
    return 0;
}


static int DispIpp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name, *path;

    path = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ipp_url_id) {
        }
        if (cmpn->eid == pei_ipp_pdf_id) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirPrinter(ip_src);

            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, "%s/%s/printer/%s", xdecode, ip_src, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
        if (cmpn->eid == pei_ipp_pcl_id) {
            remove(cmpn->file_path);
        }
        cmpn = cmpn->next;
    }

    return 0;
}


static int DispPjl(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name, *path;

    path = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pjl_url_id) {
        }
        if (cmpn->eid == pei_pjl_pdf_id) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirPrinter(ip_src);

            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, "%s/%s/printer/%s", xdecode, ip_src, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
        if (cmpn->eid == pei_pjl_pcl_id) {
            remove(cmpn->file_path);
        }
        cmpn = cmpn->next;
    }

    return 0;
}


static int DispMms(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name, *path;
    char *from, *to, *cc, *bcc;
    bool first = TRUE;
    
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_mms_from_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_to_id) {
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_cc_id) {
            cc = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_bcc_id) {
            bcc = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_part_id) {
            if (first == TRUE) {
                /* dir name and creation */
                if (DispIp(ppei->stack, ip_src) == NULL)
                    return -1;
                DispDirMms(ip_src);
            }
            first = FALSE;
            
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, "%s/%s/mms/%s", xdecode, ip_src, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
        else if (cmpn->eid == pei_mms_raw_id) {
            remove(cmpn->file_path);
        }
        cmpn = cmpn->next;
    }

    return 0;
}


static int DispTftp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];
    char *name;
    char *user, *passwd, *url, *filename, *path;
    bool downloaded, data;

    path = filename = passwd = user = NULL;
    cmpn = ppei->components;
    
    while (cmpn != NULL) {
        if (cmpn->eid == pei_tftp_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_tftp_cmd_id) {
            data = FALSE;
            filename = cmpn->name;
            path = cmpn->file_path;
        }
        else if (cmpn->eid == pei_tftp_file_in_id) {
            data = TRUE;
            downloaded = TRUE;
            filename = cmpn->name;
            path = cmpn->file_path;
        }
        else if (cmpn->eid == pei_tftp_file_out_id) {
            data = TRUE;
            downloaded = FALSE;
            filename = cmpn->name;
            path = cmpn->file_path;
        }
        else if (cmpn->eid == pei_tftp_up_n_id) {
        }
        else if (cmpn->eid == pei_tftp_down_n_id) {
        }

        cmpn = cmpn->next;
    }
    
    if (ppei->ret == FALSE && path != NULL) {
        if (data == FALSE) {
            /* erase command file */
            remove(path);
        }
        else {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
                return -1;
            DispDirTftp(ip_src, ip_dest);
            
            name = strrchr(path, '/');
            name++;
            if (downloaded == FALSE)
                sprintf(new_path, "%s/%s/tftp/%s/upload/%s", xdecode, ip_src, ip_dest, name);
            else
                sprintf(new_path, "%s/%s/tftp/%s/download/%s", xdecode, ip_src, ip_dest, name);
            rename(path, new_path);
            DispFilePaths(new_path);
        }
    }
    
    return 0;
}


static int DispDns(pei *ppei)
{
    char ip_str[XCLI_STR_DIM];
    char new_path[XCLI_STR_DIM];
    pei_component *cmpn;
    char *ip_one, *host, *cname, *id;
    FILE *dns_fp;

    ip_one = NULL;
    host = NULL;
    cname = NULL;
    id = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dns_host_id) {
            host = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_ip_id && ip_one == NULL) {
            ip_one = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_cname_id && cname == NULL) {
            cname = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_pkt_id) {
            id = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (ip_one != NULL || cname != NULL) {
        if (cname == NULL)
            cname = "";
        if (ip_one == NULL)
            ip_one = "";
        if (id == NULL)
            id = "";
        
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirDns(ip_str);
        sprintf(new_path, "%s/%s/dns/dns_%lld.txt", xdecode, ip_str, (long long)tstart);
        dns_fp = fopen(new_path, "a");
        if (dns_fp != NULL) {
            fprintf(dns_fp, "%s, %lld, %s, %s, %s\n", id, (long long)ppei->time_cap, host, cname, ip_one);
            fclose(dns_fp);
            DispFilePaths(new_path);
        }
    }
    
    return 0;
}


static int DispNntp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *path, *name;
    char ip_str[XCLI_STR_DIM];
    bool in;

    path = NULL;
    cmpn = ppei->components;
    in = FALSE;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_nntp_article_id) {
            path = cmpn->file_path;
            in = TRUE;
        }
        else if (cmpn->eid == pei_nntp_body_id) {
            path = cmpn->file_path;
            in = TRUE;
        }
        else if (cmpn->eid == pei_nntp_post_id) {
            path = cmpn->file_path;
            in = FALSE;
        }
        cmpn = cmpn->next;
    }

    /* move file */
    if (path) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirNntp(ip_str);

        /* new path */
        name = strrchr(path, '/');
        name++;
        if (in == TRUE) {
            sprintf(new_path, "%s/%s/nntp/in/%s", xdecode, ip_str, name);
        }
        else {
            sprintf(new_path, "%s/%s/nntp/out/%s", xdecode, ip_str, name);
        }
        rename(path, new_path);
        DispFilePaths(new_path);
    }
    return 0;
}


static int DispFbwc(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_str[XCLI_STR_DIM];
    char *chat, *name, *user, *friend;
    size_t chtsize;

    user = friend = chat = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_fbwc_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_friend_id) {
            friend = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_chat_id) {
            chat = cmpn->file_path;
            chtsize = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* create new message */
    if (chat != NULL) {
        if (ppei->ret == FALSE) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_str) == NULL)
                return -1;
            DispDirFbwc(ip_str, user);
            
            /* new path */
            name = strrchr(chat, '/');
            name++;
            sprintf(new_path, "%s/%s/facebook_chat/%s/%s", xdecode, ip_str, user, name);
            rename(chat, new_path);
            DispFilePaths(new_path);
        }
    }

    return 0;
}


static int DispTelnet(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *path, *name;
    char ip_str[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];

    path = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_telnet_cmd_id) {
            path = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }

    /* move file */
    if (path) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
            return -1;
        DispDirTelnet(ip_str, ip_dest);

        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(new_path, "%s/%s/telnet/%s/%s", xdecode, ip_str, ip_dest,  name);
        rename(path, new_path);
        DispFilePaths(new_path);
    }

    return 0;
}


static int DispWebmail(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *service, *eml, *dir, *name;
    char ip_str[XCLI_STR_DIM];

    service = eml = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_webmail_serv_id) {
            service = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_eml_id) {
            eml = cmpn->file_path;
        }
        else if (cmpn->eid == pei_webmail_dir_id) {
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_html_id) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_webmail_txt_id) {
            remove(cmpn->file_path);
        }
        cmpn = cmpn->next;
    }

    /* move file */
    if (eml != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirWebmail(ip_str, service);

        /* new path */
        name = strrchr(eml, '/');
        name++;
        if (dir[0] == 's')
            sprintf(new_path, "%s/%s/webmail/%s/out/%s", xdecode, ip_str, service,  name);
        else
            sprintf(new_path, "%s/%s/webmail/%s/in/%s", xdecode, ip_str, service,  name);
        rename(eml, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispHttpFile(pei *ppei)
{
    static unsigned long cnt_fl = 0;
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *file, *name;
    char ip_str[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];

    file = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_httpfile_file_id) {
            file = cmpn->file_path;
            name = cmpn->name;
        }
        if (cmpn->eid == pei_httpfile_parts_id) {
            remove(cmpn->file_path);
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (file != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
            return -1;
        DispDirHttpFile(ip_str, ip_dest);

        /* new path */
        if (name == NULL) {
            name = strrchr(file, '/');
            name++;
            snprintf(new_path, XCLI_STR_DIM, "%s/%s/httpfile/%s/%s", xdecode, ip_str, ip_dest, name);
        }
        else {
            snprintf(new_path, XCLI_STR_DIM, "%s/%s/httpfile/%s/%lld_%lu_%s", xdecode, ip_str, ip_dest, (long long)time(NULL), cnt_fl, name);
            cnt_fl++;
        }
        rename(file, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispGrbTcp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *file, *name, *raw, *raw_name;
    char ip_str[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];

    file = raw = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_grb_tcp_txt_id) {
            file = cmpn->file_path;
            name = cmpn->name;
            //ProtStackFrmDisp(ppei->stack, TRUE);
        }
        else if (cmpn->eid == pei_grb_tcp_file_id) {
            raw = cmpn->file_path;
            raw_name = cmpn->name;
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (file != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
            return -1;
        DispDirGrbTcp(ip_str, ip_dest);

        /* new path */
        name = strrchr(file, '/');
        name++;
        sprintf(new_path, "%s/%s/grbtcp/%s/%s", xdecode, ip_str, ip_dest, name);
        rename(file, new_path);
        DispFilePaths(new_path);
    }
    else if (raw != NULL) {
        /* dir name and creation */
        name = strrchr(raw, '/');
        name++;
#if 0
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
            return -1;
        DispDirGrbTcpDig(ip_str, ip_dest, TRUE);
        /* new path */
        sprintf(new_path, "%s/%s/dig/%s/%s", xdecode, ip_str, ip_dest, name);
#else
        DispDirGrbTcpDig(NULL, NULL, FALSE);
        /* new path */
        sprintf(new_path, "%s/dig/%s", xdecode, name);
#endif

        rename(raw, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispGrbUdp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *file, *name;
    char ip_str[XCLI_STR_DIM];
    char ip_dest[XCLI_STR_DIM];

    file = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_grb_udp_txt_id) {
            file = cmpn->file_path;
            name = cmpn->name;
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (file != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        if (DispDestHost(ppei->stack, ip_dest, XCLI_STR_DIM) == NULL)
            return -1;
        DispDirGrbUdp(ip_str, ip_dest);

        /* new path */
        name = strrchr(file, '/');
        name++;
        sprintf(new_path, "%s/%s/grbudp/%s/%s", xdecode, ip_str, ip_dest, name);
        rename(file, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispRtp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *from, *to, *mix, *name;
    char ip_str[XCLI_STR_DIM];

    from = to = mix = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_rtp_from){
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_rtp_to){
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_rtp_audio_mix) {
            mix = cmpn->file_path;
        }
        else if (cmpn->eid == pei_rtp_audio_from) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_rtp_audio_to) {
            remove(cmpn->file_path);
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (from != NULL && mix != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirVoip(ip_str, from, to);

        /* new path */
        name = strrchr(mix, '/');
        name++;
        sprintf(new_path, "%s/%s/voip/%s/%s/%s", xdecode, ip_str, from, to, name);
        rename(mix, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispSip(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *from, *to, *mix, *name;
    char ip_str[XCLI_STR_DIM];

    from = to = mix = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_sip_from){
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_sip_to){
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_sip_audio_mix) {
            mix = cmpn->file_path;
        }
        else if (cmpn->eid == pei_sip_audio_from) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_sip_audio_to) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_sip_cmd) {
            remove(cmpn->file_path);
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (from != NULL && mix != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirVoip(ip_str, from, to);

        /* new path */
        name = strrchr(mix, '/');
        name++;
        sprintf(new_path, "%s/%s/voip/%s/%s/%s", xdecode, ip_str, from, to, name);
        rename(mix, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispArp(pei *ppei)
{
    char new_path[XCLI_STR_DIM];
    pei_component *cmpn;
    char *ip, *mac;
    FILE *arp_fp;

    mac = ip = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_arp_mac_id) {
            mac = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_arp_ip_id) {
            ip = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (mac != NULL && ip != NULL) {
        /* dir name and creation */
        DispDirArp();
        sprintf(new_path, "%s/arp/arp_%lld.txt", xdecode, (long long)tstart);
        arp_fp = fopen(new_path, "a");
        if (arp_fp != NULL) {
            fprintf(arp_fp, "%lld, %s -> %s\n", (long long)ppei->time_cap, mac, ip);
            fclose(arp_fp);
            DispFilePaths(new_path);
        }
    }
    
    return 0;
}


static int DispIrc(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *channel, *cfile, *ufile, *cmd, *nick;

    channel = cfile = ufile = cmd = nick = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_irc_server_id) {
            cmd = cmpn->file_path;
        }
        else if (cmpn->eid == pei_irc_channel_id) {
            channel = cmpn->name;
            cfile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_irc_channel_users_id) {
            ufile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_irc_channel_nick_id) {
            nick = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == FALSE) {
        if (cmd != NULL) {
            /* erase command file */
            remove(cmd);
        }
        if (nick != NULL) {
            /* erase channel nick */
            remove(nick);
        }
        if (channel != NULL) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirIrc(ip_src, channel);
            
            name = strrchr(cfile, '/');
            name++;
            sprintf(new_path, "%s/%s/irc/%s/%s", xdecode, ip_src, channel, name);
            rename(cfile, new_path);
            name = strrchr(ufile, '/');
            name++;
            sprintf(new_path, "%s/%s/irc/%s/%s", xdecode, ip_src, channel, name);
            rename(ufile, new_path);
            DispFilePaths(new_path);
        }
        else if (ufile != NULL) {
            /* erase channel users */
            remove(ufile);
        }
    }

    return 0;
}


static int DispPaltalkExp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *duration, *chat, *nick;

    duration = chat = nick = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pltk_e_user_id) {
            nick = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pltk_e_chat_id) {
            chat = cmpn->file_path;
        }
        else if (cmpn->eid == pei_pltk_e_duration_id) {
            duration = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == FALSE) {
        if (chat != NULL) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirPaltalkExp(ip_src, nick);
            
            name = strrchr(chat, '/');
            name++;
            sprintf(new_path, "%s/%s/paltalk_exp/%s/%s", xdecode, ip_src, nick, name);
            rename(chat, new_path);
        }
    }

    return 0;
}


static int DispPaltalk(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *channel, *cfile, *ufile, *duration, *nick;

    channel = cfile = ufile = duration = nick = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pltk_room_duration_id) {
            duration = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pltk_room_id) {
            channel = cmpn->name;
            cfile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_pltk_room_users_id) {
            ufile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_pltk_room_nick_id) {
            nick = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == FALSE) {
        if (nick != NULL) {
            /* erase channel nick */
            remove(nick);
        }
        if (channel != NULL) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirPaltalk(ip_src, channel);
            
            name = strrchr(cfile, '/');
            name++;
            sprintf(new_path, "%s/%s/paltalk/%s/%s", xdecode, ip_src, channel, name);
            rename(cfile, new_path);
            name = strrchr(ufile, '/');
            name++;
            sprintf(new_path, "%s/%s/paltalk/%s/%s", xdecode, ip_src, channel, name);
            rename(ufile, new_path);
            DispFilePaths(new_path);
        }
        else if (ufile != NULL) {
            /* erase channel users */
            remove(ufile);
        }
    }

    return 0;
}


static int DispMsn(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *channel, *cfile, *from, *to, *duration;

    channel = cfile = duration = to = from = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_msn_duration_id) {
            duration = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_msn_chat_id) {
            channel = cmpn->name;
            cfile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_msn_from_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_msn_to_id) {
            to = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == FALSE) {
        if (channel != NULL) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirMsn(ip_src, from);
            
            name = strrchr(cfile, '/');
            name++;
            sprintf(new_path, "%s/%s/msn/%s/%s_%lld", xdecode, ip_src, from, to, (long long)time(NULL));
            rename(cfile, new_path);
            DispFilePaths(new_path);
        }
    }

    return 0;
}

static int DispMgcp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *from, *to, *mix, *name;
    char ip_str[XCLI_STR_DIM];

    from = to = mix = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_mgcp_from){
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mgcp_to){
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mgcp_audio_mix) {
            mix = cmpn->file_path;
        }
        else if (cmpn->eid == pei_mgcp_audio_from) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_mgcp_audio_to) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_mgcp_cmd) {
            remove(cmpn->file_path);
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (from != NULL && mix != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_str) == NULL)
            return -1;
        DispDirVoip(ip_str, from, to);

        /* new path */
        name = strrchr(mix, '/');
        name++;
        sprintf(new_path, "%s/%s/voip/%s/%s/%s", xdecode, ip_str, from, to, name);
        rename(mix, new_path);
        DispFilePaths(new_path);
    }
    
    return 0;
}


static int DispWebYmsg(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *channel, *cfile, *from, *to, *duration;

    channel = cfile = duration = to = from = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_webymsg_duration_id) {
            duration = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webymsg_chat_id) {
            channel = cmpn->name;
            cfile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_webymsg_user_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webymsg_friend_id) {
            to = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == FALSE) {
        if (channel != NULL) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirWebYmsg(ip_src, from);
            
            name = strrchr(cfile, '/');
            name++;
            sprintf(new_path, "%s/%s/webymsg/%s/%s_%lld", xdecode, ip_src, from, to, (long long)time(NULL));
            rename(cfile, new_path);
            DispFilePaths(new_path);
        }
    }

    return 0;
}


static int DispWhatsApp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *device, *phone;

    device = phone = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_wa_phone_id) {
            phone = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_wa_device_id) {
            device = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == FALSE) {
        if (phone != NULL) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_src) == NULL)
                return -1;
            DispDirWhatsApp(ip_src, phone);
        }
    }

    return 0;
}


static int DispSyslog(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *hosts, *lfile;

    hosts = lfile = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_syslog_host_id) {
            hosts = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_syslog_log_id) {
            lfile = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    if (lfile != NULL) {
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_src) == NULL)
            return -1;
        DispDirSyslog(ip_src);
        
        name = strrchr(lfile, '/');
        name++;
        sprintf(new_path, "%s/%s/syslog/%s", xdecode, ip_src, name);
        rename(lfile, new_path);
        DispFilePaths(new_path);
    }

    return 0;
}


static int DispYmsg(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_src[XCLI_STR_DIM];
    char *name;
    char *sender, *receiver, *msg, *mfile;
    int session;

    //printf("Ymsg - cli.c - DispYmsg\n");
    LogPrintf(LV_DEBUG, "Ymsg - cli.c - DispYmsg1");

    session = 0;
    sender = receiver = msg = NULL;
    cmpn = ppei->components;

/*TODO: put a size cmpn for ymsg sender, receiver, msg??? */
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ymsg_msg_id) {
            msg = cmpn->strbuf;
            mfile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_ymsg_sender_id) {
            sender = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ymsg_receiver_id) {
            receiver = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ymsg_session_id) {
            session = *(int *)(cmpn->strbuf);
        }
        cmpn = cmpn->next;
    }

        if (msg != NULL) {
                LogPrintf(LV_DEBUG, "Ymsg - cli.c - msg:%s - DispYmsg2", msg);
        /* dir name and creation */
        if (DispIp(ppei->stack, ip_src) == NULL)
            return -1;
        DispDirYmsg(ip_src, "Sessions");/*msg);*/

            if (mfile == NULL) {
               printf("mfile is NULL - error\n");
            }
            printf("Message: %s, filepath: %s\n", msg, mfile);

        name = strrchr(mfile, '/');
        name++;
        sprintf(new_path, "%s/%s/ymsg/%s/%s", xdecode, ip_src, "Sessions", name);
        //LogPrintf(LV_DEBUG, "Ymsg - cli.c - old path: ", mfile);
        //LogPrintf(LV_DEBUG, "Ymsg - cli.c - new path: ", new_path);
        rename(mfile, new_path);
        DispFilePaths(new_path);
    }

        LogPrintf(LV_DEBUG, "Ymsg - cli.c - DispYmsg3");

    return 0;

}


static int DispYahoo(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char ip_str[XCLI_STR_DIM];
    char *chat, *name, *user, *friend;
    size_t chtsize;

	LogPrintf(LV_DEBUG, "Yahoo! - cli.c - DispYahoo1");

    user = friend = chat = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_yahoo_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_yahoo_friend_id) {
            friend = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_yahoo_chat_id) {
            chat = cmpn->file_path;
            chtsize = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

	LogPrintf(LV_DEBUG, "Yahoo! - cli.c - user:%s - friend:%s - DispYahoo2", user, friend);

    /* create new message */
    if (chat != NULL) {
		LogPrintf(LV_DEBUG, "Yahoo! - cli.c - DispYahoo3");
        if (ppei->ret == FALSE) {
            /* dir name and creation */
            if (DispIp(ppei->stack, ip_str) == NULL)
                return -1;
            DispDirYahoo(ip_str, user);

            /* new path */
            name = strrchr(chat, '/');
            name++;
            sprintf(new_path, "%s/%s/yahoo_chat/%s/%s", xdecode, ip_str, user, name);
            rename(chat, new_path);
            DispFilePaths(new_path);
        }
    }

	LogPrintf(LV_DEBUG, "Yahoo! - cli.c - DispYahoo4");

    return 0;
}



int DispInit(const char *cfg_file)
{
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char kml_file[XCLI_STR_DIM];
    char sem[XCLI_STR_DIM];
    char *param;
    FILE *fp;
    int res, i;

    LogPrintf(LV_DEBUG, "CLI Dispatcher");

    npop = nsmtp = nimap = nhttp = nftp = nipp = npjl = 0;
    nmms = ntftp = ndns = nnntp = nfbwc = ntelnet = 0;
    nwebmail = nhttpfile = ngrptcp = ngrpudp = nrtp = 0;
    nsip = narp = nirc = npltk_exp = npltk = msn = 0;
    nbo = mgcp = webymsg = 0;
    syslog = nwa = 0;

    /* read configuration file */
    fp = fopen(cfg_file, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    res = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_CLI_XDECODE);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_CLI_XDECODE"=%s %s", xdecode, bufcpy);
                if (res > 0) {
                    break;
                }
            }
        }
    }
    fclose(fp);
    if (!res) {
        strcpy(xdecode, XCLI_BASE_DIR);
    }
    else {
        i = 0;
        while (xdecode[i] != '\0' && xdecode[i] != '\0')
            i++;
        xdecode[i] = '\0';
    }
    
    geo_id = 0;
    tstart = time(NULL);
    
    ip_id = ProtId("ip");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
    }
    ipv6_id = ProtId("ipv6");
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    }

    /* pei id */
    pop_id = ProtId("pop");
    if (pop_id != -1) {
        pei_pop_user_id = ProtPeiComptId(pop_id, "user");
        pei_pop_pswd_id = ProtPeiComptId(pop_id, "password");
        pei_pop_eml_id = ProtPeiComptId(pop_id, "eml");
    }

    smtp_id = ProtId("smtp");
    if (smtp_id != -1) {
        pei_smtp_to_id = ProtPeiComptId(smtp_id, "to");
        pei_smtp_from_id = ProtPeiComptId(smtp_id, "from");
        pei_smtp_eml_id = ProtPeiComptId(smtp_id, "eml");
    }

    imap_id = ProtId("imap");
    if (imap_id != -1) {
        pei_imap_user_id = ProtPeiComptId(imap_id, "user");
        pei_imap_pswd_id = ProtPeiComptId(imap_id, "password");
        pei_imap_params_id = ProtPeiComptId(imap_id, "params");
        pei_imap_eml_id = ProtPeiComptId(imap_id, "eml");
    }
    
    http_id = ProtId("http");
    if (http_id != -1) {
        http_encoding_id = ProtAttrId(http_id, "http.content_encoding");
        pei_http_url_id = ProtPeiComptId(http_id, "url");
        pei_http_client_id = ProtPeiComptId(http_id, "client");
        pei_http_host_id = ProtPeiComptId(http_id, "host");
        pei_http_content_type_id = ProtPeiComptId(http_id, "content_type");
        pei_http_method_id = ProtPeiComptId(http_id, "method");
        pei_http_status_id = ProtPeiComptId(http_id, "status");
        pei_http_req_header_id = ProtPeiComptId(http_id, "req.header");
        pei_http_req_body_id = ProtPeiComptId(http_id, "req.body");
        pei_http_res_header_id = ProtPeiComptId(http_id, "res.header");
        pei_http_res_body_id = ProtPeiComptId(http_id, "res.body");
        pei_http_file_id = ProtPeiComptId(http_id, "boundary");
    }

    ftp_id = ProtId("ftp");
    if (ftp_id != -1) {
        pei_ftp_url_id = ProtPeiComptId(ftp_id, "url");
        pei_ftp_user_id = ProtPeiComptId(ftp_id, "user");
        pei_ftp_pswd_id = ProtPeiComptId(ftp_id, "password");
        pei_ftp_cmd_id = ProtPeiComptId(ftp_id, "cmd");
        pei_ftp_file_in_id = ProtPeiComptId(ftp_id, "file_in");
        pei_ftp_file_out_id = ProtPeiComptId(ftp_id, "file_out");
        pei_ftp_file_offset_id = ProtPeiComptId(ftp_id, "offset");
        pei_ftp_down_n_id = ProtPeiComptId(ftp_id, "down_n");
        pei_ftp_up_n_id = ProtPeiComptId(ftp_id, "up_n");
    }

    ipp_id = ProtId("ipp");
    if (ipp_id != -1) {
        pei_ipp_url_id = ProtPeiComptId(ipp_id, "url");
        pei_ipp_pdf_id = ProtPeiComptId(ipp_id, "pdf");
        pei_ipp_pcl_id = ProtPeiComptId(ipp_id, "pcl");
    }

    pjl_id = ProtId("pjl");
    if (pjl_id != -1) {
        pei_pjl_url_id = ProtPeiComptId(pjl_id, "url");
        pei_pjl_pdf_id = ProtPeiComptId(pjl_id, "pdf");
        pei_pjl_pcl_id = ProtPeiComptId(pjl_id, "pcl");
    }

    mms_id = ProtId("mms");
    if (mms_id != -1) {
        pei_mms_url_id = ProtPeiComptId(mms_id, "url");
        pei_mms_from_id = ProtPeiComptId(mms_id, "from");
        pei_mms_to_id = ProtPeiComptId(mms_id, "to");
        pei_mms_cc_id = ProtPeiComptId(mms_id, "cc");
        pei_mms_bcc_id = ProtPeiComptId(mms_id, "bcc");
        pei_mms_part_id = ProtPeiComptId(mms_id, "part");
        pei_mms_raw_id = ProtPeiComptId(mms_id, "raw");
    }

    tftp_id = ProtId("tftp");
    if (tftp_id != -1) {
        pei_tftp_url_id = ProtPeiComptId(tftp_id, "url");
        pei_tftp_cmd_id = ProtPeiComptId(tftp_id, "cmd");
        pei_tftp_file_in_id = ProtPeiComptId(tftp_id, "file_in");
        pei_tftp_file_out_id = ProtPeiComptId(tftp_id, "file_out");
        pei_tftp_down_n_id = ProtPeiComptId(tftp_id, "down_n");
        pei_tftp_up_n_id = ProtPeiComptId(tftp_id, "up_n");
    }
    
    dns_id = ProtId("dns");
    if (dns_id != -1) {
        pei_dns_host_id =  ProtPeiComptId(dns_id, "host");
        pei_dns_ip_id =  ProtPeiComptId(dns_id, "ip");
        pei_dns_cname_id =  ProtPeiComptId(dns_id, "cname");
        pei_dns_pkt_id = ProtPeiComptId(dns_id, "id");
    }

    nntp_id = ProtId("nntp");
    if (nntp_id != -1) {
        pei_nntp_url_id = ProtPeiComptId(nntp_id, "url");
        pei_nntp_grp_id = ProtPeiComptId(nntp_id, "grp");
        pei_nntp_article_id = ProtPeiComptId(nntp_id, "article");
        pei_nntp_header_id = ProtPeiComptId(nntp_id, "header");
        pei_nntp_body_id = ProtPeiComptId(nntp_id, "body");
        pei_nntp_post_id = ProtPeiComptId(nntp_id, "post");
    }
    
    fbwc_id = ProtId("fbwchat");
    if (fbwc_id != -1) {
        pei_fbwc_user_id = ProtPeiComptId(fbwc_id, "user");
        pei_fbwc_friend_id = ProtPeiComptId(fbwc_id, "friend");
        pei_fbwc_chat_id = ProtPeiComptId(fbwc_id, "chat");
        pei_fbwc_duration_id = ProtPeiComptId(fbwc_id, "duration");
    }

    telnet_id = ProtId("telnet");
    if (telnet_id != -1) {
        pei_telnet_host_id = ProtPeiComptId(telnet_id, "host");
        pei_telnet_user_id = ProtPeiComptId(telnet_id, "user");
        pei_telnet_password_id= ProtPeiComptId(telnet_id, "password");
        pei_telnet_cmd_id = ProtPeiComptId(telnet_id, "cmd");
    }

    webmail_id = ProtId("webmail");
    if (webmail_id != -1) {
        pei_webmail_serv_id = ProtPeiComptId(webmail_id, "serv");
        pei_webmail_dir_id = ProtPeiComptId(webmail_id, "dir");
        pei_webmail_to_id = ProtPeiComptId(webmail_id, "to");
        pei_webmail_from_id = ProtPeiComptId(webmail_id, "from");
        pei_webmail_cc_id = ProtPeiComptId(webmail_id, "cc");
        pei_webmail_sent_id = ProtPeiComptId(webmail_id, "sent");
        pei_webmail_rec_id = ProtPeiComptId(webmail_id, "rec");
        pei_webmail_messageid_id = ProtPeiComptId(webmail_id, "id");
        pei_webmail_subj_id = ProtPeiComptId(webmail_id, "subject");
        pei_webmail_eml_id = ProtPeiComptId(webmail_id, "eml");
        pei_webmail_html_id = ProtPeiComptId(webmail_id, "html");
        pei_webmail_txt_id = ProtPeiComptId(webmail_id, "txt");
    }

    httpfile_id = ProtId("httpfd");
    if (httpfile_id != -1) {
        pei_httpfile_url_id = ProtPeiComptId(httpfile_id, "url");
        pei_httpfile_file_id = ProtPeiComptId(httpfile_id, "file");
        pei_httpfile_content_type = ProtPeiComptId(httpfile_id, "content_type");
        pei_httpfile_parts_id = ProtPeiComptId(httpfile_id, "parts");
        pei_httpfile_complete_id = ProtPeiComptId(httpfile_id, "complete");
    }

    grb_tcp_id = ProtId("tcp-grb");
    if (grb_tcp_id != -1) {
        pei_grb_tcp_l7prot_id = ProtPeiComptId(grb_tcp_id, "l7prot");
        pei_grb_tcp_txt_id = ProtPeiComptId(grb_tcp_id, "txt");
        pei_grb_tcp_size_id = ProtPeiComptId(grb_tcp_id, "size");
        pei_grb_tcp_file_id = ProtPeiComptId(grb_tcp_id, "file");
        pei_grb_tcp_file_type_id = ProtPeiComptId(grb_tcp_id, "ftype");
    }

    grb_udp_id = ProtId("udp-grb");
    if (grb_udp_id != -1) {
        pei_grb_udp_connect_id = ProtPeiComptId(grb_udp_id, "conn");
        pei_grb_udp_txt_id = ProtPeiComptId(grb_udp_id, "txt");
    }

    rtp_id = ProtId("rtp");
    if (rtp_id != -1) {
        pei_rtp_from = ProtPeiComptId(rtp_id, "from");
        pei_rtp_to = ProtPeiComptId(rtp_id, "to");
        pei_rtp_audio_from = ProtPeiComptId(rtp_id, "audio_from");
        pei_rtp_audio_to = ProtPeiComptId(rtp_id, "audio_to");
        pei_rtp_audio_mix = ProtPeiComptId(rtp_id, "audio_mix");
        pei_rtp_duration = ProtPeiComptId(rtp_id, "duration");
    }

    sip_id = ProtId("sip");
    if (sip_id != -1) {
        pei_sip_from = ProtPeiComptId(sip_id, "from");
        pei_sip_to = ProtPeiComptId(sip_id, "to");
        pei_sip_cmd = ProtPeiComptId(sip_id, "cmd");
        pei_sip_audio_from = ProtPeiComptId(sip_id, "audio_from");
        pei_sip_audio_to = ProtPeiComptId(sip_id, "audio_to");
        pei_sip_audio_mix = ProtPeiComptId(sip_id, "audio_mix");
        pei_sip_duration = ProtPeiComptId(sip_id, "duration");
    }
    
    arp_id = ProtId("arp");
    if (arp_id != -1) {
        pei_arp_mac_id = ProtPeiComptId(arp_id, "mac");
        pei_arp_ip_id = ProtPeiComptId(arp_id, "ip");
    }

    irc_id = ProtId("irc");
    if (irc_id != -1) {
        pei_irc_server_id = ProtPeiComptId(irc_id, "cmd");
        pei_irc_channel_id = ProtPeiComptId(irc_id, "channel");
        pei_irc_channel_users_id = ProtPeiComptId(irc_id, "cusers");
        pei_irc_channel_nick_id= ProtPeiComptId(irc_id, "cnick");
    }

    paltalk_exp_id = ProtId("paltalk_exp");
    if (paltalk_exp_id != -1) {
        pei_pltk_e_user_id = ProtPeiComptId(paltalk_exp_id, "user");
        pei_pltk_e_chat_id = ProtPeiComptId(paltalk_exp_id, "chat");
        pei_pltk_e_duration_id = ProtPeiComptId(paltalk_exp_id, "duration");
    
    }
    
    paltalk_id = ProtId("paltalk");
    if (paltalk_id != -1) {
        pei_pltk_room_id = ProtPeiComptId(paltalk_id, "room");
        pei_pltk_room_users_id = ProtPeiComptId(paltalk_id, "users");
        pei_pltk_room_nick_id= ProtPeiComptId(paltalk_id, "nick");
        pei_pltk_room_duration_id = ProtPeiComptId(paltalk_id, "duration");
    }
    
    msn_id = ProtId("msn");
    if (msn_id != -1) {
        pei_msn_from_id = ProtPeiComptId(msn_id, "from");
        pei_msn_to_id = ProtPeiComptId(msn_id, "to");
        pei_msn_chat_id = ProtPeiComptId(msn_id, "chat");
        pei_msn_duration_id = ProtPeiComptId(msn_id, "duration");

    }

    mgcp_id = ProtId("mgcp");
    if (mgcp_id != -1) {
        pei_mgcp_from = ProtPeiComptId(mgcp_id, "from");
        pei_mgcp_to = ProtPeiComptId(mgcp_id, "to");
        pei_mgcp_cmd = ProtPeiComptId(mgcp_id, "cmd");
        pei_mgcp_audio_from = ProtPeiComptId(mgcp_id, "audio_from");
        pei_mgcp_audio_to = ProtPeiComptId(mgcp_id, "audio_to");
        pei_mgcp_audio_mix = ProtPeiComptId(mgcp_id, "audio_mix");
        pei_mgcp_duration = ProtPeiComptId(mgcp_id, "duration");
    }
    
    webymsg_id = ProtId("webymsg");
    if (webymsg_id != -1) {
        pei_webymsg_user_id = ProtPeiComptId(webymsg_id, "user");
        pei_webymsg_friend_id = ProtPeiComptId(webymsg_id, "friend");
        pei_webymsg_chat_id = ProtPeiComptId(webymsg_id, "chat");
        pei_webymsg_duration_id = ProtPeiComptId(webymsg_id, "duration");
    }
    
    syslog_id = ProtId("syslog");
    if (syslog_id != -1) {
        pei_syslog_host_id = ProtPeiComptId(syslog_id, "hosts");
        pei_syslog_log_id = ProtPeiComptId(syslog_id, "log");
    }

    ymsg_id = ProtId("ymsg");
    if (ymsg_id != -1){
        pei_ymsg_session_id = ProtPeiComptId(ymsg_id, "session");
        pei_ymsg_sender_id = ProtPeiComptId(ymsg_id, "sender");
        pei_ymsg_receiver_id = ProtPeiComptId(ymsg_id, "receiver");
        pei_ymsg_msg_id = ProtPeiComptId(ymsg_id, "msg");
    }
    
    wa_id = ProtId("wa");
    if (wa_id != -1) {
        pei_wa_device_id = ProtPeiComptId(wa_id, "dev");
        pei_wa_phone_id = ProtPeiComptId(wa_id, "phone");
    }
    
    yahoo_id = ProtId("yahoo");
    if (yahoo_id != -1) {
	    pei_yahoo_user_id = ProtPeiComptId(yahoo_id, "user");
        pei_yahoo_friend_id = ProtPeiComptId(yahoo_id, "friend");
        pei_yahoo_chat_id = ProtPeiComptId(yahoo_id, "chat");
        pei_yahoo_duration_id = ProtPeiComptId(yahoo_id, "duration");
    }
    
    /* directory for repository */
    mkdir(xdecode, 0x01FF);
    sprintf(kml_file, "%s/geomap_%lld.kml", xdecode, (long long)(tstart/100)*100);
    sprintf(sem, "/xplico_kml_sem");
    geo_id = 1;
    if (GearthNew(geo_id, kml_file, NULL, sem) != 0)
        geo_id = 0;
    
#if DISP_CLI_FILE_LIST
    pthread_mutex_init(&file_mux, NULL);
#endif
#if HTTP_ALL_DATA
    pthread_mutex_init(&http_data_mux, NULL);
#endif

    return 0;
}


int DispEnd()
{
    
    if (geo_id != 0) {
        GearthClose(geo_id);
    }
    /* PEI protcols statistics (for debug) */
#if 0
    printf("PEIs:\n");
    printf("\tpop: %lu\n", npop);
    printf("\tsmtp: %lu\n", nsmtp);
    printf("\timap: %lu\n", nimap);
    printf("\thttp: %lu\n", nhttp);
    printf("\tftp: %lu\n", nftp);
    printf("\tipp: %lu\n", nipp);
    printf("\tpjl: %lu\n", npjl);
    printf("\tmms: %lu\n", nmms);
    printf("\ttftp: %lu\n", ntftp);
    printf("\tdns: %lu\n", ndns);
    printf("\tnntp: %lu\n", nnntp);
    printf("\tfbwc: %lu\n", nfbwc);
    printf("\ttelnet: %lu\n", ntelnet);
    printf("\twebmail: %lu\n", nwebmail);
    printf("\thttpfile: %lu\n", nhttpfile);
    printf("\tgrptcp: %lu\n", ngrptcp);
    printf("\tgrpudp: %lu\n", ngrpudp);
    printf("\trtp: %lu\n", nrtp);
    printf("\tsip: %lu\n", nsip);
    printf("\tarp: %lu\n", narp);
    printf("\tirc: %lu\n", nirc);
    printf("\tpltk_exp: %lu\n", npltk_exp);
    printf("\tpltk: %lu\n", npltk);
    printf("\tmsn: %lu\n", msn);
    printf("\tmgcp: %lu\n", mgcp);
    printf("\twebymsg: %lu\n", webymsg);
    printf("\tsyslog: %lu\n", syslog);
    printf("\tyahoo: %lu\n", nyahoo);
    printf(\"tymsg: %lu\n", ymsg);
    printf(\"twhatsapp: %lu\n", nwa);
    printf("\tbo: %lu\n", nbo);
#endif

    return 0;
}


int DispInsPei(pei *ppei)
{
    int ret;
    
    if (ppei != NULL) {
        /* pei */
        if (ppei->prot_id == pop_id) {
            if (ppei->ret == FALSE)
                npop++;
            ret = DispPop(ppei);
        }
        else if (ppei->prot_id == smtp_id) {
            if (ppei->ret == FALSE)
                nsmtp++;
            ret = DispSmtp(ppei);
        }
        else if (ppei->prot_id == imap_id) {
            if (ppei->ret == FALSE)
                nimap++;
            ret = DispImap(ppei);
        }
        else if (ppei->prot_id == http_id) {
            if (ppei->ret == FALSE)
                nhttp++;
            ret = DispHttp(ppei);
        }
        else if (ppei->prot_id == ftp_id) {
            if (ppei->ret == FALSE)
                nftp++;
            ret = DispFtp(ppei);
        }
        else if (ppei->prot_id == ipp_id) {
            if (ppei->ret == FALSE)
                nipp++;
            ret = DispIpp(ppei);
        }
        else if (ppei->prot_id == pjl_id) {
            if (ppei->ret == FALSE)
                npjl++;
            ret = DispPjl(ppei);
        }
        else if (ppei->prot_id == mms_id) {
            if (ppei->ret == FALSE)
                nmms++;
            ret = DispMms(ppei);
        }
        else if (ppei->prot_id == tftp_id) {
            if (ppei->ret == FALSE)
                ntftp++;
            ret = DispTftp(ppei);
        }
        else if (ppei->prot_id == dns_id) {
            if (ppei->ret == FALSE)
                ndns++;
            ret = DispDns(ppei);
        }
        else if (ppei->prot_id == nntp_id) {
            if (ppei->ret == FALSE)
                nnntp++;
            ret = DispNntp(ppei);
        }
        else if (ppei->prot_id == fbwc_id) {
            if (ppei->ret == FALSE)
                nfbwc++;
            ret = DispFbwc(ppei);
        }
        else if (ppei->prot_id == telnet_id) {
            if (ppei->ret == FALSE)
                ntelnet++;
            ret = DispTelnet(ppei);
        }
        else if (ppei->prot_id == webmail_id) {
            if (ppei->ret == FALSE)
                nwebmail++;
            ret = DispWebmail(ppei);
        }
        else if (ppei->prot_id == httpfile_id) {
            if (ppei->ret == FALSE)
                nhttpfile++;
            ret = DispHttpFile(ppei);
        }
        else if (ppei->prot_id == grb_tcp_id) {
            if (ppei->ret == FALSE)
                ngrptcp++;
            ret = DispGrbTcp(ppei);
        }
        else if (ppei->prot_id == grb_udp_id) {
            if (ppei->ret == FALSE)
                ngrpudp++;
            ret = DispGrbUdp(ppei);
        }
        else if (ppei->prot_id == rtp_id) {
            if (ppei->ret == FALSE)
                nrtp++;
            ret = DispRtp(ppei);
        }
        else if (ppei->prot_id == sip_id) {
            if (ppei->ret == FALSE)
                nsip++;
            ret = DispSip(ppei);
        }
        else if (ppei->prot_id == arp_id) {
            if (ppei->ret == FALSE)
                narp++;
            ret = DispArp(ppei);
        }
        else if (ppei->prot_id == irc_id) {
            if (ppei->ret == FALSE)
                nirc++;
            ret = DispIrc(ppei);
        }
        else if (ppei->prot_id == paltalk_exp_id) {
            if (ppei->ret == FALSE)
                npltk_exp++;
            ret = DispPaltalkExp(ppei);
        }
        else if (ppei->prot_id == paltalk_id) {
            if (ppei->ret == FALSE)
                npltk++;
            ret = DispPaltalk(ppei);
        }
        else if (ppei->prot_id == msn_id) {
            if (ppei->ret == FALSE)
                msn++;
            ret = DispMsn(ppei);
        }
        else if (ppei->prot_id == mgcp_id) {
            if (ppei->ret == FALSE)
                mgcp++;
            ret = DispMgcp(ppei);
        }
        else if (ppei->prot_id == webymsg_id) {
            if (ppei->ret == FALSE)
                webymsg++;
            ret = DispWebYmsg(ppei);
        }
        else if (ppei->prot_id == syslog_id) {
            if (ppei->ret == FALSE)
                syslog++;
            ret = DispSyslog(ppei);
        }
        else if (ppei->prot_id == wa_id){
            if (ppei->ret == FALSE)
    	        nwa++;
            ret = DispWhatsApp(ppei);
        }
        else if (ppei->prot_id == ymsg_id){
            if (ppei->ret == FALSE)
    	        ymsg++;
            ret = DispYmsg(ppei);
        }
        else if (ppei->prot_id == yahoo_id) {
            if (ppei->ret == FALSE)
                nyahoo++;
            ret = DispYahoo(ppei);
        }
        else {
            if (ppei->ret == FALSE)
                nbo++;
            PeiPrint(ppei);
        }

        /* kml file */
        GearthPei(geo_id, ppei);
    }
    
    return 0;
}

